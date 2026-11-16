//! JWKS for mounts that fetch keys from `jwks_url`, cached per isolate and keyed by the URL, so
//! hosted tenants whose mounts share a name never share a set, and mounts naming one URL share
//! one entry. Pinned JWKS never come through here: [`State`](crate::state::State) parses them
//! once at startup.
//!
//! The cache holds at most [`MAX_URLS`] URLs (the least recently used is dropped), each set at
//! most [`MAX_JWKS_BYTES`] and [`MAX_KEYS`] keys, so tenants choosing their own URLs can't
//! grow an isolate's memory without bound.
//!
//! A fetched set is used for [`TTL_MS`], then fetched again. When a fetch fails, the cached set
//! keeps serving for up to [`MAX_STALE_MS`] after its last successful fetch, and no further
//! fetch is tried for [`FAILURE_BACKOFF_MS`], so an issuer outage costs one fetch per URL per
//! backoff period, not one per login, and a set the issuer may have rotated keys out of stops
//! being trusted after a bounded time.
//!
//! A forced refetch (a token named a `kid` the cached set lacks) is logged when it succeeds,
//! as [`FORCED_REFETCH_LOG`], so a test or an operator can see the Worker asked the issuer
//! again; every failed fetch is logged as an error.
//!
//! Requests in one isolate run concurrently, so a fetch's outcome is merged into the cache as
//! it stands when the fetch returns, never into the copy read before it: a failed fetch can't
//! restore a set that a concurrent fetch replaced.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;

use edgekms_core::jwt::Jwks;
use futures_util::{Stream, StreamExt as _};
use worker::{Date, Fetch, Request, RequestInit, RequestRedirect, Url};

use crate::vault::{log_internal, log_notice};

/// How long a fetched JWKS is used before it is fetched again.
const TTL_MS: u64 = 10 * 60 * 1000;
/// Minimum gap between forced refetches of one URL (an unknown `kid`), so a stream of tokens
/// with made-up `kid`s can't turn into a stream of fetches.
const FORCED_GAP_MS: u64 = 60 * 1000;
/// After a failed fetch, how long before another is tried.
const FAILURE_BACKOFF_MS: u64 = 60 * 1000;
/// Longest a set is trusted after its last successful fetch while fetches keep failing.
const MAX_STALE_MS: u64 = 60 * 60 * 1000;
/// Largest JWKS document accepted.
const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Most keys accepted in one set; real issuers publish a handful.
const MAX_KEYS: usize = 64;
/// URLs cached per isolate. Hosted tenants choose their own `jwks_url`s, so past this the
/// least recently used is dropped (as `tenants::MAX_TENANTS` bounds the tenant cache).
const MAX_URLS: usize = 256;

/// The log line (after `edgekms: `) for a forced refetch that succeeded. `scripts/e2e.sh`
/// looks for it.
pub const FORCED_REFETCH_LOG: &str = "JWKS refetched for an unknown kid";

/// What one call did about fetching, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Served from the cache (or refused) without fetching.
    Cached,
    /// Fetched a set; `forced` when the call asked for a refresh.
    Fetched { forced: bool },
    /// Tried to fetch and failed.
    FetchFailed { forced: bool },
}

/// A fixed log line and its level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Log {
    Notice(&'static str),
    Error(&'static str),
}

/// What to log for `outcome`: a successful forced refetch as a notice, any failed fetch as an
/// error, nothing otherwise (a routine fetch every [`TTL_MS`] isn't news).
fn log_label(outcome: Outcome) -> Option<Log> {
    match outcome {
        Outcome::Cached | Outcome::Fetched { forced: false } => None,
        Outcome::Fetched { forced: true } => Some(Log::Notice(FORCED_REFETCH_LOG)),
        Outcome::FetchFailed { forced: false } => Some(Log::Error("JWKS fetch failed")),
        Outcome::FetchFailed { forced: true } => Some(Log::Error("JWKS forced refetch failed")),
    }
}

/// Where the login handler gets keys for a `jwks_url` mount.
#[allow(async_fn_in_trait)]
pub trait JwksSource {
    /// The JWKS for `mount`, served from `url`. `force_refresh` asks for a refetch because a
    /// token named a `kid` the current set lacks; the source may decline and return its cache.
    ///
    /// # Errors
    /// If there is no usable set: nothing cached, or a cache too stale to trust, and no fetch
    /// succeeds (or none is due yet).
    async fn jwks(&self, mount: &str, url: &str, force_refresh: bool) -> worker::Result<Jwks>;
}

/// The production [`JwksSource`]: [`jwks_for`].
pub struct FetchedJwks;

impl JwksSource for FetchedJwks {
    async fn jwks(&self, _mount: &str, url: &str, force_refresh: bool) -> worker::Result<Jwks> {
        jwks_for(url, force_refresh).await
    }
}

#[derive(Clone, Default)]
struct Entry {
    /// The last set fetched successfully, if any.
    jwks: Option<Jwks>,
    /// When `jwks` was fetched.
    fetched_ms: u64,
    last_forced_ms: Option<u64>,
    /// When the last fetch failed, if it did.
    failed_ms: Option<u64>,
    /// When a request last looked this URL up, for evicting the least recently used past
    /// [`MAX_URLS`].
    used_ms: u64,
}

impl Entry {
    /// The cached set, unless it is older than [`MAX_STALE_MS`].
    fn usable(&self, now_ms: u64) -> Option<&Jwks> {
        self.jwks
            .as_ref()
            .filter(|_| now_ms.saturating_sub(self.fetched_ms) < MAX_STALE_MS)
    }
}

/// The isolate's cache, shared through an `Rc` so a request can hold it across its fetch.
type Cache = Rc<RefCell<HashMap<String, Entry>>>;

thread_local! {
    static CACHE: Cache = Rc::new(RefCell::new(HashMap::new()));
}

/// Whether to fetch, given the cache entry: always when there is none; otherwise when the set
/// is missing or older than [`TTL_MS`], or on a forced refresh at most once per
/// [`FORCED_GAP_MS`], but never within [`FAILURE_BACKOFF_MS`] of a failed fetch.
fn should_fetch(entry: Option<&Entry>, now_ms: u64, force: bool) -> bool {
    let Some(e) = entry else {
        return true;
    };
    if e.failed_ms
        .is_some_and(|t| now_ms.saturating_sub(t) < FAILURE_BACKOFF_MS)
    {
        return false;
    }
    if e.jwks.is_none() || now_ms.saturating_sub(e.fetched_ms) >= TTL_MS {
        return true;
    }
    force
        && e.last_forced_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= FORCED_GAP_MS)
}

/// Folds the outcome of a fetch that started at `started_ms` into `current`, the entry as it
/// is now (other requests may have written it while this fetch was in flight).
///
/// A fetched set replaces the stored one only if no fetch that started later has stored its
/// own. A failure only records when it happened and never touches the stored set, so a failed
/// fetch can't put back a set that a concurrent successful one replaced.
fn merge_fetch(current: Option<Entry>, fetched: Option<Jwks>, started_ms: u64) -> Entry {
    let mut e = current.unwrap_or_default();
    match fetched {
        Some(jwks) => {
            if e.jwks.is_none() || e.fetched_ms <= started_ms {
                e.jwks = Some(jwks);
                e.fetched_ms = started_ms;
            }
            if e.failed_ms.is_some_and(|t| t <= started_ms) {
                e.failed_ms = None;
            }
        }
        None => {
            e.failed_ms = Some(e.failed_ms.map_or(started_ms, |t| t.max(started_ms)));
        }
    }
    e
}

fn unavailable() -> worker::Error {
    worker::Error::RustError("JWKS unavailable".into())
}

/// The JWKS served from `url`, through the isolate cache (see the module docs for when it
/// fetches and how long a stale set is trusted).
///
/// # Errors
/// If no usable set is cached and no fetch is due or the fetch fails.
pub async fn jwks_for(url: &str, force_refresh: bool) -> worker::Result<Jwks> {
    let cache = CACHE.with(Rc::clone);
    let now_ms = Date::now().as_millis();
    let (result, outcome) = cached_fetch(&cache, url, now_ms, force_refresh, || fetch(url)).await;
    match log_label(outcome) {
        Some(Log::Notice(label)) => log_notice(label),
        Some(Log::Error(label)) => log_internal(label),
        None => {}
    }
    result
}

/// [`jwks_for`] over an explicit cache and fetch, so the interleaving of concurrent requests
/// can be tested; it also says whether it fetched. The cache is read before the fetch and read
/// again after it; no borrow is held across the `.await`.
async fn cached_fetch<F, Fut>(
    cache: &Cache,
    url: &str,
    now_ms: u64,
    force: bool,
    fetch: F,
) -> (worker::Result<Jwks>, Outcome)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = worker::Result<Jwks>>,
{
    {
        let mut entries = cache.borrow_mut();
        let current = entries.get_mut(url);
        if !should_fetch(current.as_deref(), now_ms, force) {
            let cached = current.and_then(|e| {
                e.used_ms = e.used_ms.max(now_ms);
                e.usable(now_ms).cloned()
            });
            return (cached.ok_or_else(unavailable), Outcome::Cached);
        }
        if force {
            // Recorded before the fetch, so concurrent unknown-`kid` requests see it and stay
            // within FORCED_GAP_MS instead of each starting a fetch of their own.
            entries.entry(url.to_owned()).or_default().last_forced_ms = Some(now_ms);
        }
    }
    let fetched = fetch().await.ok();
    let outcome = if fetched.is_some() {
        Outcome::Fetched { forced: force }
    } else {
        Outcome::FetchFailed { forced: force }
    };
    let mut entries = cache.borrow_mut();
    let mut entry = merge_fetch(entries.remove(url), fetched, now_ms);
    entry.used_ms = entry.used_ms.max(now_ms);
    let result = entry.usable(now_ms).cloned().ok_or_else(unavailable);
    entries.insert(url.to_owned(), entry);
    evict(&mut entries, url);
    (result, outcome)
}

/// Drops the least recently used URLs other than `keep` until at most [`MAX_URLS`] remain.
fn evict(entries: &mut HashMap<String, Entry>, keep: &str) {
    while entries.len() > MAX_URLS {
        let Some(oldest) = entries
            .iter()
            .filter(|(k, _)| k.as_str() != keep)
            .min_by_key(|(_, e)| e.used_ms)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        entries.remove(&oldest);
    }
}

async fn fetch(url: &str) -> worker::Result<Jwks> {
    let mut resp = Fetch::Request(request(url)?).send().await?;
    check_status(resp.status_code())?;
    let declared = resp
        .headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_JWKS_BYTES as u64) {
        return Err(too_large());
    }
    let body = read_capped(resp.stream()?, MAX_JWKS_BYTES).await?;
    parse_jwks(&body)
}

/// A `GET` of `url` that takes redirects manually. The hosted rule keeping `jwks_url` off the
/// service's apex checks the configured URL only, so a redirect from an allowed host to the
/// apex must not be followed; workerd has no `redirect: "error"`, so [`check_status`] refuses
/// the 3xx instead.
fn request(url: &str) -> worker::Result<Request> {
    let mut init = RequestInit::new();
    init.redirect = RequestRedirect::Manual;
    Request::new_with_init(Url::parse(url)?.as_str(), &init)
}

/// Only a `200` is a JWKS reply; a redirect is a failed fetch.
fn check_status(status: u16) -> worker::Result<()> {
    match status {
        200 => Ok(()),
        300..400 => Err(worker::Error::RustError(
            "JWKS endpoint answered with a redirect".into(),
        )),
        _ => Err(worker::Error::RustError(
            "JWKS endpoint did not return 200".into(),
        )),
    }
}

/// A fetched JWKS document, with at most [`MAX_KEYS`] keys.
fn parse_jwks(body: &[u8]) -> worker::Result<Jwks> {
    let jwks: Jwks = serde_json::from_slice(body)
        .map_err(|_| worker::Error::RustError("JWKS document is not a JWKS".into()))?;
    if jwks.keys.len() > MAX_KEYS {
        return Err(worker::Error::RustError(
            "JWKS document has too many keys".into(),
        ));
    }
    Ok(jwks)
}

fn too_large() -> worker::Error {
    worker::Error::RustError("JWKS document too large".into())
}

/// Reads `stream` to the end, failing as soon as more than `max` bytes have arrived instead of
/// buffering the rest.
async fn read_capped(
    mut stream: impl Stream<Item = worker::Result<Vec<u8>>> + Unpin,
    max: usize,
) -> worker::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::poll_fn;
    use std::pin::{Pin, pin};
    use std::task::{Context, Poll, Waker};

    use edgekms_core::jwt::Jwk;
    use futures_util::stream;

    use super::*;

    fn set() -> Jwks {
        Jwks { keys: vec![] }
    }

    fn entry(fetched_ms: u64, last_forced_ms: Option<u64>) -> Entry {
        Entry {
            jwks: Some(set()),
            fetched_ms,
            last_forced_ms,
            failed_ms: None,
            ..Entry::default()
        }
    }

    #[test]
    fn no_entry_fetches() {
        assert!(should_fetch(None, 0, false));
    }

    #[test]
    fn fresh_entry_is_used_until_ttl() {
        let e = entry(1_000, None);
        assert!(!should_fetch(Some(&e), 1_000 + TTL_MS - 1, false));
        assert!(should_fetch(Some(&e), 1_000 + TTL_MS, false));
    }

    #[test]
    fn forced_refresh_is_rate_limited_per_mount() {
        let never_forced = entry(1_000, None);
        assert!(should_fetch(Some(&never_forced), 2_000, true));
        let just_forced = entry(1_000, Some(1_500));
        assert!(!should_fetch(
            Some(&just_forced),
            1_500 + FORCED_GAP_MS - 1,
            true
        ));
        assert!(should_fetch(
            Some(&just_forced),
            1_500 + FORCED_GAP_MS,
            true
        ));
    }

    #[test]
    fn clock_going_backwards_does_not_force_fetches() {
        let e = entry(10_000, Some(10_000));
        assert!(!should_fetch(Some(&e), 5_000, true));
        assert!(!should_fetch(Some(&e), 5_000, false));
    }

    #[test]
    fn failed_fetch_backs_off_and_keeps_serving_the_stale_set() {
        // The set expired at TTL_MS and the refetch then failed.
        let failed_at = TTL_MS;
        let e = merge_fetch(Some(entry(0, None)), None, failed_at);
        assert_eq!(e.failed_ms, Some(failed_at));
        assert_eq!(e.fetched_ms, 0, "a failure doesn't make the set fresh");
        assert!(e.usable(failed_at).is_some());
        for force in [false, true] {
            assert!(!should_fetch(
                Some(&e),
                failed_at + FAILURE_BACKOFF_MS - 1,
                force
            ));
            assert!(should_fetch(
                Some(&e),
                failed_at + FAILURE_BACKOFF_MS,
                force
            ));
        }
    }

    #[test]
    fn failed_fetch_with_nothing_cached_also_backs_off() {
        let e = merge_fetch(None, None, 5_000);
        assert!(e.usable(5_000).is_none());
        assert!(!should_fetch(
            Some(&e),
            5_000 + FAILURE_BACKOFF_MS - 1,
            false
        ));
        assert!(should_fetch(Some(&e), 5_000 + FAILURE_BACKOFF_MS, false));
    }

    #[test]
    fn stale_set_stops_being_trusted_after_max_stale_age() {
        let e = merge_fetch(Some(entry(0, None)), None, MAX_STALE_MS - 1);
        assert!(e.usable(MAX_STALE_MS - 1).is_some());
        assert!(e.usable(MAX_STALE_MS).is_none());
    }

    #[test]
    fn successful_fetch_clears_the_failure() {
        let failed = merge_fetch(Some(entry(0, None)), None, TTL_MS);
        let later = TTL_MS + FAILURE_BACKOFF_MS;
        let e = merge_fetch(Some(failed), Some(set()), later);
        assert_eq!(e.failed_ms, None);
        assert_eq!(e.fetched_ms, later);
        assert!(!should_fetch(Some(&e), later + 1, false));
    }

    // ---- concurrent requests ----

    /// A set holding one key, `kid`.
    fn with_kid(kid: &str) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "RSA".into(),
                kid: Some(kid.into()),
                alg: None,
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
            }],
        }
    }

    fn kids(jwks: &Jwks) -> Vec<String> {
        jwks.keys.iter().filter_map(|k| k.kid.clone()).collect()
    }

    /// A fetch that stays pending until the test hands it a result.
    type Gate = Rc<Cell<Option<worker::Result<Jwks>>>>;

    fn gated(gate: &Gate) -> impl Future<Output = worker::Result<Jwks>> + use<> {
        let gate = Rc::clone(gate);
        poll_fn(move |_| gate.take().map_or(Poll::Pending, Poll::Ready))
    }

    fn poll_once<T>(f: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
        f.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn cache_with(e: Entry) -> Cache {
        Rc::new(RefCell::new(HashMap::from([("m".to_owned(), e)])))
    }

    #[test]
    fn failed_fetch_cannot_restore_a_set_a_concurrent_fetch_replaced() {
        // S1 (with key K) has expired; requests A and B both start a refetch. The issuer has
        // dropped K, A's fetch returns S2 without it, and B's fetch then fails.
        let cache = cache_with(Entry {
            jwks: Some(with_kid("K")),
            ..Entry::default()
        });
        let (gate_a, gate_b): (Gate, Gate) = Default::default();
        let mut a = pin!(cached_fetch(&cache, "m", TTL_MS, false, || gated(&gate_a)));
        let mut b = pin!(cached_fetch(&cache, "m", TTL_MS, false, || gated(&gate_b)));
        assert!(poll_once(a.as_mut()).is_pending());
        assert!(poll_once(b.as_mut()).is_pending());

        gate_a.set(Some(Ok(with_kid("K2"))));
        let Poll::Ready((Ok(got), outcome)) = poll_once(a.as_mut()) else {
            panic!("A should finish with S2");
        };
        assert_eq!(kids(&got), ["K2"]);
        assert_eq!(outcome, Outcome::Fetched { forced: false });

        gate_b.set(Some(Err(worker::Error::RustError("issuer down".into()))));
        let Poll::Ready((Ok(got), outcome)) = poll_once(b.as_mut()) else {
            panic!("B should fall back to the stored set");
        };
        assert_eq!(kids(&got), ["K2"], "B must not put K back");
        assert_eq!(outcome, Outcome::FetchFailed { forced: false });

        let stored = cache.borrow()["m"].clone();
        assert_eq!(kids(stored.jwks.as_ref().unwrap()), ["K2"]);
        assert_eq!(stored.fetched_ms, TTL_MS);
        assert_eq!(stored.failed_ms, Some(TTL_MS));
    }

    #[test]
    fn concurrent_unknown_kid_requests_share_one_forced_fetch() {
        let cache = cache_with(Entry {
            jwks: Some(with_kid("K")),
            fetched_ms: 1_000,
            ..Entry::default()
        });
        let gate: Gate = Rc::default();
        let mut a = pin!(cached_fetch(&cache, "m", 2_000, true, || gated(&gate)));
        assert!(poll_once(a.as_mut()).is_pending());
        // While A's forced fetch is in flight, B is refused a fetch of its own and gets the
        // cached set.
        let mut b = pin!(cached_fetch(&cache, "m", 2_001, true, || async {
            panic!("a second forced fetch started");
        }));
        let Poll::Ready((Ok(got), outcome)) = poll_once(b.as_mut()) else {
            panic!("B should get the cached set at once");
        };
        assert_eq!(kids(&got), ["K"]);
        assert_eq!(outcome, Outcome::Cached);
        gate.set(Some(Ok(with_kid("K2"))));
        let Poll::Ready((Ok(got), outcome)) = poll_once(a.as_mut()) else {
            panic!("A should finish with the refetched set");
        };
        assert_eq!(kids(&got), ["K2"]);
        assert_eq!(outcome, Outcome::Fetched { forced: true });
    }

    #[test]
    fn forced_refetch_that_fails_is_reported_as_forced() {
        let cache = cache_with(Entry {
            jwks: Some(with_kid("K")),
            fetched_ms: 1_000,
            ..Entry::default()
        });
        let (got, outcome) = pollster::block_on(cached_fetch(&cache, "m", 2_000, true, || async {
            Err(worker::Error::RustError("issuer down".into()))
        }));
        assert_eq!(kids(&got.unwrap()), ["K"], "the cached set keeps serving");
        assert_eq!(outcome, Outcome::FetchFailed { forced: true });
    }

    #[test]
    fn forced_request_that_finds_the_set_due_anyway_is_still_forced() {
        // An expired set would have been fetched without the unknown kid; the fetch is still
        // the forced one the login asked for, and it counts against FORCED_GAP_MS.
        let cache = cache_with(entry(0, None));
        let (_, outcome) = pollster::block_on(cached_fetch(&cache, "m", TTL_MS, true, || async {
            Ok(with_kid("K2"))
        }));
        assert_eq!(outcome, Outcome::Fetched { forced: true });
        assert_eq!(cache.borrow()["m"].last_forced_ms, Some(TTL_MS));
    }

    #[test]
    fn only_forced_refetches_and_failures_are_logged() {
        assert_eq!(log_label(Outcome::Cached), None);
        assert_eq!(log_label(Outcome::Fetched { forced: false }), None);
        assert_eq!(
            log_label(Outcome::Fetched { forced: true }),
            Some(Log::Notice(FORCED_REFETCH_LOG))
        );
        assert_eq!(
            log_label(Outcome::FetchFailed { forced: false }),
            Some(Log::Error("JWKS fetch failed"))
        );
        assert_eq!(
            log_label(Outcome::FetchFailed { forced: true }),
            Some(Log::Error("JWKS forced refetch failed"))
        );
    }

    #[test]
    fn jwks_cache_is_shared_by_url_not_mount() {
        // Two hosted tenants each have a mount named `github`, pointing at different issuers.
        // Each must be verified against its own issuer's keys, never the other's cached set.
        let cache: Cache = Rc::default();
        let (url_a, url_b) = ("https://a.example/jwks", "https://b.example/jwks");
        let (got_a, _) = pollster::block_on(cached_fetch(&cache, url_a, 1_000, false, || async {
            Ok(with_kid("A"))
        }));
        let (got_b, outcome) =
            pollster::block_on(cached_fetch(&cache, url_b, 1_001, false, || async {
                Ok(with_kid("B"))
            }));
        assert_eq!(kids(&got_a.unwrap()), ["A"]);
        assert_eq!(kids(&got_b.unwrap()), ["B"]);
        assert_eq!(outcome, Outcome::Fetched { forced: false });
        // A third mount, under any name, naming URL A shares A's entry without a fetch.
        let (got, outcome) =
            pollster::block_on(cached_fetch(&cache, url_a, 1_002, false, || async {
                panic!("URL A was cached")
            }));
        assert_eq!(kids(&got.unwrap()), ["A"]);
        assert_eq!(outcome, Outcome::Cached);
        assert_eq!(cache.borrow().len(), 2);
    }

    fn url(i: usize) -> String {
        format!("https://issuer{i}.example/jwks")
    }

    #[test]
    fn cache_past_max_urls_drops_the_least_recently_used() {
        let cache: Cache = Rc::default();
        let mut now = 1_000;
        for i in 0..MAX_URLS {
            now += 1;
            let (r, _) = pollster::block_on(cached_fetch(&cache, &url(i), now, false, || async {
                Ok(with_kid("K"))
            }));
            r.unwrap();
        }
        assert_eq!(cache.borrow().len(), MAX_URLS);
        // URL 0 is used again, so URL 1 is now the least recently used.
        now += 1;
        let (_, outcome) =
            pollster::block_on(cached_fetch(&cache, &url(0), now, false, || async {
                panic!("cached")
            }));
        assert_eq!(outcome, Outcome::Cached);
        now += 1;
        let (r, _) =
            pollster::block_on(cached_fetch(&cache, &url(MAX_URLS), now, false, || async {
                Ok(with_kid("new"))
            }));
        assert_eq!(kids(&r.unwrap()), ["new"]);
        let entries = cache.borrow();
        assert_eq!(entries.len(), MAX_URLS);
        assert!(entries.contains_key(&url(0)));
        assert!(!entries.contains_key(&url(1)));
        assert!(entries.contains_key(&url(MAX_URLS)));
    }

    #[test]
    fn jwks_with_too_many_keys_is_refused() {
        let doc = |n: usize| {
            let keys: Vec<_> = (0..n)
                .map(|i| serde_json::json!({ "kty": "RSA", "kid": format!("k{i}") }))
                .collect();
            serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap()
        };
        assert_eq!(parse_jwks(&doc(MAX_KEYS)).unwrap().keys.len(), MAX_KEYS);
        assert!(parse_jwks(&doc(MAX_KEYS + 1)).is_err());
        assert!(parse_jwks(b"{\"nokeys\":1}").is_err());
    }

    #[test]
    fn older_fetch_does_not_overwrite_a_newer_one() {
        let newer = Entry {
            jwks: Some(with_kid("new")),
            fetched_ms: 200,
            ..Entry::default()
        };
        let e = merge_fetch(Some(newer), Some(with_kid("old")), 100);
        assert_eq!(kids(e.jwks.as_ref().unwrap()), ["new"]);
        assert_eq!(e.fetched_ms, 200);
    }

    #[test]
    fn success_keeps_a_failure_that_started_later() {
        let failed_later = Entry {
            jwks: Some(with_kid("K")),
            fetched_ms: 0,
            failed_ms: Some(300),
            ..Entry::default()
        };
        let e = merge_fetch(Some(failed_later), Some(with_kid("K2")), 200);
        assert_eq!(kids(e.jwks.as_ref().unwrap()), ["K2"]);
        assert_eq!(e.failed_ms, Some(300));
    }

    #[test]
    fn body_over_the_cap_stops_reading() {
        let pulled = Cell::new(0);
        let chunks = stream::iter((0..10).map(|_| {
            pulled.set(pulled.get() + 1);
            Ok(vec![0u8; 100])
        }));
        let r = pollster::block_on(read_capped(chunks, 250));
        assert!(r.is_err());
        assert_eq!(pulled.get(), 3, "stops at the chunk that crosses the cap");

        let chunks = stream::iter((0..3).map(|_| Ok(vec![1u8; 100])));
        assert_eq!(
            pollster::block_on(read_capped(chunks, 300)).unwrap().len(),
            300
        );
    }

    #[test]
    fn only_a_200_is_a_jwks_reply() {
        assert!(check_status(200).is_ok());
        for status in [301, 302, 303, 307, 308] {
            let err = check_status(status).unwrap_err().to_string();
            assert!(err.contains("redirect"), "{status}: {err}");
        }
        for status in [204, 404, 500] {
            assert!(check_status(status).is_err(), "{status}");
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    /// With redirects followed, the hosted `jwks_url` rule would only cover the first hop.
    #[wasm_bindgen_test]
    fn jwks_request_does_not_follow_redirects() {
        let req = request("https://issuer.example/.well-known/jwks").unwrap();
        assert_eq!(req.inner().redirect(), web_sys::RequestRedirect::Manual);
    }
}
