#![cfg(target_arch = "wasm32")]
//! The tenant store contract and the per-isolate tenant cache (`edgekms_worker::store`,
//! `edgekms_worker::tenants`).
//!
//! Every store contract test runs twice: against the in-memory store in `common/memstore.rs`,
//! and against `D1Store` over a stand-in for the D1 binding built on Node's `node:sqlite` with
//! the real migration, so the SQL runs on SQLite under Node. workerd's D1 itself is exercised
//! by the hosted e2e (`scripts/e2e-hosted.sh`).
//!
//! The cache tests share the isolate's cache (one wasm binary, one `thread_local`), so each
//! test uses its own tenant names.

mod common;

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use common::memstore::{MemStore, UNKNOWN_USER};
use edgekms_core::hosted::{config_mac_input, default_config};
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::tenant::TenantName;
use edgekms_core::transit::Id;
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::store::{
    AllowRow, D1Store, InviteRequestRow, InviteRow, MemberRole, MemberRow, RequestStatus,
    SshKeyLookup, SshKeyRow, StoreError, SystemKeyRow, TenantRow, TenantStatus, TenantStore,
    UserRow, Witness,
};
use edgekms_worker::tenants::{self, LoadError, REVALIDATE_MS};
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

// ---------------------------------------------------------------------------------------------
// A D1 binding stand-in on node:sqlite. It follows D1's documented type conversion: numbers,
// strings and null bind as themselves, booleans as 0/1, an ArrayBuffer or a view as a BLOB, and
// anything else (a plain Array, which is what workers-rs's `D1Type::Blob` produces) is a
// `D1_TYPE_ERROR`. BLOBs read back as an Array of numbers. `batch` is a transaction, errors are
// `D1_ERROR: <sqlite message>`, and `prepare` never throws (D1 reports bad SQL on execution).

#[wasm_bindgen(inline_js = r#"
export function fake_d1(schema) {
  const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
  const db = new DatabaseSync(':memory:');
  db.exec(schema);
  const conv = (v) => {
    if (v === null || typeof v === 'number' || typeof v === 'string') return v;
    if (typeof v === 'boolean') return v ? 1 : 0;
    if (v instanceof ArrayBuffer) return new Uint8Array(v.slice(0));
    if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength));
    throw new Error("D1_TYPE_ERROR: Type '" + (Array.isArray(v) ? 'array' : typeof v) + "' not supported");
  };
  const out = (row) => {
    const o = {};
    for (const [k, v] of Object.entries(row)) o[k] = v instanceof Uint8Array ? Array.from(v) : v;
    return o;
  };
  // workerd's wording: `D1_ERROR: UNIQUE constraint failed: tenants.name: SQLITE_CONSTRAINT
  // (extended: SQLITE_CONSTRAINT_UNIQUE)`.
  const d1err = (e) => {
    if (e.message.startsWith('D1_')) return e;
    const m = e.message.match(/^(UNIQUE|FOREIGN KEY|CHECK|NOT NULL) constraint failed/);
    const kind = m ? '_' + m[1].replace(' ', '') : '';
    const suffix = m ? ': SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT' + kind + ')' : '';
    return new Error('D1_ERROR: ' + e.message + suffix);
  };
  class Stmt {
    constructor(sql, args) { this.sql = sql; this.args = args; }
    bind(...args) {
      try { return new Stmt(this.sql, args.map(conv)); } catch (e) { throw d1err(e); }
    }
    exec() {
      const s = db.prepare(this.sql);
      if (/^\s*select/i.test(this.sql)) {
        return { success: true, results: s.all(...this.args).map(out), meta: { changes: 0 } };
      }
      const r = s.run(...this.args);
      return { success: true, results: [], meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
    }
    async first(col) {
      let r;
      try { r = this.exec(); } catch (e) { throw d1err(e); }
      const row = r.results.length ? r.results[0] : null;
      return row === null ? null : (col == null ? row : row[col]);
    }
    async all() { try { return this.exec(); } catch (e) { throw d1err(e); } }
    async run() { try { return this.exec(); } catch (e) { throw d1err(e); } }
  }
  const prepare = (sql) => new Stmt(sql, []);
  const batch = async (stmts) => {
    db.exec('BEGIN');
    try {
      const results = stmts.map((s) => s.exec());
      db.exec('COMMIT');
      return results;
    } catch (e) {
      db.exec('ROLLBACK');
      throw d1err(e);
    }
  };
  globalThis.__fake_d1_sessions = globalThis.__fake_d1_sessions || [];
  return {
    prepare,
    batch,
    withSession(constraint) {
      globalThis.__fake_d1_sessions.push(constraint);
      return { prepare, batch, getBookmark: () => null };
    },
  };
}
export function fake_d1_sessions() { return (globalThis.__fake_d1_sessions || []).slice(); }
"#)]
extern "C" {
    fn fake_d1(schema: &str) -> JsValue;
    fn fake_d1_sessions() -> Vec<String>;
}

const MIGRATIONS: [&str; 6] = [
    include_str!("../migrations/0001_tenants.sql"),
    include_str!("../migrations/0002_invites_and_logout.sql"),
    include_str!("../migrations/0003_member_macs.sql"),
    include_str!("../migrations/0004_signup_allowlist.sql"),
    include_str!("../migrations/0005_invite_requests.sql"),
    include_str!("../migrations/0006_ssh_keys.sql"),
];

fn schema() -> String {
    MIGRATIONS.concat()
}

fn d1() -> D1Store {
    D1Store::new(fake_d1(&schema()).unchecked_into())
}

/// Each contract test as two wasm tests: `<name>::mem` and `<name>::d1`.
macro_rules! contract {
    ($($name:ident),* $(,)?) => {$(
        mod $name {
            use super::*;
            #[wasm_bindgen_test]
            async fn mem() {
                super::$name(&MemStore::default()).await;
            }
            #[wasm_bindgen_test]
            async fn d1() {
                super::$name(&super::d1()).await;
            }
        }
    )*};
}

contract!(
    create_then_read,
    duplicate_name_is_name_taken,
    duplicate_root_id_is_root_id_taken,
    create_needs_a_known_user,
    update_config_with_stale_version_conflicts,
    membership_changes_compare_and_swap,
    acting_owner_must_be_unchanged,
    tenants_for_user_lists_rows,
    rows_wrapped_with_pages_by_wrap_key,
    set_status_round_trips,
    system_key_insert_race_converges,
    upsert_user_is_idempotent,
    capped_create_stops_at_the_cap,
    capped_create_counts_created_not_owned,
    invites_grant_nothing_until_accepted,
    accepting_compares_the_membership,
    holds_tenants_once_a_tenant_exists,
    tokens_after_only_rises,
    rows_wrapped_after_pages_by_id,
    allowlist_rows_round_trip,
    holds_tenants_once_an_allowlist_row_exists,
    invite_requests_round_trip,
    invite_request_insert_is_capped_atomically,
    replacing_an_invite_request_compares_the_mac,
    deciding_is_conditional_and_atomic,
    holds_tenants_once_an_invite_request_exists,
    ssh_keys_round_trip,
    ssh_key_insert_is_unique_and_capped,
    ssh_key_delete_is_conditional_on_the_user,
    revoking_a_users_keys_raises_the_cutoff,
    consuming_a_challenge_is_single_use,
    token_state_joins_the_key,
    holds_tenants_once_an_ssh_key_exists,
    ssh_key_fingerprints_have_their_shape,
);

const NOW: u64 = 1_800_000_000_000;

fn row(id: &str, name: &str, root_id: &str, wrap_key: &str) -> TenantRow {
    TenantRow {
        id: id.into(),
        name: name.into(),
        root_id: root_id.into(),
        // Every byte value, including 0 and 255, so a lossy BLOB round trip shows.
        wrapped_root: (0..60).map(|i: u8| i.wrapping_mul(67)).collect(),
        wrap_key: wrap_key.into(),
        config: r#"{"root_id":"x"}"#.into(),
        config_version: 1,
        config_mac: vec![0, 255, 128, 7],
        status: TenantStatus::Active,
    }
}

/// The owner membership MAC the contract tests store; the store never checks it.
const MAC: &[u8] = &[0xaa; 32];

fn mrow(github_id: u64, role: MemberRole, mac: u8) -> MemberRow {
    MemberRow {
        github_id,
        role,
        added_by: 1,
        added_ms: NOW + u64::from(mac),
        mac: vec![mac; 32],
    }
}

fn irow(github_id: u64, role: MemberRole, mac: u8) -> InviteRow {
    InviteRow {
        github_id,
        role,
        invited_by: 1,
        invited_ms: NOW + u64::from(mac),
        mac: vec![mac; 32],
    }
}

fn arow(github_id: u64, mac: u8) -> AllowRow {
    AllowRow {
        github_id,
        added_by: 9,
        added_ms: NOW + u64::from(mac),
        mac: vec![mac; 32],
    }
}

fn roles(v: Vec<MemberRow>) -> Vec<(u64, MemberRole)> {
    v.into_iter().map(|m| (m.github_id, m.role)).collect()
}

fn witness(m: &MemberRow) -> Witness<'_> {
    Witness {
        github_id: m.github_id,
        added_ms: m.added_ms,
        mac: &m.mac,
    }
}

async fn create_then_read(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    let r = row("t_a", "alice", "r_a", "m1");
    s.create_tenant(&r, 1, NOW, MAC).await.unwrap();

    assert_eq!(s.tenant_by_name("alice").await.unwrap(), Some(r.clone()));
    let v = s.tenant_version("alice").await.unwrap().unwrap();
    assert_eq!(
        (
            v.id.as_str(),
            v.config_version,
            v.status,
            v.wrap_key.as_str()
        ),
        ("t_a", 1, TenantStatus::Active, "m1")
    );
    assert_eq!(s.tenant_by_name("bob").await.unwrap(), None);
    assert_eq!(s.tenant_version("bob").await.unwrap(), None);
    // The owner row holds exactly what the caller MACed: owner, added by itself at `now_ms`.
    let owner = MemberRow {
        github_id: 1,
        role: MemberRole::Owner,
        added_by: 1,
        added_ms: NOW,
        mac: MAC.to_vec(),
    };
    assert_eq!(s.member("t_a", 1).await.unwrap(), Some(owner.clone()));
    assert_eq!(s.member("t_a", 2).await.unwrap(), None);
    assert_eq!(s.members("t_a").await.unwrap(), vec![owner]);
    assert_eq!(s.count_created(1).await.unwrap(), 1);
    assert_eq!(s.count_created(2).await.unwrap(), 0);
}

async fn duplicate_name_is_name_taken(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    assert_eq!(
        s.create_tenant(&row("t_b", "alice", "r_b", "m1"), 1, NOW, MAC)
            .await,
        Err(StoreError::NameTaken)
    );
    // The failed create left no membership behind (one transaction).
    assert_eq!(s.member("t_b", 1).await.unwrap(), None);
    assert_eq!(s.count_created(1).await.unwrap(), 1);
}

async fn duplicate_root_id_is_root_id_taken(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    assert_eq!(
        s.create_tenant(&row("t_b", "bob", "r_a", "m1"), 1, NOW, MAC)
            .await,
        Err(StoreError::RootIdTaken)
    );
    assert_eq!(s.tenant_by_name("bob").await.unwrap(), None);
    assert_eq!(s.member("t_b", 1).await.unwrap(), None);
}

async fn create_needs_a_known_user(s: &impl TenantStore) {
    assert_eq!(
        s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 9, NOW, MAC)
            .await,
        Err(UNKNOWN_USER)
    );
    assert_eq!(s.tenant_by_name("alice").await.unwrap(), None);
}

async fn update_config_with_stale_version_conflicts(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    assert_eq!(
        s.update_config("t_a", 1, "{\"v\":2}", &[2, 0, 2], NOW + 1)
            .await,
        Ok(2)
    );
    // A second editor still holding version 1 loses, and changes nothing.
    assert_eq!(
        s.update_config("t_a", 1, "{\"v\":\"lost\"}", &[9], NOW + 2)
            .await,
        Err(StoreError::Conflict)
    );
    let r = s.tenant_by_name("alice").await.unwrap().unwrap();
    assert_eq!(
        (r.config.as_str(), r.config_version, r.config_mac.as_slice()),
        ("{\"v\":2}", 2, &[2u8, 0, 2][..])
    );
    assert_eq!(
        s.update_config("t_a", 2, "{\"v\":3}", &[3], NOW + 3).await,
        Ok(3)
    );
    assert_eq!(
        s.update_config("t_nope", 1, "{}", &[0], NOW).await,
        Err(StoreError::NotFound)
    );
}

/// Membership changes apply only while the row they replace is the one read (by MAC), and a
/// last-owner check's witness is still stored unchanged; the store itself has no last-owner
/// rule, since it can't tell which owner rows verify.
async fn membership_changes_compare_and_swap(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    let alice = s.member("t_a", 1).await.unwrap().unwrap();

    // A new membership expects no row; expecting one, or none where one is, conflicts.
    let bob = mrow(2, MemberRole::Owner, 2);
    assert_eq!(
        s.set_member("t_a", &bob, Some(&[9; 32]), None, None).await,
        Err(StoreError::Conflict)
    );
    s.set_member("t_a", &bob, None, None, None).await.unwrap();
    assert_eq!(
        s.set_member("t_a", &bob, None, None, None).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        roles(s.members("t_a").await.unwrap()),
        vec![(1, MemberRole::Owner), (2, MemberRole::Owner)]
    );

    // Demoting alice with bob as the witness works; the row is replaced whole.
    let alice_member = mrow(1, MemberRole::Member, 3);
    s.set_member(
        "t_a",
        &alice_member,
        Some(&alice.mac),
        Some(witness(&bob)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        s.member("t_a", 1).await.unwrap(),
        Some(alice_member.clone())
    );

    // A witness that changed (or is the target itself, or isn't an owner) refuses the change.
    let stale = Witness {
        added_ms: bob.added_ms + 1,
        ..witness(&bob)
    };
    let bob_member = mrow(2, MemberRole::Member, 4);
    for w in [stale, witness(&bob_member), witness(&alice_member)] {
        assert_eq!(
            s.set_member("t_a", &bob_member, Some(&bob.mac), Some(w), None)
                .await,
            Err(StoreError::Conflict),
            "{w:?}"
        );
        assert_eq!(
            s.remove_member("t_a", 2, &bob.mac, Some(w), None).await,
            Err(StoreError::Conflict),
            "{w:?}"
        );
    }
    assert_eq!(
        s.remove_member("t_a", 2, &bob.mac, Some(witness(&bob)), None)
            .await,
        Err(StoreError::Conflict)
    );
    assert_eq!(s.member("t_a", 2).await.unwrap(), Some(bob.clone()));

    // Removal names the MAC it read.
    assert_eq!(
        s.remove_member("t_a", 1, &alice.mac, None, None).await,
        Err(StoreError::Conflict)
    );
    s.remove_member("t_a", 1, &alice_member.mac, None, None)
        .await
        .unwrap();
    assert_eq!(
        s.remove_member("t_a", 1, &alice_member.mac, None, None)
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        roles(s.members("t_a").await.unwrap()),
        vec![(2, MemberRole::Owner)]
    );
    assert_eq!(
        s.set_member("t_nope", &bob, None, None, None).await,
        Err(StoreError::NotFound)
    );
}

/// A change made by an owner applies only while that owner's own row is stored unchanged, so
/// an owner removed or demoted mid-request can't complete it.
async fn acting_owner_must_be_unchanged(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    let alice = s.member("t_a", 1).await.unwrap().unwrap();
    let bob = mrow(2, MemberRole::Owner, 2);
    s.set_member("t_a", &bob, None, None, Some(witness(&alice)))
        .await
        .unwrap();
    let carol = mrow(3, MemberRole::Member, 6);
    let carol_owner = mrow(3, MemberRole::Owner, 7);
    let stale_bob = Witness {
        added_ms: bob.added_ms + 1,
        ..witness(&bob)
    };
    let not_an_owner = mrow(4, MemberRole::Member, 8);
    for actor in [stale_bob, witness(&not_an_owner)] {
        assert_eq!(
            s.set_member("t_a", &carol, None, None, Some(actor)).await,
            Err(StoreError::Conflict),
            "{actor:?}"
        );
    }
    s.set_member("t_a", &carol, None, None, Some(witness(&bob)))
        .await
        .unwrap();
    s.set_member(
        "t_a",
        &carol_owner,
        Some(&carol.mac),
        None,
        Some(witness(&bob)),
    )
    .await
    .unwrap();
    assert_eq!(
        s.remove_member(
            "t_a",
            3,
            &carol_owner.mac,
            Some(witness(&bob)),
            Some(stale_bob)
        )
        .await,
        Err(StoreError::Conflict)
    );
    // The actor may be the target: an owner leaving, with another owner as the witness.
    s.remove_member(
        "t_a",
        3,
        &carol_owner.mac,
        Some(witness(&bob)),
        Some(witness(&carol_owner)),
    )
    .await
    .unwrap();
    assert_eq!(s.member("t_a", 3).await.unwrap(), None);
}

async fn tenants_for_user_lists_rows(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    s.create_tenant(&row("t_b", "bob", "r_b", "m1"), 2, NOW, MAC)
        .await
        .unwrap();
    let member = mrow(1, MemberRole::Member, 5);
    s.set_member("t_b", &member, None, None, None)
        .await
        .unwrap();
    let listed = s.tenants_for_user(1).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|u| (u.tenant_id.as_str(), u.name.as_str(), u.row.role))
            .collect::<Vec<_>>(),
        vec![
            ("t_a", "alice", MemberRole::Owner),
            ("t_b", "bob", MemberRole::Member)
        ]
    );
    assert_eq!(listed[1].row, member);
    assert_eq!(s.tenants_for_user(2).await.unwrap().len(), 1);
    assert_eq!(s.tenants_for_user(3).await.unwrap(), vec![]);
    assert_eq!(s.count_created(1).await.unwrap(), 1);
}

async fn rows_wrapped_with_pages_by_wrap_key(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    for (id, wrap) in [("t_1", "m1"), ("t_2", "m1"), ("t_3", "m2"), ("t_4", "m1")] {
        let name = format!("n{id}").replace('_', "");
        s.create_tenant(&row(id, &name, &format!("r{id}"), wrap), 1, NOW, MAC)
            .await
            .unwrap();
    }
    let mut moved = Vec::new();
    loop {
        let page = s.rows_wrapped_with("m1", 2).await.unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2);
        for w in page {
            assert_eq!(w.root_id, format!("r{}", w.id));
            assert_eq!(w.wrapped_root.len(), 60);
            s.set_wrapped(&w.id, "m1", &[7; 60], "m2").await.unwrap();
            // A second rewrapper racing on the same row loses.
            assert_eq!(
                s.set_wrapped(&w.id, "m1", &[8; 60], "m2").await,
                Err(StoreError::Conflict)
            );
            moved.push(w.id);
        }
    }
    moved.sort();
    assert_eq!(moved, ["t_1", "t_2", "t_4"]);
    assert_eq!(s.rows_wrapped_with("m2", 10).await.unwrap().len(), 4);
    let r = s.tenant_by_name("nt1").await.unwrap().unwrap();
    assert_eq!((r.wrapped_root, r.wrap_key.as_str()), (vec![7; 60], "m2"));
    assert_eq!(
        s.set_wrapped("t_nope", "m1", &[0; 60], "m2").await,
        Err(StoreError::NotFound)
    );
}

async fn set_status_round_trips(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    s.set_status("t_a", TenantStatus::Suspended).await.unwrap();
    assert_eq!(
        s.tenant_version("alice").await.unwrap().unwrap().status,
        TenantStatus::Suspended
    );
    assert_eq!(
        s.tenant_by_name("alice").await.unwrap().unwrap().status,
        TenantStatus::Suspended
    );
    s.set_status("t_a", TenantStatus::Active).await.unwrap();
    assert_eq!(
        s.tenant_version("alice").await.unwrap().unwrap().status,
        TenantStatus::Active
    );
    assert_eq!(
        s.set_status("t_nope", TenantStatus::Active).await,
        Err(StoreError::NotFound)
    );
}

async fn system_key_insert_race_converges(s: &impl TenantStore) {
    let first = SystemKeyRow {
        name: "control".into(),
        root_id: "r_first".into(),
        wrapped_root: vec![1; 60],
        wrap_key: "m1".into(),
        created_ms: NOW,
    };
    let second = SystemKeyRow {
        root_id: "r_second".into(),
        wrapped_root: vec![2; 60],
        created_ms: NOW + 1,
        ..first.clone()
    };
    assert_eq!(s.system_key("control").await.unwrap(), None);
    assert_eq!(s.insert_system_key_if_absent(&first).await.unwrap(), first);
    // The isolate that lost the race gets the winner's row, not its own.
    assert_eq!(s.insert_system_key_if_absent(&second).await.unwrap(), first);
    assert_eq!(s.system_key("control").await.unwrap(), Some(first.clone()));

    assert_eq!(
        s.set_system_wrapped("control", "m2", &[3; 60], "m3").await,
        Err(StoreError::Conflict)
    );
    s.set_system_wrapped("control", "m1", &[3; 60], "m2")
        .await
        .unwrap();
    let k = s.system_key("control").await.unwrap().unwrap();
    assert_eq!((k.wrapped_root, k.wrap_key.as_str()), (vec![3; 60], "m2"));
    assert_eq!(
        s.set_system_wrapped("nope", "m1", &[3; 60], "m2").await,
        Err(StoreError::NotFound)
    );
}

async fn upsert_user_is_idempotent(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(1, "alice-renamed", NOW + 5).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    assert_eq!(s.count_created(1).await.unwrap(), 1);
}

async fn capped_create_stops_at_the_cap(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant_capped(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC, 2)
        .await
        .unwrap();
    s.create_tenant_capped(&row("t_b", "alice-b", "r_b", "m1"), 1, NOW, MAC, 2)
        .await
        .unwrap();
    assert_eq!(
        s.create_tenant_capped(&row("t_c", "alice-c", "r_c", "m1"), 1, NOW, MAC, 2)
            .await,
        Err(StoreError::CapReached)
    );
    // Nothing of the refused tenant landed, not even its owner membership.
    assert_eq!(s.tenant_by_name("alice-c").await.unwrap(), None);
    assert_eq!(s.count_created(1).await.unwrap(), 2);
    // The uncapped create is unaffected (operators).
    s.create_tenant(&row("t_c", "alice-c", "r_c", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    // A cap of 1 claims the first tenant only once.
    s.upsert_user(2, "bob", NOW).await.unwrap();
    s.create_tenant_capped(&row("t_d", "bob", "r_d", "m1"), 2, NOW, MAC, 1)
        .await
        .unwrap();
    assert_eq!(
        s.create_tenant_capped(&row("t_e", "bob-x", "r_e", "m1"), 2, NOW, MAC, 1)
            .await,
        Err(StoreError::CapReached)
    );
}

async fn capped_create_counts_created_not_owned(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    // Leaving a tenant you created doesn't give the slot back.
    let bob = mrow(2, MemberRole::Owner, 2);
    s.set_member("t_a", &bob, None, None, None).await.unwrap();
    s.remove_member("t_a", 1, MAC, Some(witness(&bob)), None)
        .await
        .unwrap();
    assert_eq!(s.member("t_a", 1).await.unwrap(), None);
    assert_eq!(
        s.create_tenant_capped(&row("t_b", "alice-b", "r_b", "m1"), 1, NOW, MAC, 1)
            .await,
        Err(StoreError::CapReached)
    );
}

async fn invites_grant_nothing_until_accepted(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    let to_bob = irow(2, MemberRole::Owner, 2);
    let to_carol = irow(3, MemberRole::Member, 3);
    s.invite("t_a", &to_bob).await.unwrap();
    s.invite("t_a", &to_carol).await.unwrap();
    assert_eq!(s.invite("t_nope", &to_bob).await, Err(StoreError::NotFound));
    assert_eq!(s.member("t_a", 2).await.unwrap(), None);
    assert_eq!(s.tenants_for_user(2).await.unwrap(), vec![]);
    assert_eq!(
        s.invites_for_user(2).await.unwrap(),
        vec![UserRow {
            tenant_id: "t_a".to_owned(),
            name: "alice".to_owned(),
            row: to_bob.clone(),
        }]
    );
    assert_eq!(
        s.invites("t_a").await.unwrap(),
        vec![to_bob.clone(), to_carol.clone()]
    );
    // A re-invite replaces the row, MAC included.
    let to_bob_again = irow(2, MemberRole::Owner, 4);
    s.invite("t_a", &to_bob_again).await.unwrap();
    assert_eq!(s.invites("t_a").await.unwrap()[0], to_bob_again);

    // Accepting names the invite it read: the replaced one conflicts.
    let bob = mrow(2, MemberRole::Owner, 5);
    assert_eq!(
        s.accept_invite("t_a", &to_bob.mac, None, &bob).await,
        Err(StoreError::Conflict)
    );
    s.accept_invite("t_a", &to_bob_again.mac, None, &bob)
        .await
        .unwrap();
    assert_eq!(
        s.accept_invite("t_a", &to_bob_again.mac, None, &bob).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(s.member("t_a", 2).await.unwrap(), Some(bob));
    assert_eq!(s.invites_for_user(2).await.unwrap(), vec![]);
    // Declining or withdrawing names the invite read, too.
    assert_eq!(
        s.delete_invite("t_a", 3, &to_bob.mac).await,
        Err(StoreError::Conflict)
    );
    s.delete_invite("t_a", 3, &to_carol.mac).await.unwrap();
    assert_eq!(
        s.delete_invite("t_a", 3, &to_carol.mac).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        s.accept_invite("t_a", &to_carol.mac, None, &mrow(3, MemberRole::Member, 6))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(s.member("t_a", 3).await.unwrap(), None);
}

/// Accepting applies only while the membership is the one read: none, or the row with the MAC
/// read. A conflict leaves both the invite and the membership as they were.
async fn accepting_compares_the_membership(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    let to_alice = irow(1, MemberRole::Member, 2);
    s.invite("t_a", &to_alice).await.unwrap();
    let raised = mrow(1, MemberRole::Owner, 3);
    for current in [None, Some(&[7u8; 32][..])] {
        assert_eq!(
            s.accept_invite("t_a", &to_alice.mac, current, &raised)
                .await,
            Err(StoreError::Conflict)
        );
    }
    assert_eq!(s.invites("t_a").await.unwrap(), vec![to_alice.clone()]);
    assert_eq!(s.member("t_a", 1).await.unwrap().unwrap().mac, MAC);
    s.accept_invite("t_a", &to_alice.mac, Some(MAC), &raised)
        .await
        .unwrap();
    assert_eq!(s.member("t_a", 1).await.unwrap(), Some(raised));
    assert_eq!(s.invites("t_a").await.unwrap(), vec![]);
}

async fn holds_tenants_once_a_tenant_exists(s: &impl TenantStore) {
    assert!(!s.holds_tenants().await.unwrap());
    s.upsert_user(1, "alice", NOW).await.unwrap();
    // Users alone don't count: logging in comes before the first tenant.
    assert!(!s.holds_tenants().await.unwrap());
    s.create_tenant(&row("t_a", "alice", "r_a", "m1"), 1, NOW, MAC)
        .await
        .unwrap();
    assert!(s.holds_tenants().await.unwrap());
}

async fn tokens_after_only_rises(s: &impl TenantStore) {
    assert_eq!(s.tokens_after(1).await.unwrap(), None);
    assert_eq!(s.set_tokens_after(1, 5).await, Err(StoreError::NotFound));
    s.upsert_user(1, "alice", NOW).await.unwrap();
    assert_eq!(s.tokens_after(1).await.unwrap(), Some(0));
    s.set_tokens_after(1, NOW).await.unwrap();
    s.set_tokens_after(1, NOW - 1).await.unwrap();
    assert_eq!(s.tokens_after(1).await.unwrap(), Some(NOW));
    // A later login doesn't reset it.
    s.upsert_user(1, "alice", NOW + 9).await.unwrap();
    assert_eq!(s.tokens_after(1).await.unwrap(), Some(NOW));
}

async fn rows_wrapped_after_pages_by_id(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    for (id, name, wk) in [
        ("t_c", "tc-name", "m1"),
        ("t_a", "ta-name", "m1"),
        ("t_b", "tb-name", "m2"),
        ("t_d", "td-name", "m1"),
    ] {
        s.create_tenant(&row(id, name, &format!("r{id}"), wk), 1, NOW, MAC)
            .await
            .unwrap();
    }
    let ids = |v: Vec<edgekms_worker::store::WrappedRoot>| {
        v.into_iter().map(|w| w.id).collect::<Vec<_>>()
    };
    assert_eq!(
        ids(s.rows_wrapped_after("m1", "", 2).await.unwrap()),
        ["t_a", "t_c"]
    );
    assert_eq!(
        ids(s.rows_wrapped_after("m1", "t_c", 2).await.unwrap()),
        ["t_d"]
    );
    assert_eq!(
        ids(s.rows_wrapped_after("m1", "t_d", 2).await.unwrap()),
        Vec::<String>::new()
    );
}

/// The signup allowlist: an upsert by GitHub id, a read of one row, the whole list by id, and a
/// delete that is `NotFound` for an absent id. The store never checks the MAC.
async fn allowlist_rows_round_trip(s: &impl TenantStore) {
    assert_eq!(s.allowed_signup(7).await.unwrap(), None);
    assert_eq!(s.allowlist().await.unwrap(), vec![]);
    s.allow_signup(&arow(7, 1)).await.unwrap();
    s.allow_signup(&arow(3, 2)).await.unwrap();
    assert_eq!(s.allowed_signup(7).await.unwrap(), Some(arow(7, 1)));
    assert_eq!(s.allowlist().await.unwrap(), vec![arow(3, 2), arow(7, 1)]);
    // Adding again replaces the row, MAC included.
    s.allow_signup(&arow(7, 5)).await.unwrap();
    assert_eq!(s.allowed_signup(7).await.unwrap(), Some(arow(7, 5)));
    s.disallow_signup(7).await.unwrap();
    assert_eq!(s.allowed_signup(7).await.unwrap(), None);
    assert_eq!(s.disallow_signup(7).await, Err(StoreError::NotFound));
    assert_eq!(s.allowlist().await.unwrap(), vec![arow(3, 2)]);
}

/// Allowlist rows carry MACs under the control root too, so they count as holding state the
/// root keys: a lost root isn't replaced while one exists.
async fn holds_tenants_once_an_allowlist_row_exists(s: &impl TenantStore) {
    assert!(!s.holds_tenants().await.unwrap());
    s.allow_signup(&arow(7, 1)).await.unwrap();
    assert!(s.holds_tenants().await.unwrap());
}

/// A pending invite request from `github_id`, filed at `NOW + created`, with MAC `[mac; 32]`.
fn rrow(github_id: u64, created: u64, mac: u8) -> InviteRequestRow {
    InviteRequestRow {
        github_id,
        login: format!("user{github_id}"),
        note: "CI signing\nfor a small project \u{1f510}".into(),
        created_ms: NOW + created,
        status: RequestStatus::Pending,
        decided_by: None,
        decided_ms: None,
        mac: vec![mac; 32],
    }
}

/// `r` as a decision left it.
fn decided(mut r: InviteRequestRow, status: RequestStatus, by: u64, ms: u64) -> InviteRequestRow {
    r.status = status;
    r.decided_by = Some(by);
    r.decided_ms = Some(ms);
    r
}

fn ids(v: &[InviteRequestRow]) -> Vec<u64> {
    v.iter().map(|r| r.github_id).collect()
}

/// Invite requests: an insert, a read by GitHub id, the listing (every pending row by
/// `created_ms`, then the most recently decided up to the limit) and a delete.
async fn invite_requests_round_trip(s: &impl TenantStore) {
    assert_eq!(s.invite_request(7).await.unwrap(), None);
    assert_eq!(s.invite_requests(10).await.unwrap(), vec![]);
    for (id, created) in [(7, 30), (3, 10), (5, 20), (8, 40), (9, 50)] {
        s.insert_invite_request(&rrow(id, created, 1), 200)
            .await
            .unwrap();
    }
    assert_eq!(s.invite_request(7).await.unwrap(), Some(rrow(7, 30, 1)));
    assert_eq!(ids(&s.invite_requests(10).await.unwrap()), [3, 5, 7, 8, 9]);
    // Decided rows follow, newest decision first, and only as many as asked for.
    for (id, ms) in [(8, 100), (9, 300), (5, 200)] {
        s.decide_invite_request(id, &[1; 32], RequestStatus::Declined, 1, NOW + ms, None)
            .await
            .unwrap();
    }
    let all = s.invite_requests(10).await.unwrap();
    assert_eq!(ids(&all), [3, 7, 9, 5, 8]);
    assert_eq!(
        all[2],
        decided(rrow(9, 50, 1), RequestStatus::Declined, 1, NOW + 300)
    );
    assert_eq!(ids(&s.invite_requests(2).await.unwrap()), [3, 7, 9, 5]);
    assert_eq!(ids(&s.invite_requests(0).await.unwrap()), [3, 7]);
    s.delete_invite_request(9).await.unwrap();
    assert_eq!(s.invite_request(9).await.unwrap(), None);
    assert_eq!(s.delete_invite_request(9).await, Err(StoreError::NotFound));
}

/// The pending cap is checked in the insert itself: at the cap nothing lands (`CapReached`),
/// a second request from one id is `Conflict`, and decided rows don't count.
async fn invite_request_insert_is_capped_atomically(s: &impl TenantStore) {
    s.insert_invite_request(&rrow(1, 1, 1), 2).await.unwrap();
    assert_eq!(
        s.insert_invite_request(&rrow(1, 2, 2), 2).await,
        Err(StoreError::Conflict)
    );
    s.insert_invite_request(&rrow(2, 2, 1), 2).await.unwrap();
    assert_eq!(
        s.insert_invite_request(&rrow(3, 3, 1), 2).await,
        Err(StoreError::CapReached)
    );
    assert_eq!(s.invite_request(3).await.unwrap(), None);
    // A decision frees a place.
    s.decide_invite_request(1, &[1; 32], RequestStatus::Approved, 9, NOW, None)
        .await
        .unwrap();
    s.insert_invite_request(&rrow(3, 3, 1), 2).await.unwrap();
    assert_eq!(
        s.insert_invite_request(&rrow(4, 4, 1), 0).await,
        Err(StoreError::CapReached)
    );
}

/// A replace (of a row whose MAC didn't verify) applies only while the stored MAC is the one
/// read, resets the decision, and doesn't count the row it replaces against the cap.
async fn replacing_an_invite_request_compares_the_mac(s: &impl TenantStore) {
    s.insert_invite_request(&rrow(1, 1, 0xee), 1).await.unwrap();
    // At the cap, the only pending row is the one being replaced.
    let new = rrow(1, 5, 2);
    assert_eq!(
        s.replace_invite_request(&new, &[0xdd; 32], 1).await,
        Err(StoreError::Conflict)
    );
    s.replace_invite_request(&new, &[0xee; 32], 1)
        .await
        .unwrap();
    assert_eq!(s.invite_request(1).await.unwrap(), Some(new.clone()));
    // A decided row comes back pending, its decision cleared; the cap still applies.
    s.decide_invite_request(1, &[2; 32], RequestStatus::Declined, 9, NOW, None)
        .await
        .unwrap();
    s.insert_invite_request(&rrow(2, 2, 1), 1).await.unwrap();
    let again = rrow(1, 6, 3);
    assert_eq!(
        s.replace_invite_request(&again, &[2; 32], 1).await,
        Err(StoreError::CapReached)
    );
    s.replace_invite_request(&again, &[2; 32], 2).await.unwrap();
    assert_eq!(s.invite_request(1).await.unwrap(), Some(again));
    assert_eq!(
        s.replace_invite_request(&rrow(4, 1, 1), &[1; 32], 9).await,
        Err(StoreError::Conflict)
    );
}

/// A decision applies only to a pending row with the MAC read, and an approval's allowlist row
/// lands with it or not at all: a second decision, or one with a stale MAC, writes nothing.
async fn deciding_is_conditional_and_atomic(s: &impl TenantStore) {
    for id in 1..=3 {
        s.insert_invite_request(&rrow(id, id, 1), 9).await.unwrap();
    }
    let allow = |id, by, ms| AllowRow {
        github_id: id,
        added_by: by,
        added_ms: ms,
        mac: vec![0x44; 32],
    };
    let approve = |id, mac: u8, by, ms, row: AllowRow| async move {
        s.decide_invite_request(id, &[mac; 32], RequestStatus::Approved, by, ms, Some(&row))
            .await
    };
    // A stale MAC changes nothing and allowlists no one.
    assert_eq!(
        approve(1, 7, 9, NOW + 50, allow(1, 9, NOW + 50)).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(s.allowed_signup(1).await.unwrap(), None);
    assert_eq!(s.invite_request(1).await.unwrap(), Some(rrow(1, 1, 1)));
    // The approval writes both.
    approve(1, 1, 9, NOW + 50, allow(1, 9, NOW + 50))
        .await
        .unwrap();
    assert_eq!(
        s.allowed_signup(1).await.unwrap(),
        Some(allow(1, 9, NOW + 50))
    );
    assert_eq!(
        s.invite_request(1).await.unwrap(),
        Some(decided(rrow(1, 1, 1), RequestStatus::Approved, 9, NOW + 50))
    );
    // A second operator's approval a moment later is a conflict and writes no allowlist row.
    s.disallow_signup(1).await.unwrap();
    assert_eq!(
        approve(1, 1, 8, NOW + 60, allow(1, 8, NOW + 60)).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(s.allowed_signup(1).await.unwrap(), None);
    // A decline writes no allowlist row; a deleted row is a conflict.
    s.decide_invite_request(2, &[1; 32], RequestStatus::Declined, 9, NOW + 70, None)
        .await
        .unwrap();
    assert_eq!(s.allowed_signup(2).await.unwrap(), None);
    assert_eq!(
        s.invite_request(2).await.unwrap(),
        Some(decided(rrow(2, 2, 1), RequestStatus::Declined, 9, NOW + 70))
    );
    s.delete_invite_request(3).await.unwrap();
    assert_eq!(
        approve(3, 1, 9, NOW + 80, allow(3, 9, NOW + 80)).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(s.allowed_signup(3).await.unwrap(), None);
}

/// Invite request rows carry MACs under the control root, so they count as state the root
/// keys, like allowlist rows.
async fn holds_tenants_once_an_invite_request_exists(s: &impl TenantStore) {
    assert!(!s.holds_tenants().await.unwrap());
    s.insert_invite_request(&rrow(1, 1, 1), 9).await.unwrap();
    assert!(s.holds_tenants().await.unwrap());
}

fn krow(fp: &str, github_id: u64, mac: u8) -> SshKeyRow {
    SshKeyRow {
        fingerprint: fp.into(),
        github_id,
        key_type: "ssh-ed25519".into(),
        public_key: format!("ssh-ed25519 AAAA{fp}"),
        label: "laptop \u{e9}".into(),
        added_ms: NOW + u64::from(mac),
        added_via: "github".into(),
        last_used_ms: None,
        // Every byte value, so a lossy BLOB round trip shows.
        mac: (0..32)
            .map(|i: u8| i.wrapping_mul(37).wrapping_add(mac))
            .collect(),
    }
}

async fn ssh_keys_round_trip(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    assert_eq!(
        s.ssh_key("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .unwrap(),
        None
    );
    assert_eq!(s.ssh_keys_for_user(1).await.unwrap(), vec![]);
    let a = krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 2);
    let mut b = krow("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, 1);
    b.added_via = "ssh:SHA256:a".into();
    b.key_type = "sk-ssh-ed25519@openssh.com".into();
    s.insert_ssh_key(&a, 10).await.unwrap();
    s.insert_ssh_key(&b, 10).await.unwrap();
    s.insert_ssh_key(
        &krow("SHA256:ccccccccccccccccccccccccccccccccccccccccccc", 2, 3),
        10,
    )
    .await
    .unwrap();
    let got = s
        .ssh_key("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.row, a);
    assert_eq!(got.login, "alice");
    // By `added_ms`: b was added first.
    assert_eq!(
        s.ssh_keys_for_user(1).await.unwrap(),
        vec![b.clone(), a.clone()]
    );
    s.ssh_login_used(
        1,
        "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        NOW + 50,
    )
    .await
    .unwrap();
    let used = s
        .ssh_key("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .await
        .unwrap()
        .unwrap()
        .row;
    assert_eq!(used.last_used_ms, Some(NOW + 50));
    assert_eq!(
        s.ssh_key("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .await
            .unwrap()
            .unwrap()
            .row
            .last_used_ms,
        None
    );
    // Another user's key isn't touched by a login that names the wrong user.
    s.ssh_login_used(
        1,
        "SHA256:ccccccccccccccccccccccccccccccccccccccccccc",
        NOW + 60,
    )
    .await
    .unwrap();
    assert_eq!(
        s.ssh_key("SHA256:ccccccccccccccccccccccccccccccccccccccccccc")
            .await
            .unwrap()
            .unwrap()
            .row
            .last_used_ms,
        None
    );
}

async fn ssh_key_insert_is_unique_and_capped(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    s.insert_ssh_key(
        &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
        2,
    )
    .await
    .unwrap();
    // A fingerprint belongs to one account: a second insert, by anyone, conflicts.
    assert_eq!(
        s.insert_ssh_key(
            &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 2),
            2
        )
        .await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        s.insert_ssh_key(
            &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2, 3),
            2
        )
        .await,
        Err(StoreError::Conflict)
    );
    s.insert_ssh_key(
        &krow("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, 4),
        2,
    )
    .await
    .unwrap();
    assert_eq!(
        s.insert_ssh_key(
            &krow("SHA256:ccccccccccccccccccccccccccccccccccccccccccc", 1, 5),
            2
        )
        .await,
        Err(StoreError::CapReached)
    );
    // The cap is per user.
    s.insert_ssh_key(
        &krow("SHA256:ccccccccccccccccccccccccccccccccccccccccccc", 2, 6),
        2,
    )
    .await
    .unwrap();
    assert_eq!(s.ssh_keys_for_user(1).await.unwrap().len(), 2);
    // A key for a user with no `users` row is refused.
    assert!(
        s.insert_ssh_key(
            &krow("SHA256:ddddddddddddddddddddddddddddddddddddddddddd", 3, 7),
            2
        )
        .await
        .is_err()
    );
    assert_eq!(
        s.ssh_key("SHA256:ddddddddddddddddddddddddddddddddddddddddddd")
            .await
            .unwrap(),
        None
    );
}

async fn ssh_key_delete_is_conditional_on_the_user(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    s.insert_ssh_key(
        &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        s.delete_ssh_key(2, "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await,
        Err(StoreError::NotFound)
    );
    assert!(
        s.ssh_key("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .unwrap()
            .is_some()
    );
    s.delete_ssh_key(1, "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .await
        .unwrap();
    assert_eq!(
        s.ssh_key("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        s.delete_ssh_key(1, "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await,
        Err(StoreError::NotFound)
    );
}

async fn revoking_a_users_keys_raises_the_cutoff(s: &impl TenantStore) {
    assert_eq!(
        s.revoke_user_ssh_keys(1, NOW).await,
        Err(StoreError::NotFound)
    );
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    s.insert_ssh_key(
        &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
        10,
    )
    .await
    .unwrap();
    s.insert_ssh_key(
        &krow("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, 2),
        10,
    )
    .await
    .unwrap();
    s.insert_ssh_key(
        &krow("SHA256:ccccccccccccccccccccccccccccccccccccccccccc", 2, 3),
        10,
    )
    .await
    .unwrap();
    s.set_tokens_after(1, NOW + 100).await.unwrap();
    assert_eq!(s.revoke_user_ssh_keys(1, NOW + 5).await, Ok(2));
    assert_eq!(s.ssh_keys_for_user(1).await.unwrap(), vec![]);
    assert_eq!(s.ssh_keys_for_user(2).await.unwrap().len(), 1);
    // Never lowered.
    assert_eq!(s.tokens_after(1).await.unwrap(), Some(NOW + 100));
    assert_eq!(s.revoke_user_ssh_keys(1, NOW + 200).await, Ok(0));
    assert_eq!(s.tokens_after(1).await.unwrap(), Some(NOW + 200));
    assert_eq!(s.tokens_after(2).await.unwrap(), Some(0));
}

async fn consuming_a_challenge_is_single_use(s: &impl TenantStore) {
    let tag: Vec<u8> = (0..32).map(|i: u8| i.wrapping_mul(71)).collect();
    s.consume_challenge(&tag, NOW + 60_000, NOW).await.unwrap();
    assert_eq!(
        s.consume_challenge(&tag, NOW + 60_000, NOW + 1).await,
        Err(StoreError::Conflict)
    );
    // Another tag is its own challenge.
    s.consume_challenge(&[1; 32], NOW + 60_000, NOW)
        .await
        .unwrap();
    // Still refused at its expiry; once it has passed, a later consume purges the row (the
    // challenge itself would be refused as expired long before it reached the store).
    assert_eq!(
        s.consume_challenge(&tag, NOW + 120_000, NOW + 60_000).await,
        Err(StoreError::Conflict)
    );
    s.consume_challenge(&[2; 32], NOW + 200_000, NOW + 60_001)
        .await
        .unwrap();
    s.consume_challenge(&tag, NOW + 200_000, NOW + 60_002)
        .await
        .unwrap();
}

async fn token_state_joins_the_key(s: &impl TenantStore) {
    assert_eq!(s.token_state(1, None).await.unwrap(), None);
    assert_eq!(
        s.token_state(
            1,
            Some("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        .await
        .unwrap(),
        None
    );
    s.upsert_user(1, "alice", NOW).await.unwrap();
    s.upsert_user(2, "bob", NOW).await.unwrap();
    assert_eq!(s.token_state(1, None).await.unwrap(), Some((0, None)));
    assert_eq!(
        s.token_state(
            1,
            Some("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        .await
        .unwrap(),
        Some((0, None))
    );
    let a = krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1);
    s.insert_ssh_key(&a, 10).await.unwrap();
    s.insert_ssh_key(
        &krow("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2, 2),
        10,
    )
    .await
    .unwrap();
    s.set_tokens_after(1, NOW).await.unwrap();
    assert_eq!(
        s.token_state(
            1,
            Some("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        .await
        .unwrap(),
        Some((NOW, Some(a)))
    );
    // Another user's key never joins.
    assert_eq!(
        s.token_state(
            1,
            Some("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        )
        .await
        .unwrap(),
        Some((NOW, None))
    );
    assert_eq!(s.token_state(1, None).await.unwrap(), Some((NOW, None)));
}

/// A fingerprint that isn't `SHA256:` and 43 characters can't be stored, so every stored row
/// has an id its owner can delete it by.
async fn ssh_key_fingerprints_have_their_shape(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    let long = format!("SHA256:{}", "a".repeat(44));
    for bad in [
        "SHA256:a",
        "MD5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        long.as_str(),
    ] {
        assert!(
            s.insert_ssh_key(&krow(bad, 1, 1), 10).await.is_err(),
            "{bad}"
        );
    }
    assert_eq!(s.ssh_keys_for_user(1).await.unwrap(), vec![]);
}

async fn holds_tenants_once_an_ssh_key_exists(s: &impl TenantStore) {
    s.upsert_user(1, "alice", NOW).await.unwrap();
    assert!(!s.holds_tenants().await.unwrap());
    s.insert_ssh_key(
        &krow("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
        10,
    )
    .await
    .unwrap();
    assert!(s.holds_tenants().await.unwrap());
}

/// The control plane's store never opens the replica session.
#[wasm_bindgen_test]
async fn d1_primary_store_reads_the_primary() {
    let s = D1Store::primary(fake_d1(&schema()).unchecked_into());
    assert!(s.is_primary_only());
    let before = fake_d1_sessions().len();
    s.tenant_version("alice").await.unwrap();
    s.tenant_by_name("alice").await.unwrap();
    assert_eq!(fake_d1_sessions().len(), before);
}

/// workers-rs's `D1Type::Blob` binds a JS Array, which D1 doesn't list as a bindable type;
/// `D1Store` binds `Uint8Array`s instead, and the stand-in refuses Arrays the same way.
#[wasm_bindgen_test]
async fn d1_blobs_round_trip_as_bytes() {
    let s = d1();
    s.upsert_user(1, "alice", NOW).await.unwrap();
    let mut r = row("t_a", "alice", "r_a", "m1");
    r.wrapped_root = (0..=255).collect();
    s.create_tenant(&r, 1, NOW, MAC).await.unwrap();
    assert_eq!(s.tenant_by_name("alice").await.unwrap(), Some(r));
}

/// Rows written before `0003_member_macs.sql` read back with the placeholder empty MAC, which
/// never verifies (a MAC is 32 bytes), so they fail closed at the control plane.
#[wasm_bindgen_test]
async fn d1_rows_from_before_the_mac_migration_have_an_empty_mac() {
    let legacy = "INSERT INTO users (github_id, login, created_ms, last_login_ms) \
                  VALUES (1, 'alice', 0, 0); \
                  INSERT INTO tenants (id, name, root_id, wrapped_root, wrap_key, config, \
                  config_version, config_mac, created_by, created_ms, updated_ms) \
                  VALUES ('t_a', 'alice', 'r_a', x'00', 'm1', '{}', 1, x'00', 1, 0, 0); \
                  INSERT INTO members (tenant_id, github_id, role, added_by, added_ms) \
                  VALUES ('t_a', 1, 'owner', 1, 0); \
                  INSERT INTO invites (tenant_id, github_id, role, invited_by, invited_ms) \
                  VALUES ('t_a', 2, 'owner', 1, 0);";
    let schema = format!(
        "{}{}{legacy}{}",
        MIGRATIONS[0], MIGRATIONS[1], MIGRATIONS[2]
    );
    let s = D1Store::new(fake_d1(&schema).unchecked_into());
    assert_eq!(
        s.member("t_a", 1).await.unwrap().unwrap().mac,
        Vec::<u8>::new()
    );
    assert_eq!(s.invites("t_a").await.unwrap()[0].mac, Vec::<u8>::new());
    assert_eq!(
        s.tenants_for_user(1).await.unwrap()[0].row.mac,
        Vec::<u8>::new()
    );
}

/// A row that doesn't parse (a negative integer, a mac that isn't a BLOB) is skipped and
/// logged, never fatal to the listing it is in, so it counts as absent like any row that
/// doesn't verify, and the rest of the tenant stays manageable.
#[wasm_bindgen_test]
async fn d1_malformed_member_and_invite_rows_are_skipped() {
    let rows = "INSERT INTO users (github_id, login, created_ms, last_login_ms) \
                VALUES (1, 'alice', 0, 0); \
                INSERT INTO tenants (id, name, root_id, wrapped_root, wrap_key, config, \
                config_version, config_mac, created_by, created_ms, updated_ms) \
                VALUES ('t_a', 'alice', 'r_a', x'00', 'm1', '{}', 1, x'00', 1, 0, 0); \
                INSERT INTO members (tenant_id, github_id, role, added_by, added_ms, mac) VALUES \
                ('t_a', 1, 'owner', 1, 0, x'aa'), ('t_a', 2, 'member', 1, -5, x'aa'), \
                ('t_a', 3, 'member', 1, 0, 'text'), ('t_a', -4, 'member', 1, 0, x'aa'); \
                INSERT INTO invites (tenant_id, github_id, role, invited_by, invited_ms, mac) \
                VALUES ('t_a', 5, 'member', 1, 0, x'bb'), ('t_a', 6, 'member', -1, 0, x'bb'), \
                ('t_a', 7, 'owner', 1, 0, 'text');";
    let s = D1Store::new(fake_d1(&format!("{}{rows}", schema())).unchecked_into());
    assert_eq!(
        roles(s.members("t_a").await.unwrap()),
        vec![(1, MemberRole::Owner)]
    );
    assert_eq!(
        s.invites("t_a")
            .await
            .unwrap()
            .iter()
            .map(|i| i.github_id)
            .collect::<Vec<_>>(),
        vec![5]
    );
    assert_eq!(s.member("t_a", 1).await.unwrap().unwrap().mac, vec![0xaa]);
    for bad in [2, 3] {
        assert_eq!(s.member("t_a", bad).await.unwrap(), None, "{bad}");
        assert_eq!(s.tenants_for_user(bad).await.unwrap(), vec![], "{bad}");
    }
    assert_eq!(s.tenants_for_user(1).await.unwrap().len(), 1);
    assert_eq!(s.invites_for_user(5).await.unwrap().len(), 1);
    for bad in [6, 7] {
        assert_eq!(s.invites_for_user(bad).await.unwrap(), vec![], "{bad}");
    }
}

/// An allowlist row that doesn't parse (a negative integer, a mac that isn't a BLOB) is skipped
/// and logged, so it admits no one, as a row that doesn't verify.
#[wasm_bindgen_test]
async fn d1_malformed_allowlist_rows_are_skipped() {
    let rows = "INSERT INTO signup_allowlist (github_id, added_by, added_ms, mac) VALUES \
                (1, 9, 0, x'aa'), (2, 9, -5, x'aa'), (3, 9, 0, 'text'), (-4, 9, 0, x'aa');";
    let s = D1Store::new(fake_d1(&format!("{}{rows}", schema())).unchecked_into());
    assert_eq!(
        s.allowlist()
            .await
            .unwrap()
            .iter()
            .map(|r| r.github_id)
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(s.allowed_signup(1).await.unwrap().unwrap().mac, vec![0xaa]);
    for bad in [2, 3] {
        assert_eq!(s.allowed_signup(bad).await.unwrap(), None, "{bad}");
    }
}

/// An invite request row that doesn't parse (a negative integer, a mac that isn't a BLOB) is
/// skipped and logged, so it is absent from the read and the listing.
#[wasm_bindgen_test]
async fn d1_malformed_invite_request_rows_are_skipped() {
    let rows = "INSERT INTO invite_requests (github_id, login, note, created_ms, mac) VALUES \
                (1, 'a', '', 0, x'aa'), (2, 'b', '', -5, x'aa'), (3, 'c', '', 0, 'text'); \
                INSERT INTO invite_requests (github_id, login, note, created_ms, status, \
                decided_by, decided_ms, mac) VALUES (4, 'd', '', 0, 'approved', -1, 1, x'aa');";
    let s = D1Store::new(fake_d1(&format!("{}{rows}", schema())).unchecked_into());
    assert_eq!(ids(&s.invite_requests(10).await.unwrap()), [1]);
    assert_eq!(s.invite_request(1).await.unwrap().unwrap().mac, vec![0xaa]);
    for bad in [2, 3, 4] {
        assert_eq!(s.invite_request(bad).await.unwrap(), None, "{bad}");
    }
}

/// Data-plane reads go through one `first-unconstrained` D1 session per store (nearest
/// replica, and sequentially consistent between the version read and the row read).
#[wasm_bindgen_test]
async fn d1_data_plane_reads_share_one_unconstrained_session() {
    let s = d1();
    let before = fake_d1_sessions().len();
    s.tenant_version("alice").await.unwrap();
    s.tenant_by_name("alice").await.unwrap();
    s.tenant_version("alice").await.unwrap();
    let sessions = fake_d1_sessions();
    assert_eq!(&sessions[before..], ["first-unconstrained"]);
}

// ---------------------------------------------------------------------------------------------
// The tenant cache.

const CLIENT: &str = "Iv_hosted_test";
const OWNER: u64 = 4242;
const M1: [u8; 32] = [0x11; 32];
const M2: [u8; 32] = [0x22; 32];

thread_local! {
    static NEXT: Cell<u64> = const { Cell::new(1) };
}

fn next() -> u64 {
    NEXT.with(|n| {
        let v = n.get();
        n.set(v + 1);
        v
    })
}

struct Fx {
    store: MemStore,
    admin: MasterAdmin,
    unwrap: MasterUnwrap,
}

async fn fx() -> Fx {
    let store = MemStore::default();
    store.upsert_user(OWNER, "owner", NOW).await.unwrap();
    Fx {
        store,
        admin: MasterAdmin::from_bytes("m1", &[("m1", &M1), ("m2", &M2)])
            .await
            .unwrap(),
        unwrap: MasterUnwrap::from_bytes(&[("m1", &M1), ("m2", &M2)])
            .await
            .unwrap(),
    }
}

/// A tenant as the control plane creates one.
struct Made {
    name: String,
    id: String,
    root_id: Id,
    ops: WebCryptoKeyOps,
}

impl Made {
    fn tenant_name(&self) -> TenantName {
        TenantName::new(&self.name).unwrap()
    }

    async fn mac(&self, version: u64, config: &str) -> Vec<u8> {
        self.ops
            .mac(
                MacPurpose::Config,
                &config_mac_input(&self.id, &self.name, version, config),
            )
            .await
            .unwrap()
            .to_vec()
    }

    /// The default config plus one more key, so an edit is visible.
    fn edited_config(&self) -> String {
        let mut v: serde_json::Value = serde_json::from_str(&self.default_config()).unwrap();
        v["keys"]["second"] =
            serde_json::json!({"id": "k_second", "latest_version": 1, "min_decryption_version": 1});
        v.to_string()
    }

    fn default_config(&self) -> String {
        default_config(&self.root_id, &Id::new("k_default").unwrap(), OWNER, CLIENT)
    }
}

/// Creates tenant `<prefix>-<n>` with the default config (or `config`, if given) and a valid
/// MAC.
async fn make(fx: &Fx, prefix: &str, config: Option<&str>) -> Made {
    let name = format!("{prefix}-{}", next());
    make_named(fx, &name, config).await
}

/// As [`make`], under exactly `name` (with a fresh id and root).
async fn make_named(fx: &Fx, name: &str, config: Option<&str>) -> Made {
    let n = next();
    let name = name.to_owned();
    let id = format!("t_{n:016x}");
    let root_id = Id::new(&format!("r_{n:016x}")).unwrap();
    let (handle, wrapped) = fx.admin.new_root(&id, &root_id).await.unwrap();
    let made = Made {
        name,
        id,
        root_id: root_id.clone(),
        ops: WebCryptoKeyOps::from_hkdf_key(handle, root_id.clone()).unwrap(),
    };
    let config = config.map_or_else(|| made.default_config(), str::to_owned);
    let mac = made.mac(1, &config).await;
    fx.store
        .create_tenant(
            &TenantRow {
                id: made.id.clone(),
                name: made.name.clone(),
                root_id: root_id.as_str().to_owned(),
                wrapped_root: wrapped,
                wrap_key: "m1".into(),
                config,
                config_version: 1,
                config_mac: mac,
                status: TenantStatus::Active,
            },
            OWNER,
            NOW,
            &[0xaa; 32],
        )
        .await
        .unwrap();
    made
}

fn origin(m: &Made) -> String {
    format!("https://{}.edge.km", m.name)
}

async fn load(fx: &Fx, m: &Made, now: u64) -> Result<tenants::Loaded, LoadError> {
    load_from(&fx.store, fx, m, now).await
}

async fn load_from(
    store: &impl TenantStore,
    fx: &Fx,
    m: &Made,
    now: u64,
) -> Result<tenants::Loaded, LoadError> {
    tenants::load(store, &fx.unwrap, &m.tenant_name(), origin(m), CLIENT, now).await
}

#[wasm_bindgen_test]
async fn first_load_unwraps_and_caches() {
    let fx = fx().await;
    let m = make(&fx, "first", None).await;
    let loaded = load(&fx, &m, NOW).await.unwrap();
    assert_eq!(loaded.tenant_id, m.id);
    assert_eq!(loaded.state.config.root_id, m.root_id);
    assert_eq!(fx.unwrap.unwrap_count(), 1);

    // The cached handle is the tenant's root: a ciphertext it makes decrypts under the root
    // the control plane created.
    let key = Id::new("k_default").unwrap();
    let ct = loaded.state.ops.encrypt(&key, 1, b"hello").await.unwrap();
    let pt = m.ops.decrypt(&key, &ct.parse().unwrap()).await.unwrap();
    assert_eq!(&pt[..], b"hello");

    let again = load(&fx, &m, NOW + 1).await.unwrap();
    assert!(std::rc::Rc::ptr_eq(&loaded.state, &again.state));
    assert_eq!(fx.unwrap.unwrap_count(), 1);
}

#[wasm_bindgen_test]
async fn second_load_within_30s_reads_nothing() {
    let fx = fx().await;
    let m = make(&fx, "second", None).await;
    load(&fx, &m, NOW).await.unwrap();
    let calls = fx.store.calls();
    load(&fx, &m, NOW + REVALIDATE_MS - 1).await.unwrap();
    assert_eq!(fx.store.calls(), calls, "a fresh entry touches no store");
    // Past the interval, one cheap version read and nothing else.
    load(&fx, &m, NOW + REVALIDATE_MS).await.unwrap();
    assert_eq!(fx.store.calls(), calls + 1);
    // And the revalidation restarted the interval.
    load(&fx, &m, NOW + 2 * REVALIDATE_MS - 1).await.unwrap();
    assert_eq!(fx.store.calls(), calls + 1);
    assert_eq!(fx.unwrap.unwrap_count(), 1);
}

async fn edit(fx: &Fx, m: &Made, from_version: u64, config: &str) {
    let mac = m.mac(from_version + 1, config).await;
    fx.store
        .update_config(&m.id, from_version, config, &mac, NOW)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn config_edit_is_seen_after_revalidate() {
    let fx = fx().await;
    let m = make(&fx, "edit", None).await;
    load(&fx, &m, NOW).await.unwrap();
    edit(&fx, &m, 1, &m.edited_config()).await;

    let stale = load(&fx, &m, NOW + 1).await.unwrap();
    assert!(!stale.state.config.keys.contains_key("second"));
    let fresh = load(&fx, &m, NOW + REVALIDATE_MS + 1).await.unwrap();
    assert!(fresh.state.config.keys.contains_key("second"));
}

#[wasm_bindgen_test]
async fn config_edit_does_not_unwrap_again() {
    let fx = fx().await;
    let m = make(&fx, "nounwrap", None).await;
    load(&fx, &m, NOW).await.unwrap();
    edit(&fx, &m, 1, &m.edited_config()).await;
    let fresh = load(&fx, &m, NOW + REVALIDATE_MS).await.unwrap();
    assert!(fresh.state.config.keys.contains_key("second"));
    assert_eq!(fx.unwrap.unwrap_count(), 1);
}

#[wasm_bindgen_test]
async fn rewrap_unwraps_again() {
    let fx = fx().await;
    let m = make(&fx, "rewrap", None).await;
    let before = load(&fx, &m, NOW).await.unwrap();
    let row = fx.store.tenant_by_name(&m.name).await.unwrap().unwrap();
    let admin2 = MasterAdmin::from_bytes("m2", &[("m1", &M1), ("m2", &M2)])
        .await
        .unwrap();
    let rewrapped = admin2
        .rewrap("m1", &row.wrapped_root, &m.id, &m.root_id)
        .await
        .unwrap();
    fx.store
        .set_wrapped(&m.id, "m1", &rewrapped, "m2")
        .await
        .unwrap();

    let after = load(&fx, &m, NOW + REVALIDATE_MS).await.unwrap();
    assert_eq!(fx.unwrap.unwrap_count(), 2);
    assert!(!std::rc::Rc::ptr_eq(&before.state, &after.state));
}

#[wasm_bindgen_test]
async fn tampered_config_is_refused() {
    let fx = fx().await;
    let m = make(&fx, "tamper", None).await;
    // A direct D1 write that adds a role without the master can't produce a MAC.
    fx.store.tamper(&m.name, |r| r.config = m.edited_config());
    assert_eq!(
        load(&fx, &m, NOW).await.err(),
        Some(LoadError::Invalid("tenant_config_mac_bad"))
    );

    // A MAC from another version doesn't verify either (the version is in the MAC input).
    let n = make(&fx, "tamperver", None).await;
    fx.store.tamper(&n.name, |r| r.config_version = 2);
    assert_eq!(
        load(&fx, &n, NOW).await.err(),
        Some(LoadError::Invalid("tenant_config_mac_bad"))
    );
}

#[wasm_bindgen_test]
async fn swapped_wrapped_root_is_refused() {
    let fx = fx().await;
    let a = make(&fx, "swapa", None).await;
    let b = make(&fx, "swapb", None).await;
    let a_wrapped = fx
        .store
        .tenant_by_name(&a.name)
        .await
        .unwrap()
        .unwrap()
        .wrapped_root;
    fx.store.tamper(&b.name, |r| r.wrapped_root = a_wrapped);
    assert_eq!(
        load(&fx, &b, NOW).await.err(),
        Some(LoadError::Invalid("tenant_unwrap_failed"))
    );
    assert_eq!(fx.unwrap.unwrap_count(), 0);
}

#[wasm_bindgen_test]
async fn bad_edit_keeps_the_previous_entry_for_one_interval() {
    let fx = fx().await;
    let m = make(&fx, "badedit", None).await;
    load(&fx, &m, NOW).await.unwrap();
    fx.store
        .update_config(&m.id, 1, &m.edited_config(), &[0; 32], NOW)
        .await
        .unwrap();

    let t1 = NOW + REVALIDATE_MS;
    let kept = load(&fx, &m, t1).await.unwrap();
    assert!(!kept.state.config.keys.contains_key("second"));
    let kept = load(&fx, &m, t1 + REVALIDATE_MS - 1).await.unwrap();
    assert!(!kept.state.config.keys.contains_key("second"));
    assert_eq!(
        load(&fx, &m, t1 + REVALIDATE_MS).await.err(),
        Some(LoadError::Invalid("tenant_config_mac_bad"))
    );
    // A correct edit restores it.
    edit(&fx, &m, 2, &m.edited_config()).await;
    let fixed = load(&fx, &m, t1 + REVALIDATE_MS + 1).await.unwrap();
    assert!(fixed.state.config.keys.contains_key("second"));
}

#[wasm_bindgen_test]
async fn config_failing_hosted_rules_is_refused() {
    let fx = fx().await;
    let probe = make(&fx, "rulesprobe", None).await;

    // Correctly MACed, but naming its own origin.
    let m = make(&fx, "rules", None).await;
    let mut cfg: serde_json::Value = serde_json::from_str(&m.default_config()).unwrap();
    cfg["public_origins"] = serde_json::json!(["https://evil.example"]);
    let cfg = cfg.to_string();
    let mac = m.mac(1, &cfg).await;
    fx.store.tamper(&m.name, |r| {
        r.config.clone_from(&cfg);
        r.config_mac = mac;
    });
    assert_eq!(
        load(&fx, &m, NOW).await.err(),
        Some(LoadError::Invalid("tenant_config_invalid"))
    );

    // Another GitHub App's client id.
    let g = make(&fx, "rulesgh", None).await;
    let cfg = g.default_config().replace(CLIENT, "Iv_someone_else");
    let mac = g.mac(1, &cfg).await;
    fx.store.tamper(&g.name, |r| {
        r.config.clone_from(&cfg);
        r.config_mac = mac;
    });
    assert_eq!(
        load(&fx, &g, NOW).await.err(),
        Some(LoadError::Invalid("tenant_config_invalid"))
    );

    // Another tenant's root id (the config is MACed under this tenant's root).
    assert_eq!(
        load(&fx, &probe, NOW).await.map(|l| l.tenant_id),
        Ok(probe.id.clone())
    );
    let x = make(&fx, "rulesroot", Some(&probe.default_config())).await;
    assert_eq!(
        load(&fx, &x, NOW).await.err(),
        Some(LoadError::Invalid("tenant_config_invalid"))
    );
}

#[wasm_bindgen_test]
async fn public_origins_is_the_tenant_origin() {
    let fx = fx().await;
    let m = make(&fx, "origin", None).await;
    let loaded = load(&fx, &m, NOW).await.unwrap();
    assert_eq!(loaded.state.config.public_origins, vec![origin(&m)]);
}

#[wasm_bindgen_test]
async fn unknown_name_is_negative_cached() {
    let fx = fx().await;
    let name = TenantName::new(&format!("ghost-{}", next())).unwrap();
    let get = |now| {
        tenants::load(
            &fx.store,
            &fx.unwrap,
            &name,
            "https://x.edge.km".into(),
            CLIENT,
            now,
        )
    };
    assert_eq!(get(NOW).await.err(), Some(LoadError::Unknown));
    let calls = fx.store.calls();
    assert_eq!(
        get(NOW + tenants::NEGATIVE_MS - 1).await.err(),
        Some(LoadError::Unknown)
    );
    assert_eq!(fx.store.calls(), calls, "a cached miss touches no store");
    assert_eq!(
        get(NOW + tenants::NEGATIVE_MS).await.err(),
        Some(LoadError::Unknown)
    );
    assert_eq!(fx.store.calls(), calls + 1);
}

#[wasm_bindgen_test]
async fn suspended_tenant_is_refused() {
    let fx = fx().await;
    let m = make(&fx, "suspend", None).await;
    load(&fx, &m, NOW).await.unwrap();
    fx.store
        .set_status(&m.id, TenantStatus::Suspended)
        .await
        .unwrap();
    // Seen at the next revalidation, like any other change.
    assert!(load(&fx, &m, NOW + 1).await.is_ok());
    assert_eq!(
        load(&fx, &m, NOW + REVALIDATE_MS).await.err(),
        Some(LoadError::Suspended)
    );
    // The refusal is cached like an unknown name: no store read per request.
    let calls = fx.store.calls();
    assert_eq!(
        load(&fx, &m, NOW + REVALIDATE_MS + tenants::NEGATIVE_MS - 1)
            .await
            .err(),
        Some(LoadError::Suspended)
    );
    assert_eq!(fx.store.calls(), calls);
    // Reactivation is seen once that expires, with a fresh unwrap (the entry was dropped).
    fx.store
        .set_status(&m.id, TenantStatus::Active)
        .await
        .unwrap();
    assert!(
        load(&fx, &m, NOW + REVALIDATE_MS + tenants::NEGATIVE_MS)
            .await
            .is_ok()
    );
    assert_eq!(fx.unwrap.unwrap_count(), 2);

    // A tenant suspended before its first load never loads.
    let s = make(&fx, "suspended", None).await;
    fx.store
        .set_status(&s.id, TenantStatus::Suspended)
        .await
        .unwrap();
    assert_eq!(load(&fx, &s, NOW).await.err(), Some(LoadError::Suspended));
}

#[wasm_bindgen_test]
async fn store_failure_is_backend() {
    let fx = fx().await;
    let m = make(&fx, "outage", None).await;
    fx.store.fail_with(Some(StoreError::Backend("d1_down")));
    assert_eq!(
        load(&fx, &m, NOW).await.err(),
        Some(LoadError::Backend("d1_down"))
    );
    // A cached tenant keeps serving through an outage until its revalidation.
    fx.store.fail_with(None);
    load(&fx, &m, NOW).await.unwrap();
    fx.store.fail_with(Some(StoreError::Backend("d1_down")));
    assert!(load(&fx, &m, NOW + REVALIDATE_MS - 1).await.is_ok());
    assert_eq!(
        load(&fx, &m, NOW + REVALIDATE_MS).await.err(),
        Some(LoadError::Backend("d1_down"))
    );
}

#[wasm_bindgen_test]
async fn lru_drops_the_oldest_past_256() {
    let fx = fx().await;
    let mut made = Vec::new();
    for _ in 0..=tenants::MAX_TENANTS {
        made.push(make(&fx, "lru", None).await);
    }
    for m in &made {
        load(&fx, m, NOW).await.unwrap();
    }
    let n = u64::try_from(made.len()).unwrap();
    assert_eq!(fx.unwrap.unwrap_count(), n);
    // The newest 256 are cached...
    load(&fx, &made[made.len() - 1], NOW + 1).await.unwrap();
    load(&fx, &made[1], NOW + 1).await.unwrap();
    assert_eq!(fx.unwrap.unwrap_count(), n);
    // ...and the first, least recently used, was dropped.
    let calls = fx.store.calls();
    load(&fx, &made[0], NOW + 1).await.unwrap();
    assert_eq!(fx.unwrap.unwrap_count(), n + 1);
    assert_eq!(fx.store.calls(), calls + 2);
}

/// A D1 writer swapping two rows' names would serve A's keys at B's hostname; the name is in
/// the MAC input, so neither row loads under the other's name.
#[wasm_bindgen_test]
async fn swapped_names_are_refused() {
    let fx = fx().await;
    let a = make(&fx, "nameswapa", None).await;
    let b = make(&fx, "nameswapb", None).await;
    let parked = format!("parked-{}", next());
    fx.store.tamper(&a.name, |r| r.name.clone_from(&parked));
    fx.store.tamper(&b.name, |r| r.name.clone_from(&a.name));
    fx.store.tamper(&parked, |r| r.name.clone_from(&b.name));
    for m in [&a, &b] {
        assert_eq!(
            load(&fx, m, NOW).await.err(),
            Some(LoadError::Invalid("tenant_config_mac_bad")),
            "{}",
            m.name
        );
    }
}

#[wasm_bindgen_test]
async fn name_recreated_with_a_new_id_serves_the_new_tenant() {
    let fx = fx().await;
    let old = make(&fx, "recreate", None).await;
    let first = load(&fx, &old, NOW).await.unwrap();
    assert_eq!(first.tenant_id, old.id);
    fx.store.delete_tenant(&old.name);
    let new = make_named(&fx, &old.name, None).await;
    assert_ne!(new.id, old.id);

    let later = load(&fx, &new, NOW + REVALIDATE_MS).await.unwrap();
    assert_eq!(later.tenant_id, new.id);
    assert_eq!(later.state.config.root_id, new.root_id);
    // A new tenant means a new root, never the old tenant's handle.
    assert_eq!(fx.unwrap.unwrap_count(), 2);
}

/// The previous entry only covers for a broken edit of the same tenant: a broken row under a
/// new id is refused at once, not answered with the old tenant's state.
#[wasm_bindgen_test]
async fn broken_row_with_a_new_id_does_not_keep_the_old_entry() {
    let fx = fx().await;
    let old = make(&fx, "recreatebad", None).await;
    load(&fx, &old, NOW).await.unwrap();
    fx.store.delete_tenant(&old.name);
    let new = make_named(&fx, &old.name, None).await;
    fx.store.tamper(&new.name, |r| r.config_mac = vec![0; 32]);
    assert_eq!(
        load(&fx, &new, NOW + REVALIDATE_MS).await.err(),
        Some(LoadError::Invalid("tenant_config_mac_bad"))
    );
}

/// A row rolled back to an older, config with a valid MAC is ignored by an isolate that has
/// already served a newer one.
#[wasm_bindgen_test]
async fn older_config_version_is_ignored() {
    let fx = fx().await;
    let m = make(&fx, "rollback", None).await;
    let v1 = fx.store.tenant_by_name(&m.name).await.unwrap().unwrap();
    load(&fx, &m, NOW).await.unwrap();
    edit(&fx, &m, 1, &m.edited_config()).await;
    let t = NOW + REVALIDATE_MS;
    let v2 = load(&fx, &m, t).await.unwrap();
    assert!(v2.state.config.keys.contains_key("second"));
    fx.store.tamper(&m.name, |r| *r = v1.clone());
    let after = load(&fx, &m, t + REVALIDATE_MS).await.unwrap();
    assert!(after.state.config.keys.contains_key("second"));
    assert!(std::rc::Rc::ptr_eq(&v2.state, &after.state));
}

async fn load_name(fx: &Fx, name: &TenantName, now: u64) -> Result<tenants::Loaded, LoadError> {
    tenants::load(
        &fx.store,
        &fx.unwrap,
        name,
        "https://x.edge.km".into(),
        CLIENT,
        now,
    )
    .await
}

#[wasm_bindgen_test]
async fn unknown_names_past_max_unknown_drop_the_soonest_expiring() {
    let fx = fx().await;
    // Far past every other test's clock, so their negative entries have all expired.
    let base = NOW + 1_000_000_000;
    let prefix = format!("flood-{}", next());
    let names: Vec<TenantName> = (0..=tenants::MAX_UNKNOWN)
        .map(|i| TenantName::new(&format!("{prefix}-{i}")).unwrap())
        .collect();
    for (i, name) in names.iter().enumerate() {
        let at = base + u64::try_from(i).unwrap();
        assert_eq!(
            load_name(&fx, name, at).await.err(),
            Some(LoadError::Unknown)
        );
    }
    let now = base + u64::try_from(names.len()).unwrap();
    let calls = fx.store.calls();
    assert_eq!(
        load_name(&fx, &names[1], now).await.err(),
        Some(LoadError::Unknown)
    );
    assert_eq!(
        load_name(&fx, &names[names.len() - 1], now).await.err(),
        Some(LoadError::Unknown)
    );
    assert_eq!(fx.store.calls(), calls, "the newer names are still cached");
    assert_eq!(
        load_name(&fx, &names[0], now).await.err(),
        Some(LoadError::Unknown)
    );
    assert_eq!(fx.store.calls(), calls + 1, "the oldest was dropped");
}

/// A [`MemStore`] whose first `tenant_by_name` reads the row at once but returns it only when
/// the gate opens, so a test can finish a second load in between.
struct Gated<'a> {
    inner: &'a MemStore,
    captured: Cell<bool>,
    open: Rc<Cell<bool>>,
    waker: Rc<RefCell<Option<Waker>>>,
}

struct Wait {
    open: Rc<Cell<bool>>,
    waker: Rc<RefCell<Option<Waker>>>,
}

impl Future for Wait {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.open.get() {
            Poll::Ready(())
        } else {
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Gated<'_> {
    fn open(&self) {
        self.open.set(true);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }
}

#[allow(clippy::many_single_char_names)]
impl TenantStore for Gated<'_> {
    async fn tenant_version(
        &self,
        name: &str,
    ) -> Result<Option<edgekms_worker::store::TenantVersion>, StoreError> {
        self.inner.tenant_version(name).await
    }
    async fn tenant_by_name(&self, name: &str) -> Result<Option<TenantRow>, StoreError> {
        let row = self.inner.tenant_by_name(name).await;
        if !self.captured.replace(true) {
            Wait {
                open: self.open.clone(),
                waker: self.waker.clone(),
            }
            .await;
        }
        row
    }
    async fn create_tenant(
        &self,
        r: &TenantRow,
        o: u64,
        n: u64,
        m: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.create_tenant(r, o, n, m).await
    }
    async fn create_tenant_capped(
        &self,
        r: &TenantRow,
        o: u64,
        n: u64,
        m: &[u8],
        c: u64,
    ) -> Result<(), StoreError> {
        self.inner.create_tenant_capped(r, o, n, m, c).await
    }
    async fn tokens_after(&self, g: u64) -> Result<Option<u64>, StoreError> {
        self.inner.tokens_after(g).await
    }
    async fn set_tokens_after(&self, g: u64, m: u64) -> Result<(), StoreError> {
        self.inner.set_tokens_after(g, m).await
    }
    async fn invite(&self, t: &str, r: &InviteRow) -> Result<(), StoreError> {
        self.inner.invite(t, r).await
    }
    async fn invites(&self, t: &str) -> Result<Vec<InviteRow>, StoreError> {
        self.inner.invites(t).await
    }
    async fn invites_for_user(&self, g: u64) -> Result<Vec<UserRow<InviteRow>>, StoreError> {
        self.inner.invites_for_user(g).await
    }
    async fn accept_invite(
        &self,
        t: &str,
        i: &[u8],
        c: Option<&[u8]>,
        m: &MemberRow,
    ) -> Result<(), StoreError> {
        self.inner.accept_invite(t, i, c, m).await
    }
    async fn delete_invite(&self, t: &str, g: u64, m: &[u8]) -> Result<(), StoreError> {
        self.inner.delete_invite(t, g, m).await
    }
    async fn rows_wrapped_after(
        &self,
        w: &str,
        a: &str,
        l: u32,
    ) -> Result<Vec<edgekms_worker::store::WrappedRoot>, StoreError> {
        self.inner.rows_wrapped_after(w, a, l).await
    }
    async fn update_config(
        &self,
        i: &str,
        e: u64,
        c: &str,
        m: &[u8],
        n: u64,
    ) -> Result<u64, StoreError> {
        self.inner.update_config(i, e, c, m, n).await
    }
    async fn upsert_user(&self, g: u64, l: &str, n: u64) -> Result<(), StoreError> {
        self.inner.upsert_user(g, l, n).await
    }
    async fn tenants_for_user(&self, g: u64) -> Result<Vec<UserRow<MemberRow>>, StoreError> {
        self.inner.tenants_for_user(g).await
    }
    async fn count_created(&self, g: u64) -> Result<u64, StoreError> {
        self.inner.count_created(g).await
    }
    async fn members(&self, t: &str) -> Result<Vec<MemberRow>, StoreError> {
        self.inner.members(t).await
    }
    async fn member(&self, t: &str, g: u64) -> Result<Option<MemberRow>, StoreError> {
        self.inner.member(t, g).await
    }
    async fn set_member(
        &self,
        t: &str,
        r: &MemberRow,
        c: Option<&[u8]>,
        w: Option<Witness<'_>>,
        a: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        self.inner.set_member(t, r, c, w, a).await
    }
    async fn remove_member(
        &self,
        t: &str,
        g: u64,
        m: &[u8],
        w: Option<Witness<'_>>,
        a: Option<Witness<'_>>,
    ) -> Result<(), StoreError> {
        self.inner.remove_member(t, g, m, w, a).await
    }
    async fn rows_wrapped_with(
        &self,
        w: &str,
        l: u32,
    ) -> Result<Vec<edgekms_worker::store::WrappedRoot>, StoreError> {
        self.inner.rows_wrapped_with(w, l).await
    }
    async fn set_wrapped(&self, i: &str, o: &str, w: &[u8], k: &str) -> Result<(), StoreError> {
        self.inner.set_wrapped(i, o, w, k).await
    }
    async fn set_status(&self, i: &str, s: TenantStatus) -> Result<(), StoreError> {
        self.inner.set_status(i, s).await
    }
    async fn holds_tenants(&self) -> Result<bool, StoreError> {
        self.inner.holds_tenants().await
    }
    async fn allow_signup(&self, r: &AllowRow) -> Result<(), StoreError> {
        self.inner.allow_signup(r).await
    }
    async fn allowed_signup(&self, g: u64) -> Result<Option<AllowRow>, StoreError> {
        self.inner.allowed_signup(g).await
    }
    async fn allowlist(&self) -> Result<Vec<AllowRow>, StoreError> {
        self.inner.allowlist().await
    }
    async fn disallow_signup(&self, g: u64) -> Result<(), StoreError> {
        self.inner.disallow_signup(g).await
    }
    async fn invite_request(&self, g: u64) -> Result<Option<InviteRequestRow>, StoreError> {
        self.inner.invite_request(g).await
    }
    async fn insert_invite_request(&self, r: &InviteRequestRow, m: u64) -> Result<(), StoreError> {
        self.inner.insert_invite_request(r, m).await
    }
    async fn replace_invite_request(
        &self,
        r: &InviteRequestRow,
        o: &[u8],
        m: u64,
    ) -> Result<(), StoreError> {
        self.inner.replace_invite_request(r, o, m).await
    }
    async fn invite_requests(&self, l: u32) -> Result<Vec<InviteRequestRow>, StoreError> {
        self.inner.invite_requests(l).await
    }
    async fn decide_invite_request(
        &self,
        g: u64,
        e: &[u8],
        s: RequestStatus,
        b: u64,
        m: u64,
        a: Option<&AllowRow>,
    ) -> Result<(), StoreError> {
        self.inner.decide_invite_request(g, e, s, b, m, a).await
    }
    async fn delete_invite_request(&self, g: u64) -> Result<(), StoreError> {
        self.inner.delete_invite_request(g).await
    }
    async fn system_key(&self, n: &str) -> Result<Option<SystemKeyRow>, StoreError> {
        self.inner.system_key(n).await
    }
    async fn insert_system_key_if_absent(
        &self,
        r: &SystemKeyRow,
    ) -> Result<SystemKeyRow, StoreError> {
        self.inner.insert_system_key_if_absent(r).await
    }
    async fn set_system_wrapped(
        &self,
        n: &str,
        o: &str,
        w: &[u8],
        k: &str,
    ) -> Result<(), StoreError> {
        self.inner.set_system_wrapped(n, o, w, k).await
    }
    async fn ssh_key(&self, f: &str) -> Result<Option<SshKeyLookup>, StoreError> {
        self.inner.ssh_key(f).await
    }
    async fn ssh_keys_for_user(&self, g: u64) -> Result<Vec<SshKeyRow>, StoreError> {
        self.inner.ssh_keys_for_user(g).await
    }
    async fn insert_ssh_key(&self, r: &SshKeyRow, m: u64) -> Result<(), StoreError> {
        self.inner.insert_ssh_key(r, m).await
    }
    async fn delete_ssh_key(&self, g: u64, f: &str) -> Result<(), StoreError> {
        self.inner.delete_ssh_key(g, f).await
    }
    async fn revoke_user_ssh_keys(&self, g: u64, n: u64) -> Result<u64, StoreError> {
        self.inner.revoke_user_ssh_keys(g, n).await
    }
    async fn consume_challenge(&self, t: &[u8], e: u64, n: u64) -> Result<(), StoreError> {
        self.inner.consume_challenge(t, e, n).await
    }
    async fn ssh_login_used(&self, g: u64, f: &str, n: u64) -> Result<(), StoreError> {
        self.inner.ssh_login_used(g, f, n).await
    }
    async fn token_state(
        &self,
        g: u64,
        f: Option<&str>,
    ) -> Result<Option<(u64, Option<SshKeyRow>)>, StoreError> {
        self.inner.token_state(g, f).await
    }
}

/// Load A reads version 2, then stalls; meanwhile version 3 lands and load B caches it. When A
/// finishes it must not replace B's newer entry with its older row.
#[wasm_bindgen_test]
async fn concurrent_loads_finishing_out_of_order_keep_the_newer_entry() {
    let fx = fx().await;
    let m = make(&fx, "race", None).await;
    load(&fx, &m, NOW).await.unwrap();
    edit(&fx, &m, 1, &m.edited_config()).await;

    let gated = Gated {
        inner: &fx.store,
        captured: Cell::new(false),
        open: Rc::new(Cell::new(false)),
        waker: Rc::new(RefCell::new(None)),
    };
    let t = NOW + REVALIDATE_MS;
    let mut v3: serde_json::Value = serde_json::from_str(&m.edited_config()).unwrap();
    v3["keys"]["third"] =
        serde_json::json!({"id": "k_third", "latest_version": 1, "min_decryption_version": 1});
    let v3 = v3.to_string();

    let a = load_from(&gated, &fx, &m, t);
    let b = async {
        assert!(gated.captured.get(), "load A has read version 2");
        edit(&fx, &m, 2, &v3).await;
        let b = load_from(&gated, &fx, &m, t).await.unwrap();
        gated.open();
        b
    };
    let (a, b) = futures_util::future::join(a, b).await;
    assert!(b.state.config.keys.contains_key("third"));
    // A hands back the newer entry it found, not its own older build...
    assert!(a.unwrap().state.config.keys.contains_key("third"));
    // ...and the cache still holds version 3.
    let cached = load(&fx, &m, t + 1).await.unwrap();
    assert!(cached.state.config.keys.contains_key("third"));
}
