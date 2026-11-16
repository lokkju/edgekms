//! Every tenant config fragment in the published docs (each fenced `json` block) is a config the
//! hosted service accepts. Fragments in one file build on each other in order, as the docs
//! present them, merged into a new tenant's default config.

use std::path::{Path, PathBuf};

use edgekms_core::config::Config;
use edgekms_core::hosted::{HostedRules, default_config, validate_hosted};
use edgekms_core::transit::Id;
use serde_json::Value;

const CLIENT_ID: &str = "Iv23liHostedApp";

fn docs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut out = Vec::new();
    for dir in [root.clone(), root.join("guides")] {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "md") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The bodies of the file's fenced `json` blocks.
fn json_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let t = line.trim_start();
        match &mut cur {
            None if t == "```json" => cur = Some(String::new()),
            Some(body) if t == "```" => {
                out.push(std::mem::take(body));
                cur = None;
            }
            Some(body) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    out
}

#[test]
fn published_config_snippets_validate() {
    let root_id = Id::new("r_0123456789abcdef").unwrap();
    let key_id = Id::new("k_fedcba9876543210").unwrap();
    let mut checked = 0;
    for path in docs() {
        let text = std::fs::read_to_string(&path).unwrap();
        let mut config: Value =
            serde_json::from_str(&default_config(&root_id, &key_id, 1_234_567, CLIENT_ID)).unwrap();
        for (i, block) in json_blocks(&text).iter().enumerate() {
            let where_ = format!("{} block {}", path.display(), i + 1);
            let fragment: Value =
                serde_json::from_str(block).unwrap_or_else(|e| panic!("{where_}: {e}"));
            let Value::Object(sections) = fragment else {
                panic!("{where_}: not a JSON object");
            };
            for (section, entries) in sections {
                let Value::Object(entries) = entries else {
                    panic!("{where_}: {section} is not an object");
                };
                let target = config[&section]
                    .as_object_mut()
                    .unwrap_or_else(|| panic!("{where_}: unknown section {section}"));
                target.extend(entries);
            }
            let parsed =
                Config::from_json(&config.to_string()).unwrap_or_else(|e| panic!("{where_}: {e}"));
            validate_hosted(
                &parsed,
                &HostedRules {
                    root_id: &root_id,
                    github_client_id: CLIENT_ID,
                    apex: "edgekms.dev",
                },
            )
            .unwrap_or_else(|e| panic!("{where_}: {e}"));
            checked += 1;
        }
    }
    assert!(checked >= 10, "only {checked} config blocks found");
}
