use toml::Value;

/// A single change detected between running and candidate configs.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigChange {
    /// Dotted path to the changed key, e.g. `meta.hostname` or `interfaces[0].mtu`.
    pub path: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeKind {
    Added { new: String },
    Removed { old: String },
    Modified { old: String, new: String },
}

impl std::fmt::Display for ConfigChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ChangeKind::Added { new } => write!(f, "+ {}: {new}", self.path),
            ChangeKind::Removed { old } => write!(f, "- {}: {old}", self.path),
            ChangeKind::Modified { old, new } => {
                write!(f, "~ {}: {old} -> {new}", self.path)
            }
        }
    }
}

/// Compare two `RouterConfig`s via their TOML `Value` representations.
///
/// Returns a list of changes (added / removed / modified leaf values).
pub fn diff_configs(
    running: &ruster_config::RouterConfig,
    candidate: &ruster_config::RouterConfig,
) -> Vec<ConfigChange> {
    let old = toml::Value::try_from(running).expect("running config should serialise");
    let new = toml::Value::try_from(candidate).expect("candidate config should serialise");
    let mut changes = Vec::new();
    diff_value("", &old, &new, &mut changes);
    changes
}

fn diff_value(prefix: &str, old: &Value, new: &Value, out: &mut Vec<ConfigChange>) {
    match (old, new) {
        (Value::Table(a), Value::Table(b)) => {
            for (k, v_old) in a {
                let path = join_path(prefix, k);
                match b.get(k) {
                    Some(v_new) => diff_value(&path, v_old, v_new, out),
                    None => collect_removed(&path, v_old, out),
                }
            }
            for (k, v_new) in b {
                if !a.contains_key(k) {
                    let path = join_path(prefix, k);
                    collect_added(&path, v_new, out);
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            let max_len = a.len().max(b.len());
            for i in 0..max_len {
                let path = format!("{prefix}[{i}]");
                match (a.get(i), b.get(i)) {
                    (Some(v_old), Some(v_new)) => diff_value(&path, v_old, v_new, out),
                    (Some(v_old), None) => collect_removed(&path, v_old, out),
                    (None, Some(v_new)) => collect_added(&path, v_new, out),
                    (None, None) => unreachable!(),
                }
            }
        }
        _ => {
            if old != new {
                out.push(ConfigChange {
                    path: prefix.to_string(),
                    kind: ChangeKind::Modified {
                        old: value_display(old),
                        new: value_display(new),
                    },
                });
            }
        }
    }
}

fn collect_added(prefix: &str, val: &Value, out: &mut Vec<ConfigChange>) {
    match val {
        Value::Table(t) => {
            for (k, v) in t {
                collect_added(&join_path(prefix, k), v, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                collect_added(&format!("{prefix}[{i}]"), v, out);
            }
        }
        _ => {
            out.push(ConfigChange {
                path: prefix.to_string(),
                kind: ChangeKind::Added {
                    new: value_display(val),
                },
            });
        }
    }
}

fn collect_removed(prefix: &str, val: &Value, out: &mut Vec<ConfigChange>) {
    match val {
        Value::Table(t) => {
            for (k, v) in t {
                collect_removed(&join_path(prefix, k), v, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                collect_removed(&format!("{prefix}[{i}]"), v, out);
            }
        }
        _ => {
            out.push(ConfigChange {
                path: prefix.to_string(),
                kind: ChangeKind::Removed {
                    old: value_display(val),
                },
            });
        }
    }
}

fn join_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{s}\""),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Datetime(d) => d.to_string(),
        Value::Array(a) => format!("[{} items]", a.len()),
        Value::Table(_) => "{...}".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(s: &str) -> ruster_config::RouterConfig {
        toml::from_str(s).expect("test config should parse")
    }

    fn example_toml() -> String {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("router.toml.example");
        std::fs::read_to_string(&path).expect("example toml")
    }

    #[test]
    fn identical_configs_produce_no_changes() {
        let cfg = load(&example_toml());
        let changes = diff_configs(&cfg, &cfg);
        assert!(changes.is_empty());
    }

    #[test]
    fn hostname_change_detected() {
        let cfg1 = load(&example_toml());
        let mut cfg2 = cfg1.clone();
        cfg2.meta.hostname = "new-host".to_string();
        let changes = diff_configs(&cfg1, &cfg2);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "meta.hostname");
        assert!(matches!(&changes[0].kind, ChangeKind::Modified { .. }));
    }

    #[test]
    fn mtu_change_detected() {
        let cfg1 = load(&example_toml());
        let mut cfg2 = cfg1.clone();
        cfg2.interfaces[0].mtu = 9000;
        let changes = diff_configs(&cfg1, &cfg2);
        assert!(changes.iter().any(|c| c.path.contains("mtu")));
    }
}
