use serde::de::IntoDeserializer;
use serde_path_to_error::{Path, Segment};
use toml::Value;

use crate::{ConfigV1, Diagnostic, DiagnosticCode, SourcePath, VersionedConfig};

pub const SCHEMA_VERSION_V1: u32 = 1;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_INTERFACES: usize = 256;
pub const MAX_ADDRESSES: usize = 1024;
pub const MAX_ROUTES: usize = 4096;
pub const MAX_NEIGHBORS: usize = 4096;
pub const MAX_FIREWALL_RULES: usize = 4096;

const FORBIDDEN_FIELDS: &[&str] = &[
    "config-generation",
    "egress-control-owner",
    "firewall-hash-key",
    "generation",
    "hash",
    "hash-key",
    "owner-steering-key",
    "ownership",
    "ownership-generation",
    "queue",
    "queue-id",
    "queues",
    "shard",
    "shard-id",
    "shards",
    "steering-key",
    "umem",
    "worker-count",
    "workers",
];

const SAFE_PATH_FIELDS: &[&str] = &[
    "action",
    "actions",
    "address",
    "addresses",
    "allocator-seed",
    "capacity",
    "default-ttl",
    "destination",
    "destination-ports",
    "device",
    "dynamic-neighbor-ttl-ms",
    "dynamic-neighbors",
    "egress",
    "failure-holds",
    "firewall",
    "first",
    "failure-dispatch-scans",
    "generated-arp",
    "generated-icmpv4",
    "icmpv4-errors",
    "id",
    "idle-ttl-ms",
    "ingress",
    "inside",
    "interface",
    "interfaces",
    "interval-ms",
    "ipv4",
    "ipv4-origin",
    "last",
    "mac",
    "mappings",
    "max-attempts",
    "name",
    "nat44",
    "neighbors",
    "outside",
    "peers",
    "policy",
    "ports",
    "prefix",
    "protocol",
    "public-address",
    "realm",
    "resolution",
    "resolution-timer-scans",
    "routes",
    "rules",
    "rx",
    "schema-version",
    "sessions",
    "source",
    "source-ports",
    "state-ttl-ms",
    "states",
    "tcp",
    "tcp-active-idle-ttl-ms",
    "tcp-opening-idle-ttl-ms",
    "tick",
    "udp",
    "udp-idle-ttl-ms",
    "via",
];

/// Parses bounded UTF-8 TOML using schema-version predispatch and exact V1 DTOs.
pub fn parse(input: &[u8]) -> Result<VersionedConfig, Diagnostic> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(Diagnostic::bounded(
            DiagnosticCode::InputTooLarge,
            SourcePath::default(),
            MAX_CONFIG_BYTES,
            input.len(),
        ));
    }

    let source = std::str::from_utf8(input)
        .map_err(|_| Diagnostic::new(DiagnosticCode::InvalidUtf8, SourcePath::default()))?;
    let value = toml::from_str::<Value>(source).map_err(syntax_diagnostic)?;
    let table = value
        .as_table()
        .ok_or_else(|| Diagnostic::new(DiagnosticCode::InvalidType, SourcePath::default()))?;
    let version_path = SourcePath::root_field("schema-version");
    let version = table.get("schema-version").ok_or_else(|| {
        Diagnostic::new(DiagnosticCode::MissingSchemaVersion, version_path.clone())
    })?;
    let version = version.as_integer().ok_or_else(|| {
        Diagnostic::new(DiagnosticCode::InvalidSchemaVersion, version_path.clone())
    })?;
    if version != i64::from(SCHEMA_VERSION_V1) {
        return Err(Diagnostic::new(
            DiagnosticCode::UnsupportedSchemaVersion,
            version_path,
        ));
    }

    reject_forbidden_fields(&value, &mut SourcePath::default())?;
    let config = deserialize_exact(value)?;
    enforce_list_bounds(&config)?;
    Ok(VersionedConfig::V1(config))
}

fn syntax_diagnostic(error: toml::de::Error) -> Diagnostic {
    let message = error.message();
    let code = if message.contains("duplicate key") || message.contains("duplicate field") {
        DiagnosticCode::DuplicateField
    } else {
        DiagnosticCode::InvalidToml
    };
    Diagnostic::new(code, SourcePath::default())
}

fn deserialize_exact(value: Value) -> Result<ConfigV1, Diagnostic> {
    let deserializer = value.into_deserializer();
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let code = classify_decode_error(error.inner());
        Diagnostic::new(code, convert_path(error.path()))
    })
}

fn classify_decode_error(error: &toml::de::Error) -> DiagnosticCode {
    let message = error.message();
    if message.contains("unknown field") {
        DiagnosticCode::UnknownField
    } else if message.contains("duplicate field") {
        DiagnosticCode::DuplicateField
    } else if message.contains("missing field") {
        DiagnosticCode::MissingField
    } else {
        DiagnosticCode::InvalidType
    }
}

fn convert_path(path: &Path) -> SourcePath {
    let mut converted = SourcePath::default();
    for segment in path {
        match segment {
            Segment::Seq { index } => converted.push_index(*index),
            Segment::Map { key } if SAFE_PATH_FIELDS.contains(&key.as_str()) => {
                converted.push_field(key.clone());
            }
            Segment::Map { .. } | Segment::Enum { .. } | Segment::Unknown => {}
        }
    }
    converted
}

fn reject_forbidden_fields(value: &Value, path: &mut SourcePath) -> Result<(), Diagnostic> {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push_index(index);
                reject_forbidden_fields(value, path)?;
                path.pop();
            }
        }
        Value::Table(table) => {
            for (field, value) in table {
                let normalized = field.to_ascii_lowercase().replace('_', "-");
                if FORBIDDEN_FIELDS.contains(&normalized.as_str()) {
                    path.push_field(normalized);
                    return Err(Diagnostic::new(
                        DiagnosticCode::ForbiddenField,
                        path.clone(),
                    ));
                }
                if SAFE_PATH_FIELDS.contains(&normalized.as_str()) {
                    path.push_field(normalized);
                    reject_forbidden_fields(value, path)?;
                    path.pop();
                } else {
                    reject_forbidden_fields(value, path)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn enforce_list_bounds(config: &ConfigV1) -> Result<(), Diagnostic> {
    check_list("interfaces", config.interfaces.len(), MAX_INTERFACES)?;
    check_list("addresses", config.addresses.len(), MAX_ADDRESSES)?;
    check_list("routes", config.routes.len(), MAX_ROUTES)?;
    check_list("neighbors", config.neighbors.len(), MAX_NEIGHBORS)?;
    if let Some(firewall) = &config.firewall {
        let mut path = SourcePath::root_field("firewall");
        path.push_field("rules");
        check_list_path(path, firewall.rules.len(), MAX_FIREWALL_RULES)?;
    }
    Ok(())
}

fn check_list(field: &str, actual: usize, limit: usize) -> Result<(), Diagnostic> {
    check_list_path(SourcePath::root_field(field), actual, limit)
}

fn check_list_path(path: SourcePath, actual: usize, limit: usize) -> Result<(), Diagnostic> {
    if actual > limit {
        Err(Diagnostic::bounded(
            DiagnosticCode::ListTooLong,
            path,
            limit,
            actual,
        ))
    } else {
        Ok(())
    }
}
