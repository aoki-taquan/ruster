//! BGP message parsing and serialization.
//!
//! Implements the four BGP message types defined in RFC 4271:
//! - OPEN: Session establishment with capabilities negotiation
//! - UPDATE: Route advertisement and withdrawal
//! - NOTIFICATION: Error reporting
//! - KEEPALIVE: Liveliness check
//!
//! RFC-REF: RFC 4271 Section 4
//! "This section describes message formats used by BGP."
//!
//! # Wire Format
//!
//! Every BGP message starts with a 19-byte header:
//! - 16 bytes: Marker (all 0xFF)
//! - 2 bytes: Length (total message length including header)
//! - 1 byte: Type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE)

use super::path::{AsPath, Origin, PathAttributes};

// ── Constants ────────────────────────────────────────────────────────

/// BGP marker: 16 bytes of 0xFF.
///
/// RFC-REF: RFC 4271 Section 4.1
/// "This 16-octet field is included for compatibility; it MUST be set
/// to all ones."
pub const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// BGP header length in bytes.
pub const BGP_HEADER_LEN: usize = 19;

/// Minimum BGP message length (header only, for KEEPALIVE).
///
/// RFC-REF: RFC 4271 Section 4.1
/// "The minimum value of the Length field is 19."
pub const BGP_MIN_MSG_LEN: usize = 19;

/// Maximum BGP message length.
///
/// RFC-REF: RFC 4271 Section 4.1
/// "The value of the Length field MUST always be at least 19 and no
/// greater than 4096."
pub const BGP_MAX_MSG_LEN: usize = 4096;

/// BGP version 4.
pub const BGP_VERSION: u8 = 4;

// ── Message type codes ───────────────────────────────────────────────

/// RFC-REF: RFC 4271 Section 4.1
/// "Type field: 1 - OPEN, 2 - UPDATE, 3 - NOTIFICATION, 4 - KEEPALIVE"
pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

// ── NOTIFICATION error codes ─────────────────────────────────────────

/// RFC-REF: RFC 4271 Section 4.5
/// "Error codes and sub-codes for NOTIFICATION messages."
#[allow(dead_code)]
pub const ERR_MSG_HEADER: u8 = 1;
pub const ERR_OPEN_MSG: u8 = 2;
#[allow(dead_code)]
pub const ERR_UPDATE_MSG: u8 = 3;
pub const ERR_HOLD_TIMER_EXPIRED: u8 = 4;
pub const ERR_FSM: u8 = 5;
pub const ERR_CEASE: u8 = 6;

// OPEN sub-codes
pub const OPEN_SUB_UNSUPPORTED_VERSION: u8 = 1;
pub const OPEN_SUB_BAD_PEER_AS: u8 = 2;
#[allow(dead_code)]
pub const OPEN_SUB_BAD_BGP_ID: u8 = 3;

// ── Path attribute type codes ────────────────────────────────────────

/// RFC-REF: RFC 4271 Section 5
/// "Path attribute type codes."
pub const ATTR_ORIGIN: u8 = 1;
pub const ATTR_AS_PATH: u8 = 2;
pub const ATTR_NEXT_HOP: u8 = 3;
pub const ATTR_MULTI_EXIT_DISC: u8 = 4;
pub const ATTR_LOCAL_PREF: u8 = 5;

// Path attribute flags
pub const ATTR_FLAG_OPTIONAL: u8 = 0x80;
pub const ATTR_FLAG_TRANSITIVE: u8 = 0x40;
pub const ATTR_FLAG_EXTENDED_LEN: u8 = 0x10;

// AS_PATH segment types
pub const AS_SET: u8 = 1;
pub const AS_SEQUENCE: u8 = 2;

// ── Message types ────────────────────────────────────────────────────

/// A parsed BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    Keepalive,
}

/// BGP OPEN message.
///
/// RFC-REF: RFC 4271 Section 4.2
/// "After a TCP connection is established, the first message sent by
/// each side is an OPEN message."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    /// BGP version (must be 4).
    pub version: u8,
    /// Sender's autonomous system number.
    pub my_as: u16,
    /// Hold time in seconds (0 or >= 3).
    pub hold_time: u16,
    /// BGP identifier (router ID) as 4-byte value.
    pub bgp_id: [u8; 4],
    /// Optional parameters (capabilities, etc.).
    /// RFC-DEVIATION:
    /// reason: v0.2 minimal implementation — only 4-byte AS capability parsed
    /// impact: cannot negotiate MP-BGP or other capabilities
    /// issue: #158
    /// plan: add full capability negotiation in v0.3
    pub capabilities: Vec<BgpCapability>,
}

/// BGP capability (subset for minimal implementation).
///
/// RFC-DEVIATION:
/// reason: v0.2 minimal — only IPv4 unicast and 4-byte AS supported
/// impact: cannot negotiate MP-BGP for IPv6 or other AFI/SAFI
/// issue: #158
/// plan: add full capability set in v0.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpCapability {
    /// 4-byte AS number capability (RFC 6793).
    FourOctetAs(u32),
    /// Unknown/unsupported capability (code, data).
    Unknown(u8, Vec<u8>),
}

/// BGP UPDATE message.
///
/// RFC-REF: RFC 4271 Section 4.3
/// "UPDATE messages are used to transfer routing information between
/// BGP peers."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    /// Withdrawn routes: list of (prefix, prefix_len) pairs.
    pub withdrawn_routes: Vec<([u8; 4], u8)>,
    /// Path attributes for the advertised routes.
    pub path_attributes: PathAttributes,
    /// Network Layer Reachability Information (NLRI): list of
    /// (prefix, prefix_len) pairs being advertised.
    pub nlri: Vec<([u8; 4], u8)>,
}

/// BGP NOTIFICATION message.
///
/// RFC-REF: RFC 4271 Section 4.5
/// "A NOTIFICATION message is sent when an error condition is detected."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    /// Error code.
    pub error_code: u8,
    /// Error sub-code.
    pub error_subcode: u8,
    /// Additional error data.
    pub data: Vec<u8>,
}

// ── Parse error ──────────────────────────────────────────────────────

/// Errors that can occur when parsing a BGP message from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Message is too short to contain a valid header.
    TooShort,
    /// Marker field is not all 0xFF.
    InvalidMarker,
    /// Length field exceeds maximum or is less than minimum.
    InvalidLength(u16),
    /// Unknown message type code.
    UnknownType(u8),
    /// OPEN message body is malformed.
    MalformedOpen(String),
    /// UPDATE message body is malformed.
    MalformedUpdate(String),
    /// NOTIFICATION message body is malformed.
    MalformedNotification,
    /// Buffer underrun during parsing.
    Truncated,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message too short"),
            Self::InvalidMarker => write!(f, "invalid BGP marker"),
            Self::InvalidLength(l) => write!(f, "invalid length: {l}"),
            Self::UnknownType(t) => write!(f, "unknown message type: {t}"),
            Self::MalformedOpen(s) => write!(f, "malformed OPEN: {s}"),
            Self::MalformedUpdate(s) => write!(f, "malformed UPDATE: {s}"),
            Self::MalformedNotification => write!(f, "malformed NOTIFICATION"),
            Self::Truncated => write!(f, "truncated message"),
        }
    }
}

impl std::error::Error for ParseError {}

// ── Parsing ──────────────────────────────────────────────────────────

impl BgpMessage {
    /// Parse a BGP message from a byte buffer.
    ///
    /// The buffer must contain exactly one complete BGP message
    /// (header + body).  Returns the parsed message and the number
    /// of bytes consumed.
    ///
    /// RFC-REF: RFC 4271 Section 4.1
    /// "Each message has a fixed-size header."
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < BGP_HEADER_LEN {
            return Err(ParseError::TooShort);
        }

        // Validate marker.
        if buf[0..16] != BGP_MARKER {
            return Err(ParseError::InvalidMarker);
        }

        let length = u16::from_be_bytes([buf[16], buf[17]]) as usize;
        if length < BGP_MIN_MSG_LEN || length > BGP_MAX_MSG_LEN {
            return Err(ParseError::InvalidLength(length as u16));
        }
        if buf.len() < length {
            return Err(ParseError::Truncated);
        }

        let msg_type = buf[18];
        let body = &buf[BGP_HEADER_LEN..length];

        let msg = match msg_type {
            MSG_OPEN => Self::parse_open(body)?,
            MSG_UPDATE => Self::parse_update(body)?,
            MSG_NOTIFICATION => Self::parse_notification(body)?,
            MSG_KEEPALIVE => {
                // RFC-REF: RFC 4271 Section 4.4
                // "A KEEPALIVE message consists of only the message header
                // and has a length of 19 octets."
                BgpMessage::Keepalive
            }
            _ => return Err(ParseError::UnknownType(msg_type)),
        };

        Ok((msg, length))
    }

    /// Parse an OPEN message body.
    fn parse_open(body: &[u8]) -> Result<Self, ParseError> {
        // Minimum OPEN body: version(1) + AS(2) + hold(2) + id(4) + opt_len(1) = 10
        if body.len() < 10 {
            return Err(ParseError::MalformedOpen("body too short".into()));
        }

        let version = body[0];
        let my_as = u16::from_be_bytes([body[1], body[2]]);
        let hold_time = u16::from_be_bytes([body[3], body[4]]);
        let bgp_id = [body[5], body[6], body[7], body[8]];
        let opt_params_len = body[9] as usize;

        if body.len() < 10 + opt_params_len {
            return Err(ParseError::MalformedOpen(
                "optional parameters truncated".into(),
            ));
        }

        let capabilities = parse_capabilities(&body[10..10 + opt_params_len]);

        Ok(BgpMessage::Open(OpenMessage {
            version,
            my_as,
            hold_time,
            bgp_id,
            capabilities,
        }))
    }

    /// Parse an UPDATE message body.
    ///
    /// RFC-REF: RFC 4271 Section 4.3
    fn parse_update(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 2 {
            return Err(ParseError::MalformedUpdate(
                "withdrawn length missing".into(),
            ));
        }

        let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let mut pos = 2;

        if body.len() < pos + withdrawn_len {
            return Err(ParseError::MalformedUpdate(
                "withdrawn routes truncated".into(),
            ));
        }

        let withdrawn_routes = parse_nlri(&body[pos..pos + withdrawn_len])?;
        pos += withdrawn_len;

        if body.len() < pos + 2 {
            return Err(ParseError::MalformedUpdate(
                "path attributes length missing".into(),
            ));
        }

        let path_attrs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;

        if body.len() < pos + path_attrs_len {
            return Err(ParseError::MalformedUpdate(
                "path attributes truncated".into(),
            ));
        }

        let path_attributes = parse_path_attributes(&body[pos..pos + path_attrs_len])?;
        pos += path_attrs_len;

        // Remaining bytes are NLRI.
        let nlri = parse_nlri(&body[pos..])?;

        Ok(BgpMessage::Update(UpdateMessage {
            withdrawn_routes,
            path_attributes,
            nlri,
        }))
    }

    /// Parse a NOTIFICATION message body.
    fn parse_notification(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 2 {
            return Err(ParseError::MalformedNotification);
        }

        Ok(BgpMessage::Notification(NotificationMessage {
            error_code: body[0],
            error_subcode: body[1],
            data: body[2..].to_vec(),
        }))
    }
}

// ── Serialization ────────────────────────────────────────────────────

impl BgpMessage {
    /// Serialize this BGP message to bytes (header + body).
    pub fn serialize(&self) -> Vec<u8> {
        let body = match self {
            Self::Open(open) => serialize_open(open),
            Self::Update(update) => serialize_update(update),
            Self::Notification(notif) => serialize_notification(notif),
            Self::Keepalive => Vec::new(),
        };

        let msg_type = match self {
            Self::Open(_) => MSG_OPEN,
            Self::Update(_) => MSG_UPDATE,
            Self::Notification(_) => MSG_NOTIFICATION,
            Self::Keepalive => MSG_KEEPALIVE,
        };

        let total_len = (BGP_HEADER_LEN + body.len()) as u16;
        let mut buf = Vec::with_capacity(total_len as usize);

        // Header: marker + length + type.
        buf.extend_from_slice(&BGP_MARKER);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(&body);

        buf
    }
}

fn serialize_open(open: &OpenMessage) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(open.version);
    body.extend_from_slice(&open.my_as.to_be_bytes());
    body.extend_from_slice(&open.hold_time.to_be_bytes());
    body.extend_from_slice(&open.bgp_id);

    // Optional parameters (capabilities).
    let opt_params = serialize_capabilities(&open.capabilities);
    body.push(opt_params.len() as u8);
    body.extend_from_slice(&opt_params);

    body
}

fn serialize_capabilities(caps: &[BgpCapability]) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        let (code, data) = match cap {
            BgpCapability::FourOctetAs(asn) => (65u8, asn.to_be_bytes().to_vec()),
            BgpCapability::Unknown(code, data) => (*code, data.clone()),
        };
        // Capability TLV inside optional parameter type 2 (Capabilities).
        // Optional parameter: type(1) + length(1) + cap_code(1) + cap_len(1) + cap_data
        let cap_len = data.len();
        let param_len = 2 + cap_len; // cap_code + cap_len + data
        buf.push(2); // Optional parameter type: Capability
        buf.push(param_len as u8);
        buf.push(code);
        buf.push(cap_len as u8);
        buf.extend_from_slice(&data);
    }
    buf
}

fn serialize_update(update: &UpdateMessage) -> Vec<u8> {
    let mut body = Vec::new();

    // Withdrawn routes length + data.
    let withdrawn = serialize_nlri(&update.withdrawn_routes);
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(&withdrawn);

    // Path attributes length + data.
    let attrs = serialize_path_attributes(&update.path_attributes);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);

    // NLRI.
    let nlri = serialize_nlri(&update.nlri);
    body.extend_from_slice(&nlri);

    body
}

fn serialize_notification(notif: &NotificationMessage) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + notif.data.len());
    body.push(notif.error_code);
    body.push(notif.error_subcode);
    body.extend_from_slice(&notif.data);
    body
}

// ── NLRI parsing/serialization ───────────────────────────────────────

/// Parse NLRI (or withdrawn routes) from a byte slice.
///
/// Each entry is: prefix_len(1 byte) + prefix (variable, ceil(prefix_len/8) bytes).
///
/// RFC-REF: RFC 4271 Section 4.3
/// "Each prefix is encoded as a 2-tuple of the form <length, prefix>."
fn parse_nlri(data: &[u8]) -> Result<Vec<([u8; 4], u8)>, ParseError> {
    let mut routes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let prefix_len = data[pos];
        pos += 1;

        if prefix_len > 32 {
            return Err(ParseError::MalformedUpdate(format!(
                "prefix length {prefix_len} > 32"
            )));
        }

        let prefix_bytes = ((prefix_len + 7) / 8) as usize;
        if pos + prefix_bytes > data.len() {
            return Err(ParseError::MalformedUpdate("NLRI prefix truncated".into()));
        }

        let mut prefix = [0u8; 4];
        for i in 0..prefix_bytes {
            prefix[i] = data[pos + i];
        }
        pos += prefix_bytes;

        routes.push((prefix, prefix_len));
    }

    Ok(routes)
}

/// Serialize NLRI entries to bytes.
fn serialize_nlri(routes: &[([u8; 4], u8)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &(prefix, prefix_len) in routes {
        buf.push(prefix_len);
        let prefix_bytes = ((prefix_len + 7) / 8) as usize;
        buf.extend_from_slice(&prefix[..prefix_bytes]);
    }
    buf
}

// ── Path attribute parsing/serialization ─────────────────────────────

/// Parse path attributes from a byte slice.
///
/// RFC-REF: RFC 4271 Section 5
fn parse_path_attributes(data: &[u8]) -> Result<PathAttributes, ParseError> {
    let mut attrs = PathAttributes::default();
    let mut pos = 0;

    while pos < data.len() {
        if pos + 3 > data.len() {
            return Err(ParseError::MalformedUpdate(
                "path attribute header truncated".into(),
            ));
        }

        let flags = data[pos];
        let type_code = data[pos + 1];
        pos += 2;

        let attr_len = if flags & ATTR_FLAG_EXTENDED_LEN != 0 {
            if pos + 2 > data.len() {
                return Err(ParseError::MalformedUpdate(
                    "extended length truncated".into(),
                ));
            }
            let l = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            l
        } else {
            if pos >= data.len() {
                return Err(ParseError::MalformedUpdate(
                    "attribute length truncated".into(),
                ));
            }
            let l = data[pos] as usize;
            pos += 1;
            l
        };

        if pos + attr_len > data.len() {
            return Err(ParseError::MalformedUpdate(
                "attribute value truncated".into(),
            ));
        }

        let value = &data[pos..pos + attr_len];
        pos += attr_len;

        match type_code {
            ATTR_ORIGIN => {
                if value.is_empty() {
                    return Err(ParseError::MalformedUpdate("ORIGIN empty".into()));
                }
                attrs.origin = match value[0] {
                    0 => Origin::Igp,
                    1 => Origin::Egp,
                    2 => Origin::Incomplete,
                    v => {
                        return Err(ParseError::MalformedUpdate(format!(
                            "unknown ORIGIN value: {v}"
                        )))
                    }
                };
            }
            ATTR_AS_PATH => {
                attrs.as_path = parse_as_path(value)?;
            }
            ATTR_NEXT_HOP => {
                if value.len() != 4 {
                    return Err(ParseError::MalformedUpdate(format!(
                        "NEXT_HOP length {}, expected 4",
                        value.len()
                    )));
                }
                attrs.next_hop = [value[0], value[1], value[2], value[3]];
            }
            ATTR_MULTI_EXIT_DISC => {
                if value.len() != 4 {
                    return Err(ParseError::MalformedUpdate(format!(
                        "MED length {}, expected 4",
                        value.len()
                    )));
                }
                attrs.med = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            ATTR_LOCAL_PREF => {
                if value.len() != 4 {
                    return Err(ParseError::MalformedUpdate(format!(
                        "LOCAL_PREF length {}, expected 4",
                        value.len()
                    )));
                }
                attrs.local_pref =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {
                // Skip unknown attributes.
                // RFC-DEVIATION:
                // reason: minimal implementation ignores unknown path attributes
                // impact: may not properly handle all route information
                // issue: #158
                // plan: add handling for additional attributes in v0.3
            }
        }
    }

    Ok(attrs)
}

/// Parse AS_PATH attribute value.
///
/// RFC-REF: RFC 4271 Section 5.1.2
/// "AS_PATH is composed of a sequence of AS path segments."
fn parse_as_path(data: &[u8]) -> Result<AsPath, ParseError> {
    let mut segments = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(ParseError::MalformedUpdate(
                "AS_PATH segment header truncated".into(),
            ));
        }

        let seg_type = data[pos];
        let seg_len = data[pos + 1] as usize;
        pos += 2;

        // Each AS number is 2 bytes (16-bit ASN).
        // RFC-DEVIATION:
        // reason: minimal implementation uses 2-byte ASN encoding only
        // impact: cannot handle 4-byte ASNs in AS_PATH wire format
        // issue: #158
        // plan: add 4-byte ASN support with RFC 6793 in v0.3
        let as_size = 2;
        if pos + seg_len * as_size > data.len() {
            return Err(ParseError::MalformedUpdate(
                "AS_PATH segment data truncated".into(),
            ));
        }

        let mut asns = Vec::with_capacity(seg_len);
        for i in 0..seg_len {
            let asn = u16::from_be_bytes([data[pos + i * as_size], data[pos + i * as_size + 1]]);
            asns.push(asn as u32);
        }
        pos += seg_len * as_size;

        match seg_type {
            AS_SET => segments.push(super::path::AsPathSegment::AsSet(asns)),
            AS_SEQUENCE => segments.push(super::path::AsPathSegment::AsSequence(asns)),
            _ => {
                return Err(ParseError::MalformedUpdate(format!(
                    "unknown AS_PATH segment type: {seg_type}"
                )))
            }
        }
    }

    Ok(AsPath { segments })
}

/// Serialize path attributes to bytes.
fn serialize_path_attributes(attrs: &PathAttributes) -> Vec<u8> {
    let mut buf = Vec::new();

    // ORIGIN: well-known mandatory, transitive.
    // Flags: 0x40 (transitive).
    buf.push(ATTR_FLAG_TRANSITIVE);
    buf.push(ATTR_ORIGIN);
    buf.push(1); // length
    buf.push(match attrs.origin {
        Origin::Igp => 0,
        Origin::Egp => 1,
        Origin::Incomplete => 2,
    });

    // AS_PATH: well-known mandatory, transitive.
    let as_path_data = serialize_as_path(&attrs.as_path);
    buf.push(ATTR_FLAG_TRANSITIVE);
    buf.push(ATTR_AS_PATH);
    buf.push(as_path_data.len() as u8);
    buf.extend_from_slice(&as_path_data);

    // NEXT_HOP: well-known mandatory, transitive.
    buf.push(ATTR_FLAG_TRANSITIVE);
    buf.push(ATTR_NEXT_HOP);
    buf.push(4); // length
    buf.extend_from_slice(&attrs.next_hop);

    // MED: optional, non-transitive.
    if let Some(med) = attrs.med {
        buf.push(ATTR_FLAG_OPTIONAL);
        buf.push(ATTR_MULTI_EXIT_DISC);
        buf.push(4);
        buf.extend_from_slice(&med.to_be_bytes());
    }

    // LOCAL_PREF: well-known, transitive (for iBGP; optional for eBGP).
    if let Some(lp) = attrs.local_pref {
        buf.push(ATTR_FLAG_TRANSITIVE);
        buf.push(ATTR_LOCAL_PREF);
        buf.push(4);
        buf.extend_from_slice(&lp.to_be_bytes());
    }

    buf
}

/// Serialize AS_PATH segments to bytes.
fn serialize_as_path(as_path: &AsPath) -> Vec<u8> {
    let mut buf = Vec::new();
    for segment in &as_path.segments {
        let (seg_type, asns) = match segment {
            super::path::AsPathSegment::AsSet(asns) => (AS_SET, asns),
            super::path::AsPathSegment::AsSequence(asns) => (AS_SEQUENCE, asns),
        };
        buf.push(seg_type);
        buf.push(asns.len() as u8);
        for &asn in asns {
            // Serialize as 2-byte ASN on the wire.
            buf.extend_from_slice(&(asn as u16).to_be_bytes());
        }
    }
    buf
}

/// Parse capabilities from OPEN optional parameters.
fn parse_capabilities(data: &[u8]) -> Vec<BgpCapability> {
    let mut caps = Vec::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let param_type = data[pos];
        let param_len = data[pos + 1] as usize;
        pos += 2;

        if pos + param_len > data.len() {
            break;
        }

        if param_type == 2 {
            // Capability optional parameter.
            let mut cpos = pos;
            while cpos + 2 <= pos + param_len {
                let cap_code = data[cpos];
                let cap_len = data[cpos + 1] as usize;
                cpos += 2;

                if cpos + cap_len > pos + param_len {
                    break;
                }

                let cap_data = &data[cpos..cpos + cap_len];
                cpos += cap_len;

                match cap_code {
                    65 if cap_data.len() == 4 => {
                        let asn = u32::from_be_bytes([
                            cap_data[0],
                            cap_data[1],
                            cap_data[2],
                            cap_data[3],
                        ]);
                        caps.push(BgpCapability::FourOctetAs(asn));
                    }
                    _ => {
                        caps.push(BgpCapability::Unknown(cap_code, cap_data.to_vec()));
                    }
                }
            }
        }

        pos += param_len;
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::path::{AsPath, AsPathSegment, Origin, PathAttributes};

    // ── KEEPALIVE round-trip ─────────────────────────────────────────

    #[test]
    fn keepalive_serialize_parse() {
        let msg = BgpMessage::Keepalive;
        let bytes = msg.serialize();
        assert_eq!(bytes.len(), BGP_HEADER_LEN);
        assert_eq!(bytes[18], MSG_KEEPALIVE);

        let (parsed, consumed) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(consumed, BGP_HEADER_LEN);
        assert_eq!(parsed, BgpMessage::Keepalive);
    }

    // ── OPEN round-trip ──────────────────────────────────────────────

    #[test]
    fn open_serialize_parse() {
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_id: [10, 0, 0, 1],
            capabilities: vec![],
        };
        let msg = BgpMessage::Open(open.clone());
        let bytes = msg.serialize();

        let (parsed, consumed) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, BgpMessage::Open(open));
    }

    #[test]
    fn open_with_4byte_as_capability() {
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 23456, // AS_TRANS for 4-byte AS
            hold_time: 90,
            bgp_id: [10, 0, 0, 1],
            capabilities: vec![BgpCapability::FourOctetAs(65537)],
        };
        let msg = BgpMessage::Open(open.clone());
        let bytes = msg.serialize();

        let (parsed, _) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(parsed, BgpMessage::Open(open));
    }

    // ── UPDATE round-trip ────────────────────────────────────────────

    #[test]
    fn update_advertise_route() {
        let update = UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: PathAttributes {
                origin: Origin::Igp,
                as_path: AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
                },
                next_hop: [10, 0, 0, 2],
                med: Some(100),
                local_pref: Some(200),
            },
            nlri: vec![([192, 168, 1, 0], 24)],
        };
        let msg = BgpMessage::Update(update.clone());
        let bytes = msg.serialize();

        let (parsed, consumed) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match parsed {
            BgpMessage::Update(u) => {
                assert_eq!(u.withdrawn_routes, update.withdrawn_routes);
                assert_eq!(u.nlri, update.nlri);
                assert_eq!(u.path_attributes.origin, Origin::Igp);
                assert_eq!(u.path_attributes.as_path, update.path_attributes.as_path);
                assert_eq!(u.path_attributes.next_hop, [10, 0, 0, 2]);
                assert_eq!(u.path_attributes.med, Some(100));
                assert_eq!(u.path_attributes.local_pref, Some(200));
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn update_withdraw_route() {
        let update = UpdateMessage {
            withdrawn_routes: vec![([10, 0, 0, 0], 8)],
            path_attributes: PathAttributes::default(),
            nlri: vec![],
        };
        let msg = BgpMessage::Update(update.clone());
        let bytes = msg.serialize();

        let (parsed, _) = BgpMessage::parse(&bytes).unwrap();
        match parsed {
            BgpMessage::Update(u) => {
                assert_eq!(u.withdrawn_routes, vec![([10, 0, 0, 0], 8)]);
                assert!(u.nlri.is_empty());
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn update_multiple_nlri() {
        let update = UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: PathAttributes {
                origin: Origin::Egp,
                as_path: AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                },
                next_hop: [10, 0, 0, 2],
                med: None,
                local_pref: None,
            },
            nlri: vec![
                ([192, 168, 1, 0], 24),
                ([10, 0, 0, 0], 8),
                ([0, 0, 0, 0], 0),
            ],
        };
        let msg = BgpMessage::Update(update.clone());
        let bytes = msg.serialize();

        let (parsed, _) = BgpMessage::parse(&bytes).unwrap();
        match parsed {
            BgpMessage::Update(u) => {
                assert_eq!(u.nlri.len(), 3);
                assert_eq!(u.nlri[0], ([192, 168, 1, 0], 24));
                assert_eq!(u.nlri[1], ([10, 0, 0, 0], 8));
                assert_eq!(u.nlri[2], ([0, 0, 0, 0], 0));
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    // ── NOTIFICATION round-trip ──────────────────────────────────────

    #[test]
    fn notification_serialize_parse() {
        let notif = NotificationMessage {
            error_code: ERR_HOLD_TIMER_EXPIRED,
            error_subcode: 0,
            data: vec![],
        };
        let msg = BgpMessage::Notification(notif.clone());
        let bytes = msg.serialize();

        let (parsed, consumed) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, BgpMessage::Notification(notif));
    }

    #[test]
    fn notification_with_data() {
        let notif = NotificationMessage {
            error_code: ERR_OPEN_MSG,
            error_subcode: OPEN_SUB_BAD_PEER_AS,
            data: vec![0x00, 0x01],
        };
        let msg = BgpMessage::Notification(notif.clone());
        let bytes = msg.serialize();

        let (parsed, _) = BgpMessage::parse(&bytes).unwrap();
        assert_eq!(parsed, BgpMessage::Notification(notif));
    }

    // ── Parse error tests ────────────────────────────────────────────

    #[test]
    fn parse_too_short() {
        let err = BgpMessage::parse(&[0xFF; 10]).unwrap_err();
        assert!(matches!(err, ParseError::TooShort));
    }

    #[test]
    fn parse_invalid_marker() {
        let mut buf = vec![0x00; 19];
        buf[16] = 0;
        buf[17] = 19;
        buf[18] = MSG_KEEPALIVE;
        let err = BgpMessage::parse(&buf).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMarker));
    }

    #[test]
    fn parse_invalid_length_too_small() {
        let mut buf = vec![0xFF; 19];
        buf[16] = 0;
        buf[17] = 18; // less than minimum
        buf[18] = MSG_KEEPALIVE;
        let err = BgpMessage::parse(&buf).unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength(18)));
    }

    #[test]
    fn parse_unknown_type() {
        let mut buf = vec![0xFF; 19];
        buf[16] = 0;
        buf[17] = 19;
        buf[18] = 99; // unknown
        let err = BgpMessage::parse(&buf).unwrap_err();
        assert!(matches!(err, ParseError::UnknownType(99)));
    }

    // ── NLRI parsing edge cases ──────────────────────────────────────

    #[test]
    fn nlri_zero_prefix_len() {
        // Default route: prefix_len=0, no prefix bytes.
        let data = [0u8]; // prefix_len = 0
        let routes = parse_nlri(&data).unwrap();
        assert_eq!(routes, vec![([0, 0, 0, 0], 0)]);
    }

    #[test]
    fn nlri_host_route() {
        // /32 host route: prefix_len=32, 4 prefix bytes.
        let data = [32, 10, 0, 0, 1];
        let routes = parse_nlri(&data).unwrap();
        assert_eq!(routes, vec![([10, 0, 0, 1], 32)]);
    }

    #[test]
    fn nlri_invalid_prefix_len() {
        let data = [33]; // > 32
        let err = parse_nlri(&data).unwrap_err();
        assert!(matches!(err, ParseError::MalformedUpdate(_)));
    }
}
