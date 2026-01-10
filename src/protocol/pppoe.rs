//! PPPoE protocol - RFC 2516
//!
//! Point-to-Point Protocol over Ethernet for establishing PPP sessions
//! over Ethernet networks.

use crate::{Error, Result};

/// PPPoE Discovery EtherType
pub const PPPOE_DISCOVERY_ETHERTYPE: u16 = 0x8863;

/// PPPoE Session EtherType
pub const PPPOE_SESSION_ETHERTYPE: u16 = 0x8864;

/// PPPoE header size (ver/type + code + session_id + length)
pub const PPPOE_HEADER_SIZE: usize = 6;

/// PPPoE version (must be 1)
pub const PPPOE_VERSION: u8 = 1;

/// PPPoE type (must be 1)
pub const PPPOE_TYPE: u8 = 1;

/// PPPoE Discovery codes
pub mod codes {
    /// Active Discovery Initiation (broadcast from client)
    pub const PADI: u8 = 0x09;
    /// Active Discovery Offer (unicast from server)
    pub const PADO: u8 = 0x07;
    /// Active Discovery Request (unicast to server)
    pub const PADR: u8 = 0x19;
    /// Active Discovery Session-confirmation (assigns session_id)
    pub const PADS: u8 = 0x65;
    /// Active Discovery Terminate
    pub const PADT: u8 = 0xa7;
    /// Session data (code=0 in session stage)
    pub const SESSION: u8 = 0x00;
}

/// PPPoE tag types used in Discovery packets
pub mod tags {
    /// End of list
    pub const END_OF_LIST: u16 = 0x0000;
    /// Service name (empty = any service)
    pub const SERVICE_NAME: u16 = 0x0101;
    /// Access Concentrator name
    pub const AC_NAME: u16 = 0x0102;
    /// Host unique identifier (used to match responses)
    pub const HOST_UNIQ: u16 = 0x0103;
    /// AC cookie (must be echoed back)
    pub const AC_COOKIE: u16 = 0x0104;
    /// Vendor specific
    pub const VENDOR_SPECIFIC: u16 = 0x0105;
    /// Relay session ID
    pub const RELAY_SESSION_ID: u16 = 0x0110;
    /// Service name error
    pub const SERVICE_NAME_ERROR: u16 = 0x0201;
    /// AC system error
    pub const AC_SYSTEM_ERROR: u16 = 0x0202;
    /// Generic error
    pub const GENERIC_ERROR: u16 = 0x0203;
}

/// Parsed PPPoE frame (zero-copy reference)
#[derive(Debug)]
pub struct PppoeFrame<'a> {
    buffer: &'a [u8],
}

impl<'a> PppoeFrame<'a> {
    /// Parse PPPoE frame from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < PPPOE_HEADER_SIZE {
            return Err(Error::Parse("PPPoE frame too short".into()));
        }

        let frame = Self { buffer };

        // Verify version and type
        if frame.version() != PPPOE_VERSION || frame.frame_type() != PPPOE_TYPE {
            return Err(Error::Parse(format!(
                "Invalid PPPoE version/type: {}/{}",
                frame.version(),
                frame.frame_type()
            )));
        }

        // Verify payload length matches
        let payload_len = frame.length() as usize;
        if buffer.len() < PPPOE_HEADER_SIZE + payload_len {
            return Err(Error::Parse("PPPoE payload truncated".into()));
        }

        Ok(frame)
    }

    /// Version (4 bits, should be 1)
    pub fn version(&self) -> u8 {
        (self.buffer[0] >> 4) & 0x0f
    }

    /// Type (4 bits, should be 1)
    pub fn frame_type(&self) -> u8 {
        self.buffer[0] & 0x0f
    }

    /// Code (PADI, PADO, PADR, PADS, PADT, or 0 for session)
    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    /// Session ID (0 for discovery, assigned by server for session)
    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Payload length
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Payload (tags for discovery, PPP frame for session)
    pub fn payload(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[PPPOE_HEADER_SIZE..PPPOE_HEADER_SIZE + len]
    }

    /// Iterate over tags in discovery payload
    pub fn iter_tags(&self) -> PppoeTagIterator<'_> {
        PppoeTagIterator {
            data: self.payload(),
            offset: 0,
        }
    }

    /// Find a specific tag by type
    pub fn find_tag(&self, tag_type: u16) -> Option<&[u8]> {
        for tag in self.iter_tags() {
            if tag.tag_type == tag_type {
                return Some(tag.data);
            }
        }
        None
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        let len = PPPOE_HEADER_SIZE + self.length() as usize;
        &self.buffer[..len]
    }
}

/// A PPPoE tag during iteration
#[derive(Debug, Clone)]
pub struct PppoeTag<'a> {
    /// Tag type
    pub tag_type: u16,
    /// Tag data
    pub data: &'a [u8],
}

/// Iterator over PPPoE tags
pub struct PppoeTagIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for PppoeTagIterator<'a> {
    type Item = PppoeTag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least 4 bytes for tag header (type + length)
        if self.offset + 4 > self.data.len() {
            return None;
        }

        let tag_type = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
        let tag_len =
            u16::from_be_bytes([self.data[self.offset + 2], self.data[self.offset + 3]]) as usize;

        // End of list
        if tag_type == tags::END_OF_LIST && tag_len == 0 {
            return None;
        }

        let data_start = self.offset + 4;
        let data_end = data_start + tag_len;

        if data_end > self.data.len() {
            return None;
        }

        let tag = PppoeTag {
            tag_type,
            data: &self.data[data_start..data_end],
        };

        self.offset = data_end;
        Some(tag)
    }
}

/// Builder for PPPoE frames
#[derive(Debug, Default)]
pub struct PppoeBuilder {
    code: u8,
    session_id: u16,
    payload: Vec<u8>,
}

impl PppoeBuilder {
    /// Create a new builder for discovery packets
    pub fn discovery() -> Self {
        Self {
            code: codes::PADI,
            session_id: 0,
            payload: Vec::new(),
        }
    }

    /// Create a new builder for session packets
    pub fn session(session_id: u16) -> Self {
        Self {
            code: codes::SESSION,
            session_id,
            payload: Vec::new(),
        }
    }

    /// Set the code
    pub fn code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// Set the session ID
    pub fn session_id(mut self, session_id: u16) -> Self {
        self.session_id = session_id;
        self
    }

    /// Add a raw tag (for discovery packets)
    pub fn add_tag(mut self, tag_type: u16, data: &[u8]) -> Self {
        self.payload.extend_from_slice(&tag_type.to_be_bytes());
        self.payload
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.payload.extend_from_slice(data);
        self
    }

    /// Add service name tag
    pub fn service_name(self, name: &str) -> Self {
        self.add_tag(tags::SERVICE_NAME, name.as_bytes())
    }

    /// Add empty service name tag (accept any service)
    pub fn service_name_any(self) -> Self {
        self.add_tag(tags::SERVICE_NAME, &[])
    }

    /// Add host unique tag
    pub fn host_uniq(self, uniq: &[u8]) -> Self {
        self.add_tag(tags::HOST_UNIQ, uniq)
    }

    /// Add AC cookie tag
    pub fn ac_cookie(self, cookie: &[u8]) -> Self {
        self.add_tag(tags::AC_COOKIE, cookie)
    }

    /// Set payload directly (for session packets containing PPP)
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the PPPoE frame
    pub fn build(self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(PPPOE_HEADER_SIZE + self.payload.len());

        // Version (4 bits) + Type (4 bits) = 0x11
        frame.push((PPPOE_VERSION << 4) | PPPOE_TYPE);
        // Code
        frame.push(self.code);
        // Session ID
        frame.extend_from_slice(&self.session_id.to_be_bytes());
        // Length
        frame.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        // Payload
        frame.extend_from_slice(&self.payload);

        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_padi() {
        // PPPoE PADI with Service-Name tag (empty)
        let data = [
            0x11, // Version=1, Type=1
            0x09, // Code=PADI
            0x00, 0x00, // Session ID=0
            0x00, 0x04, // Length=4
            0x01, 0x01, // Tag: Service-Name
            0x00, 0x00, // Tag Length=0
        ];

        let frame = PppoeFrame::parse(&data).unwrap();
        assert_eq!(frame.version(), 1);
        assert_eq!(frame.frame_type(), 1);
        assert_eq!(frame.code(), codes::PADI);
        assert_eq!(frame.session_id(), 0);
        assert_eq!(frame.length(), 4);

        let tags: Vec<_> = frame.iter_tags().collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].tag_type, tags::SERVICE_NAME);
        assert_eq!(tags[0].data.len(), 0);
    }

    #[test]
    fn test_parse_pado() {
        // PPPoE PADO with Service-Name and AC-Name tags
        let data = [
            0x11, // Version=1, Type=1
            0x07, // Code=PADO
            0x00, 0x00, // Session ID=0
            0x00, 0x10, // Length=16
            0x01, 0x01, // Tag: Service-Name
            0x00, 0x00, // Tag Length=0
            0x01, 0x02, // Tag: AC-Name
            0x00, 0x04, // Tag Length=4
            b't', b'e', b's', b't', // AC Name
            0x01, 0x04, // Tag: AC-Cookie
            0x00, 0x00, // Tag Length=0
        ];

        let frame = PppoeFrame::parse(&data).unwrap();
        assert_eq!(frame.code(), codes::PADO);

        let ac_name = frame.find_tag(tags::AC_NAME).unwrap();
        assert_eq!(ac_name, b"test");
    }

    #[test]
    fn test_parse_pads() {
        // PPPoE PADS with session ID
        let data = [
            0x11, // Version=1, Type=1
            0x65, // Code=PADS
            0x00, 0x01, // Session ID=1
            0x00, 0x04, // Length=4
            0x01, 0x01, // Tag: Service-Name
            0x00, 0x00, // Tag Length=0
        ];

        let frame = PppoeFrame::parse(&data).unwrap();
        assert_eq!(frame.code(), codes::PADS);
        assert_eq!(frame.session_id(), 1);
    }

    #[test]
    fn test_parse_session() {
        // PPPoE Session with PPP payload
        let data = [
            0x11, // Version=1, Type=1
            0x00, // Code=0 (Session)
            0x00, 0x01, // Session ID=1
            0x00, 0x04, // Length=4
            0xc0, 0x21, // PPP Protocol: LCP
            0x01, 0x02, // Some LCP data
        ];

        let frame = PppoeFrame::parse(&data).unwrap();
        assert_eq!(frame.code(), codes::SESSION);
        assert_eq!(frame.session_id(), 1);
        assert_eq!(frame.payload(), &[0xc0, 0x21, 0x01, 0x02]);
    }

    #[test]
    fn test_build_padi() {
        let frame = PppoeBuilder::discovery()
            .code(codes::PADI)
            .service_name_any()
            .host_uniq(&[0x12, 0x34, 0x56, 0x78])
            .build();

        let parsed = PppoeFrame::parse(&frame).unwrap();
        assert_eq!(parsed.code(), codes::PADI);
        assert_eq!(parsed.session_id(), 0);

        let host_uniq = parsed.find_tag(tags::HOST_UNIQ).unwrap();
        assert_eq!(host_uniq, &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_build_padr() {
        let frame = PppoeBuilder::discovery()
            .code(codes::PADR)
            .service_name("ISP")
            .ac_cookie(&[0xaa, 0xbb])
            .build();

        let parsed = PppoeFrame::parse(&frame).unwrap();
        assert_eq!(parsed.code(), codes::PADR);

        let service_name = parsed.find_tag(tags::SERVICE_NAME).unwrap();
        assert_eq!(service_name, b"ISP");

        let cookie = parsed.find_tag(tags::AC_COOKIE).unwrap();
        assert_eq!(cookie, &[0xaa, 0xbb]);
    }

    #[test]
    fn test_build_padt() {
        let frame = PppoeBuilder::discovery()
            .code(codes::PADT)
            .session_id(0x1234)
            .build();

        let parsed = PppoeFrame::parse(&frame).unwrap();
        assert_eq!(parsed.code(), codes::PADT);
        assert_eq!(parsed.session_id(), 0x1234);
    }

    #[test]
    fn test_build_session() {
        let ppp_data = [0xc0, 0x21, 0x01, 0x01, 0x00, 0x04]; // LCP Configure-Request

        let frame = PppoeBuilder::session(0x0001).payload(&ppp_data).build();

        let parsed = PppoeFrame::parse(&frame).unwrap();
        assert_eq!(parsed.code(), codes::SESSION);
        assert_eq!(parsed.session_id(), 0x0001);
        assert_eq!(parsed.payload(), &ppp_data);
    }

    #[test]
    fn test_roundtrip() {
        let original = PppoeBuilder::discovery()
            .code(codes::PADI)
            .service_name("test-service")
            .host_uniq(&[1, 2, 3, 4])
            .build();

        let parsed = PppoeFrame::parse(&original).unwrap();
        assert_eq!(parsed.as_bytes(), original.as_slice());
    }

    #[test]
    fn test_parse_invalid_version() {
        let data = [
            0x21, // Version=2 (invalid), Type=1
            0x09, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(PppoeFrame::parse(&data).is_err());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x11, 0x09, 0x00];
        assert!(PppoeFrame::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated_payload() {
        let data = [
            0x11, 0x09, 0x00, 0x00, 0x00, 0x10, // Length=16 but only 2 bytes follow
            0x01, 0x01,
        ];
        assert!(PppoeFrame::parse(&data).is_err());
    }
}
