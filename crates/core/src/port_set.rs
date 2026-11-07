//! The public ports of a NAT: a range, or a MAP-E port set (RFC 7597 section 5.1).
//!
//! A port set is numbered by an index `0..count()`, which the NAT's port tables
//! use; [`PortSet::port`] and [`PortSet::index`] convert.
//!
//! # Standards
//!
//! - RFC 7597 section 5.1 (the GMA algorithm): with PSID offset `a`, PSID length
//!   `k` and `m = 16 - a - k`, the ports of PSID `p` are
//!   `(A << (k + m)) | (p << m) | j` for `A` in `1..2^a` (`0` when `a` is 0) and
//!   `j` in `0..2^m`. With `a > 0` the ports below `2^(16 - a)` (A = 0) are left
//!   out, as the RFC asks for the well-known ports.
//!
//! Deviations: a PSID offset of 0 (contiguous blocks, as lw4o6 uses), a PSID
//! length of 0 (no sharing) and `a + k = 16` (one port per PSID per block) are
//! refused, although RFC 7597 allows them; MAP-E's default offset is 6.

/// The public ports of a NAT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortSet {
    shape: Shape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Range { first: u16, last: u16 },
    Psid { offset: u8, length: u8, psid: u16 },
}

/// Why a port set was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortSetError {
    /// The range includes port 0 or is reversed.
    Range,
    /// `offset + length` is over 16, `length` is 0 or 16, or the PSID does not
    /// fit `length` bits.
    Psid,
}

impl PortSet {
    /// The ports `first..=last` (port 0 is refused).
    pub const fn range(first: u16, last: u16) -> Result<Self, PortSetError> {
        if first == 0 || first > last {
            return Err(PortSetError::Range);
        }
        Ok(Self {
            shape: Shape::Range { first, last },
        })
    }

    /// The MAP-E port set of PSID `psid` with PSID offset `offset` (RFC 7597's
    /// `a`, 6 by default) and length `length` (`k`).
    pub const fn psid(offset: u8, length: u8, psid: u16) -> Result<Self, PortSetError> {
        if offset == 0 || length == 0 || offset as u16 + length as u16 >= 16 || psid >> length != 0
        {
            return Err(PortSetError::Psid);
        }
        Ok(Self {
            shape: Shape::Psid {
                offset,
                length,
                psid,
            },
        })
    }

    /// How many ports there are.
    #[must_use]
    pub const fn count(self) -> usize {
        match self.shape {
            Shape::Range { first, last } => (last - first) as usize + 1,
            Shape::Psid { offset, length, .. } => {
                let m = 16 - offset - length;
                let blocks = if offset == 0 {
                    1
                } else {
                    (1_usize << offset) - 1
                };
                blocks << m
            }
        }
    }

    /// The port numbered `index` (below [`Self::count`]).
    #[must_use]
    pub const fn port(self, index: usize) -> u16 {
        match self.shape {
            Shape::Range { first, .. } => first + index as u16,
            Shape::Psid {
                offset,
                length,
                psid,
            } => {
                let m = 16 - offset - length;
                let a = (index >> m) as u16 + if offset == 0 { 0 } else { 1 };
                let j = (index & ((1 << m) - 1)) as u16;
                (a << (length + m)) | (psid << m) | j
            }
        }
    }

    /// The number of `port`, or `None` when it is not in the set.
    #[must_use]
    pub const fn index(self, port: u16) -> Option<usize> {
        match self.shape {
            Shape::Range { first, last } => {
                if port >= first && port <= last {
                    Some((port - first) as usize)
                } else {
                    None
                }
            }
            Shape::Psid {
                offset,
                length,
                psid,
            } => {
                let m = 16 - offset - length;
                if (port >> m) & ((1 << length) - 1) != psid {
                    return None;
                }
                let a = (port >> (length + m)) as usize;
                let a = if offset == 0 {
                    a
                } else if a == 0 {
                    return None;
                } else {
                    a - 1
                };
                Some((a << m) | (port as usize & ((1 << m) - 1)))
            }
        }
    }

    /// Whether `port` is in the set.
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.index(port).is_some()
    }

    /// The lowest and highest ports.
    #[must_use]
    pub const fn bounds(self) -> (u16, u16) {
        (self.port(0), self.port(self.count() - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_numbers_its_ports_in_order() {
        let set = PortSet::range(40_000, 40_009).unwrap();
        assert_eq!(set.count(), 10);
        assert_eq!((set.port(0), set.port(9)), (40_000, 40_009));
        assert_eq!(set.index(40_005), Some(5));
        assert_eq!(set.index(39_999), None);
        assert!(PortSet::range(0, 10).is_err());
    }

    /// RFC 7597 Appendix B example 2: a = 6, k = 6 (m = 4), PSID 0x34.
    #[test]
    fn a_psid_set_follows_rfc_7597() {
        let set = PortSet::psid(6, 6, 0x34).unwrap();
        assert_eq!(set.count(), 63 * 16);
        // A = 1: 0b000001 110100 0000 = 1856 .. 1871.
        assert_eq!(set.port(0), 1856);
        assert_eq!(set.port(15), 1871);
        // A = 2: 2880.
        assert_eq!(set.port(16), 2880);
        assert_eq!(set.bounds().1, (63 << 10) | (0x34 << 4) | 15);
        for index in [0, 1, 15, 16, 500, set.count() - 1] {
            assert_eq!(set.index(set.port(index)), Some(index));
        }
        // Another PSID's port, and a well-known one (A = 0).
        assert_eq!(set.index(1856 + 16), None);
        assert_eq!(set.index(0x34 << 4), None);
        assert!(PortSet::psid(6, 0, 0).is_err());
        assert!(PortSet::psid(6, 6, 64).is_err());
        assert!(PortSet::psid(8, 8, 1).is_err());
        assert!(PortSet::psid(0, 6, 5).is_err(), "offset 0 is refused");
    }
}
