//! ChaCha20-Poly1305 for the WireGuard data path. It works in place on a borrowed
//! buffer and never allocates.
//!
//! # Standards
//!
//! - RFC 8439 sections 2.1 to 2.8: ChaCha20 (IETF variant, 96-bit nonce, 32-bit
//!   block counter), Poly1305, and the AEAD construction.
//! - WireGuard (whitepaper section 5.4.6) uses the 12-byte nonce of four zero
//!   bytes followed by the 64-bit little-endian packet counter; [`wireguard_nonce`]
//!   builds it.
//!
//! Deviations: none. Only the in-place, detached-tag form is offered.

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Length of the authentication tag.
pub const TAG_LEN: usize = 16;

/// The nonce WireGuard uses for the packet with this counter.
pub fn wireguard_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte keystream block (RFC 8439 2.3).
fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        initial[4 + i] = le32(&key[4 * i..]);
    }
    initial[12] = counter;
    for i in 0..3 {
        initial[13 + i] = le32(&nonce[4 * i..]);
    }
    let mut s = initial;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(initial[i]).to_le_bytes());
    }
    out
}

/// XORs the keystream starting at block `counter` into `data` (RFC 8439 2.4).
fn apply_keystream(key: &[u8; 32], nonce: &[u8; 12], mut counter: u32, data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let ks = block(key, counter, nonce);
        for (byte, k) in chunk.iter_mut().zip(ks) {
            *byte ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Poly1305 (RFC 8439 2.5) with 26-bit limbs.
struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    buffered: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let r = [
            le32(&key[0..]) & 0x03ff_ffff,
            (le32(&key[3..]) >> 2) & 0x03ff_ff03,
            (le32(&key[6..]) >> 4) & 0x03ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x03f0_3fff,
            (le32(&key[12..]) >> 8) & 0x000f_ffff,
        ];
        let pad = [
            le32(&key[16..]),
            le32(&key[20..]),
            le32(&key[24..]),
            le32(&key[28..]),
        ];
        Self {
            r,
            h: [0; 5],
            pad,
            buf: [0; 16],
            buffered: 0,
        }
    }

    fn process(&mut self, m: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let mask = 0x03ff_ffff;
        let h0 = u64::from(self.h[0] + (le32(&m[0..]) & mask));
        let h1 = u64::from(self.h[1] + ((le32(&m[3..]) >> 2) & mask));
        let h2 = u64::from(self.h[2] + ((le32(&m[6..]) >> 4) & mask));
        let h3 = u64::from(self.h[3] + ((le32(&m[9..]) >> 6) & mask));
        let h4 = u64::from(self.h[4] + ((le32(&m[12..]) >> 8) | hibit));

        let mut d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let m64 = u64::from(mask);
        let mut c = d0 >> 26;
        d0 &= m64;
        d1 += c;
        c = d1 >> 26;
        d1 &= m64;
        d2 += c;
        c = d2 >> 26;
        d2 &= m64;
        d3 += c;
        c = d3 >> 26;
        d3 &= m64;
        d4 += c;
        c = d4 >> 26;
        d4 &= m64;
        d0 += c * 5;
        c = d0 >> 26;
        d0 &= m64;
        d1 += c;
        self.h = [d0 as u32, d1 as u32, d2 as u32, d3 as u32, d4 as u32];
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = (16 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 16 {
                return;
            }
            let block = self.buf;
            self.process(&block, 1 << 24);
            self.buffered = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.process(&block, 1 << 24);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Pads the data so far with zeros to a multiple of 16 bytes (the AEAD's pad16).
    fn pad16(&mut self) {
        if self.buffered > 0 {
            let zeros = [0u8; 16];
            let n = 16 - self.buffered;
            self.update(&zeros[..n]);
        }
    }

    fn finish(mut self) -> [u8; TAG_LEN] {
        if self.buffered > 0 {
            let mut block = [0u8; 16];
            block[..self.buffered].copy_from_slice(&self.buf[..self.buffered]);
            block[self.buffered] = 1;
            self.process(&block, 0);
        }
        let mask = 0x03ff_ffff;
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= mask;
        h2 += c;
        c = h2 >> 26;
        h2 &= mask;
        h3 += c;
        c = h3 >> 26;
        h3 &= mask;
        h4 += c;
        c = h4 >> 26;
        h4 &= mask;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= mask;
        h1 += c;

        // h + 5 - 2^130: keep it when h >= 2^130 - 5.
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= mask;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= mask;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= mask;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= mask;
        let g4 = (h4 + c).wrapping_sub(1 << 26);
        let keep_g = (g4 >> 31).wrapping_sub(1);
        let keep_h = !keep_g;
        let h0 = (h0 & keep_h) | (g0 & keep_g);
        let h1 = (h1 & keep_h) | (g1 & keep_g);
        let h2 = (h2 & keep_h) | (g2 & keep_g);
        let h3 = (h3 & keep_h) | (g3 & keep_g);
        let h4 = (h4 & keep_h) | (g4 & keep_g);

        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        let mut f = u64::from(w0) + u64::from(self.pad[0]);
        let mut tag = [0u8; TAG_LEN];
        tag[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w1) + u64::from(self.pad[1]) + (f >> 32);
        tag[4..8].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w2) + u64::from(self.pad[2]) + (f >> 32);
        tag[8..12].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w3) + u64::from(self.pad[3]) + (f >> 32);
        tag[12..16].copy_from_slice(&(f as u32).to_le_bytes());
        tag
    }
}

/// The tag over `aad` and `ciphertext` (RFC 8439 2.8).
fn compute_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block(key, 0, nonce)[..32]);
    let mut mac = Poly1305::new(&otk);
    mac.update(aad);
    mac.pad16();
    mac.update(ciphertext);
    mac.pad16();
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finish()
}

/// Encrypts `data` in place and returns the tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
    apply_keystream(key, nonce, 1, data);
    compute_tag(key, nonce, aad, data)
}

/// Checks the tag and, only if it is right, decrypts `data` in place. Returns
/// whether the tag was right; on `false` `data` is unchanged.
#[must_use]
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let expected = compute_tag(key, nonce, aad, data);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return false;
    }
    apply_keystream(key, nonce, 1, data);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn chacha20_block_matches_rfc_8439_2_3_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
        let out = block(&key, 1, &nonce);
        assert_eq!(out[..16], hex("10f1e7e4d13b5915500fdd1fa32071c4")[..],);
        assert_eq!(out[48..], hex("b5129cd1de164eb9cbd083e8a2503c4e")[..],);
    }

    #[test]
    fn poly1305_matches_rfc_8439_2_5_2() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let mut mac = Poly1305::new(&key);
        mac.update(b"Cryptographic Forum Research Group");
        assert_eq!(
            mac.finish()[..],
            hex("a8061dc1305136c6c22b8baf0c0127a9")[..]
        );
    }

    #[test]
    fn poly1305_gives_the_same_tag_however_the_input_is_split() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let data: Vec<u8> = (0..100u8).collect();
        let mut whole = Poly1305::new(&key);
        whole.update(&data);
        let want = whole.finish();
        for cut in [1, 5, 15, 16, 17, 33, 99] {
            let mut split = Poly1305::new(&key);
            split.update(&data[..cut]);
            split.update(&data[cut..]);
            assert_eq!(split.finish(), want, "cut {cut}");
        }
    }

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    fn rfc_key_nonce_aad() -> ([u8; 32], [u8; 12], Vec<u8>) {
        let key = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = hex("070000004041424344454647").try_into().unwrap();
        (key, nonce, hex("50515253c0c1c2c3c4c5c6c7"))
    }

    #[test]
    fn aead_matches_rfc_8439_2_8_2() {
        let (key, nonce, aad) = rfc_key_nonce_aad();
        let mut data = PLAINTEXT.to_vec();
        let tag = seal(&key, &nonce, &aad, &mut data);
        assert_eq!(data[..16], hex("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(tag[..], hex("1ae10b594f09e26a7e902ecbd0600691")[..]);
        assert!(open(&key, &nonce, &aad, &mut data, &tag));
        assert_eq!(data, PLAINTEXT);
    }

    #[test]
    fn open_refuses_a_changed_message_and_leaves_it_alone() {
        let (key, nonce, aad) = rfc_key_nonce_aad();
        let mut data = PLAINTEXT.to_vec();
        let tag = seal(&key, &nonce, &aad, &mut data);
        let sealed = data.clone();

        data[3] ^= 1;
        let tampered = data.clone();
        assert!(!open(&key, &nonce, &aad, &mut data, &tag));
        assert_eq!(data, tampered);

        let mut data = sealed.clone();
        assert!(!open(&key, &nonce, b"other", &mut data, &tag));
        let mut bad_tag = tag;
        bad_tag[15] ^= 0x80;
        assert!(!open(&key, &nonce, &aad, &mut data, &bad_tag));
        assert_eq!(data, sealed);
    }

    #[test]
    fn empty_and_block_sized_messages_round_trip() {
        let key = [9u8; 32];
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1420] {
            let nonce = wireguard_nonce(len as u64);
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut data = plain.clone();
            let tag = seal(&key, &nonce, &[], &mut data);
            assert!(open(&key, &nonce, &[], &mut data, &tag), "len {len}");
            assert_eq!(data, plain);
        }
    }

    #[test]
    fn the_wireguard_nonce_is_four_zero_bytes_and_the_little_endian_counter() {
        assert_eq!(
            wireguard_nonce(0x0102),
            hex("00000000 0201000000000000")[..]
        );
    }
}
