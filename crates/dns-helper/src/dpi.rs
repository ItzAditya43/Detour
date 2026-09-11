//! DPI evasion by TLS-record fragmentation.
//!
//! Some networks read the server name from the (unencrypted) SNI field of a
//! TLS ClientHello and act on it — here, redirecting `www.youtube.com` to
//! YouTube's restricted-mode server. The name sits in one TLS record, so the
//! filter finds it with a single read.
//!
//! Splitting the ClientHello across two TLS records *inside* the hostname
//! defeats that: the record layer may fragment a handshake message anywhere,
//! so the real server reassembles it and completes the handshake, while a
//! filter that expects the SNI in one record no longer sees `youtube` as a
//! contiguous string. No decryption happens — only the record framing is
//! changed — so this is not a man-in-the-middle.
//!
//! Confirmed on the target network: TCP-segment splitting alone did nothing
//! (the middlebox reassembles TCP), but record fragmentation cut mid-hostname
//! lifted the restriction on every attempt.

/// A TLS record header is 5 bytes: content type, 2-byte version, 2-byte length.
const TLS_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SNI: u16 = 0x0000;

fn u16be(b: &[u8], i: usize) -> Option<usize> {
    Some(((*b.get(i)? as usize) << 8) | *b.get(i + 1)? as usize)
}

/// Given the handshake bytes (a TLS record's payload, i.e. everything after the
/// 5-byte record header), return an offset that falls in the middle of the SNI
/// hostname. Returns `None` if this is not a ClientHello with an SNI, or if the
/// structure does not parse — callers fall back to a fixed split.
pub fn sni_split_offset(p: &[u8]) -> Option<usize> {
    if *p.first()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    // 1 type + 3 length + 2 version + 32 random
    let mut i = 1 + 3 + 2 + 32;
    let sid_len = *p.get(i)?;
    i += 1 + sid_len as usize;
    let cipher_len = u16be(p, i)?;
    i += 2 + cipher_len;
    let comp_len = *p.get(i)? as usize;
    i += 1 + comp_len;
    let _ext_total = u16be(p, i)?;
    i += 2;

    while i + 4 <= p.len() {
        let etype = u16be(p, i)? as u16;
        let elen = u16be(p, i + 2)?;
        let edata_start = i + 4;
        if etype == EXT_SNI {
            // server_name_list: 2-byte list length, then entries of
            // name_type(1) + name_length(2) + name.
            let name_type = *p.get(edata_start + 2)?;
            if name_type != 0 {
                return None;
            }
            let name_len = u16be(p, edata_start + 3)?;
            let name_start = edata_start + 5;
            if name_len < 2 || name_start + name_len > p.len() {
                return None;
            }
            return Some(name_start + name_len / 2);
        }
        i = edata_start + elen;
    }
    None
}

/// Reframe a client's first TLS flight so the ClientHello is split across two
/// records inside the SNI hostname. If `data` is not a single handshake record,
/// or has no SNI, it is returned unchanged (nothing to gain, nothing broken).
pub fn fragment_client_hello(data: &[u8]) -> Vec<u8> {
    if data.len() <= TLS_HEADER || data[0] != CONTENT_HANDSHAKE {
        return data.to_vec();
    }
    let rec_len = match u16be(data, 3) {
        Some(n) => n,
        None => return data.to_vec(),
    };
    // Only reframe when the whole record is present and `data` is exactly it.
    if TLS_HEADER + rec_len != data.len() {
        return data.to_vec();
    }
    let version = [data[1], data[2]];
    let payload = &data[TLS_HEADER..];

    let cut = match sni_split_offset(payload) {
        Some(c) if c > 0 && c < payload.len() => c,
        // No SNI found: splitting near the front still separates most of the
        // handshake and is harmless.
        _ => {
            if payload.len() < 2 {
                return data.to_vec();
            }
            (payload.len() / 2).max(1)
        }
    };

    let mut out = Vec::with_capacity(data.len() + TLS_HEADER);
    for part in [&payload[..cut], &payload[cut..]] {
        out.push(CONTENT_HANDSHAKE);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid ClientHello record for `host`.
    fn client_hello(host: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // SNI extension body
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
        sni.push(0); // name type host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        ext.extend_from_slice(&EXT_SNI.to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1); // compression methods len
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(HANDSHAKE_CLIENT_HELLO);
        hs.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(CONTENT_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_offset_inside_hostname() {
        let rec = client_hello("www.youtube.com");
        let payload = &rec[TLS_HEADER..];
        let off = sni_split_offset(payload).expect("SNI found");
        // The offset must land within the hostname bytes.
        let name_pos = payload
            .windows(15)
            .position(|w| w == b"www.youtube.com")
            .unwrap();
        assert!(off > name_pos && off < name_pos + 15, "off={off} name_pos={name_pos}");
    }

    #[test]
    fn fragmenting_produces_two_records_and_preserves_bytes() {
        let rec = client_hello("www.youtube.com");
        let out = fragment_client_hello(&rec);

        // Two records now.
        assert_eq!(out[0], CONTENT_HANDSHAKE);
        let len1 = u16be(&out, 3).unwrap();
        let second = TLS_HEADER + len1;
        assert_eq!(out[second], CONTENT_HANDSHAKE, "second record header");

        // Concatenated payloads equal the original handshake bytes.
        let p1 = &out[TLS_HEADER..second];
        let len2 = u16be(&out, second + 3).unwrap();
        let p2 = &out[second + TLS_HEADER..second + TLS_HEADER + len2];
        let rebuilt: Vec<u8> = p1.iter().chain(p2).copied().collect();
        assert_eq!(rebuilt, &rec[TLS_HEADER..]);
    }

    #[test]
    fn split_falls_inside_hostname_so_name_is_severed() {
        let rec = client_hello("www.youtube.com");
        let out = fragment_client_hello(&rec);
        let len1 = u16be(&out, 3).unwrap();
        let first_record = &out[..TLS_HEADER + len1];
        // The intact substring "youtube" must not survive in the first record.
        assert!(
            first_record.windows(7).all(|w| w != b"youtube"),
            "hostname was not severed"
        );
    }

    #[test]
    fn non_tls_data_passes_through_unchanged() {
        let http = b"CONNECT www.youtube.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(fragment_client_hello(http), http);
        assert_eq!(fragment_client_hello(&[]), Vec::<u8>::new());
        assert_eq!(fragment_client_hello(&[0x16, 0x03]), vec![0x16, 0x03]);
    }

    #[test]
    fn partial_record_is_not_reframed() {
        // Record header claims more than is present.
        let rec = client_hello("www.youtube.com");
        let truncated = &rec[..rec.len() - 3];
        assert_eq!(fragment_client_hello(truncated), truncated);
    }

    #[test]
    fn client_hello_without_sni_still_splits_safely() {
        // A handshake record with no extensions.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes()); // zero extensions
        let mut hs = vec![HANDSHAKE_CLIENT_HELLO];
        hs.extend_from_slice(&[0, (body.len() >> 8) as u8, body.len() as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let out = fragment_client_hello(&rec);
        assert_ne!(out, rec, "should still fragment");
        assert!(out.len() > rec.len(), "gained a second record header");
    }
}
