use super::*;
use crate::DkimAlgorithm;

const RFC8463_SEED: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

const RFC8463_MESSAGE: &[u8] = b"From: Joe SixPack <joe@football.example.com>\r\n\
To: Suzie Q <suzie@shopping.example.net>\r\n\
Subject: Is dinner ready?\r\n\
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n\
Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n\
\r\n\
Hi.\r\n\
\r\n\
We lost the game.  Are you hungry yet?\r\n\
\r\n\
Joe.\r\n";

fn b64(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    base64_append(bytes, &mut out);
    String::from_utf8(out).unwrap()
}

fn rfc_key() -> DkimKey {
    let mut seed = Vec::new();
    crate::encode::base64_decode(RFC8463_SEED.as_bytes(), &mut seed).unwrap();
    DkimKey::ed25519_from_seed(&seed.try_into().unwrap()).unwrap()
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/dkim/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn test_rfc8463_appendix_a_ed25519_signature() {
    // The RFC's own signature header, folded as published.
    let header = b"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n \
d=football.example.com; i=@football.example.com;\r\n \
q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n \
subject : date : message-id : from : subject : date;\r\n \
bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n \
b=";
    let parsed = Parsed::new(RFC8463_MESSAGE).unwrap();
    let bh = body_hash(parsed.body(RFC8463_MESSAGE), Canonicalization::Relaxed);
    assert_eq!(b64(&bh), "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=");

    let canon = HeaderCanonicalizer::new(Canonicalization::Relaxed);
    let mut data = Vec::new();
    for i in 0..5 {
        canon.canonicalize(parsed.field(RFC8463_MESSAGE, i), &mut data);
    }
    canon.canonicalize(header, &mut data);
    data.truncate(data.len() - 2);
    let sig = rfc_key().sign(&data).unwrap();
    assert_eq!(
        b64(&sig),
        "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11BusFa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="
    );
    assert_eq!(
        rfc_key().dns_record(),
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    );
}

#[test]
fn test_empty_body_hashes() {
    assert_eq!(
        b64(&body_hash(b"", Canonicalization::Simple)),
        "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
    );
    assert_eq!(
        b64(&body_hash(b"", Canonicalization::Relaxed)),
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}

/// What a verifier does with an emitted header (RFC 6376 section 6.1.3),
/// written apart from the signer: parse the tags, select the headers named
/// in h= bottom-up, delete the b= value, canonicalize, and rebuild the
/// signed data. Both algorithms are deterministic, so signing that data
/// again must give the same b=.
fn verify(signed: &[u8], key: &DkimKey) {
    let text = std::str::from_utf8(signed).unwrap();
    let end = text.find("\r\n\r\n").unwrap() + 2;
    let mut fields: Vec<&str> = Vec::new();
    let mut start = 0;
    for (i, _) in text[..end].match_indices("\r\n") {
        if !text[i + 2..].starts_with([' ', '\t']) {
            fields.push(&text[start..i + 2]);
            start = i + 2;
        }
    }
    let sig = fields[0];
    assert!(sig.starts_with("DKIM-Signature:"));
    for line in sig.split("\r\n") {
        assert!(line.len() <= 78, "line too long: {line:?}");
    }
    let unfolded: String = sig["DKIM-Signature:".len()..]
        .replace("\r\n", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let tags: Vec<(&str, &str)> = unfolded
        .split(';')
        .filter(|t| !t.is_empty())
        .map(|t| t.split_once('=').unwrap())
        .collect();
    let tag = |k: &str| tags.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
    assert!(tag("l").is_none(), "T-19: l= must never be written");
    assert_eq!(tag("v"), Some("1"));
    assert_eq!(tag("a"), Some(key.algorithm().name()));
    let (hc, bc) = tag("c").unwrap().split_once('/').unwrap();
    let mode = |n: &str| match n {
        "simple" => Canonicalization::Simple,
        "relaxed" => Canonicalization::Relaxed,
        other => panic!("{other}"),
    };
    let body = &signed[end + 2..];
    assert_eq!(tag("bh").unwrap(), b64(&body_hash(body, mode(bc))));

    let canon = HeaderCanonicalizer::new(mode(hc));
    let mut data = Vec::new();
    let mut used = vec![false; fields.len()];
    used[0] = true;
    for name in tag("h").unwrap().split(':') {
        let found = (0..fields.len()).rev().find(|&i| {
            !used[i]
                && fields[i]
                    .split(':')
                    .next()
                    .unwrap()
                    .trim_end()
                    .eq_ignore_ascii_case(name)
        });
        if let Some(i) = found {
            used[i] = true;
            canon.canonicalize(fields[i].as_bytes(), &mut data);
        }
    }
    let b_at = sig.rfind("b=").unwrap();
    canon.canonicalize(&sig.as_bytes()[..b_at + 2], &mut data);
    data.truncate(data.len() - 2);
    assert_eq!(tag("b").unwrap(), b64(&key.sign(&data).unwrap()));
}

fn signed_with(signer: &DkimSigner, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    signer.sign_into(message, 1_528_637_909, &mut out).unwrap();
    out.extend_from_slice(message);
    out
}

#[test]
fn test_signatures_verify_under_every_canonicalization() {
    use Canonicalization::{Relaxed, Simple};
    let keys = [
        rfc_key(),
        DkimKey::rsa_from_pem(&fixture("rsa-2048.pem")).unwrap(),
    ];
    for key in keys {
        for (h, b) in [
            (Relaxed, Relaxed),
            (Simple, Simple),
            (Relaxed, Simple),
            (Simple, Relaxed),
        ] {
            let signer = DkimSigner::new("football.example.com", "brisbane", key.clone())
                .unwrap()
                .canonicalization(h, b)
                .expiry(3600);
            let signed = signed_with(&signer, RFC8463_MESSAGE);
            verify(&signed, &key);
            let text = String::from_utf8(signed).unwrap();
            assert!(text.contains("x=1528641509;"), "{text}");
        }
    }
}

#[test]
fn test_header_list_and_oversigning() {
    let signer = DkimSigner::new("football.example.com", "brisbane", rfc_key()).unwrap();
    let header = signer.sign(RFC8463_MESSAGE, 1_528_637_909).unwrap();
    let flat: String = header.replace("\r\n ", "");
    assert!(
        flat.contains(
            "h=from:to:subject:date:message-id:from:to:cc:subject:date:message-id:reply-to:sender:in-reply-to:references:mime-version:content-type:content-transfer-encoding:list-unsubscribe:list-unsubscribe-post;"
        ),
        "{flat}"
    );
    assert!(!flat.contains("rsa-sha1") && !flat.contains("l="), "{flat}");

    // Only From is listed when the caller's list leaves it out.
    let signer = signer.headers(&["Subject"]).unwrap().oversign(&[]).unwrap();
    let flat = signer
        .sign(RFC8463_MESSAGE, 0)
        .unwrap()
        .replace("\r\n ", "");
    assert!(flat.contains("h=from:subject;"), "{flat}");
}

#[test]
fn test_added_header_changes_the_signed_data() {
    // T-20: a second Subject added after signing lands on an oversigned
    // slot that was hashed as empty, so the data a verifier rebuilds differs.
    let key = rfc_key();
    let signer = DkimSigner::new("football.example.com", "brisbane", key.clone()).unwrap();
    let signed = signed_with(&signer, RFC8463_MESSAGE);
    let text = String::from_utf8(signed).unwrap();
    let tampered = text.replacen("From: Joe", "Subject: Free money\r\nFrom: Joe", 1);
    let result = std::panic::catch_unwind(|| verify(tampered.as_bytes(), &key));
    assert!(
        result.is_err(),
        "a header added in transit must break the signature"
    );
}

#[test]
fn test_every_default_header_added_in_transit_breaks_the_signature() {
    // A verifier hashes the bottom-most instances named in h=; a signed
    // header that is not oversigned can be added above the signed one and
    // the signature still verifies. Every default header is oversigned, so
    // each of these breaks it, present in the message or not.
    let key = rfc_key();
    let signer = DkimSigner::new("football.example.com", "brisbane", key.clone()).unwrap();
    let text = String::from_utf8(signed_with(&signer, RFC8463_MESSAGE)).unwrap();
    verify(text.as_bytes(), &key);
    for added in [
        "Content-Type: text/html; charset=utf-8",
        "Content-Transfer-Encoding: base64",
        "MIME-Version: 2.0",
        "Sender: ceo@example.com",
        "List-Unsubscribe: <https://evil.example/u>",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
        "In-Reply-To: <x@evil.example>",
        "References: <x@evil.example>",
        "Reply-To: x@evil.example",
        "Cc: x@evil.example",
    ] {
        let tampered = text.replacen("From: Joe", &format!("{added}\r\nFrom: Joe"), 1);
        let result = std::panic::catch_unwind(|| verify(tampered.as_bytes(), &key));
        assert!(
            result.is_err(),
            "{added} added in transit must break the signature"
        );
    }
}

#[test]
fn test_several_signatures_are_independent() {
    let ed = DkimSigner::new("football.example.com", "brisbane", rfc_key()).unwrap();
    let rsa_key = DkimKey::rsa_from_pem(&fixture("rsa-2048.pem")).unwrap();
    let rsa = DkimSigner::new("football.example.com", "test", rsa_key.clone()).unwrap();
    let headers = sign_all(&[ed.clone(), rsa.clone()], RFC8463_MESSAGE, 1_528_637_909).unwrap();
    let mut expected = ed
        .sign(RFC8463_MESSAGE, 1_528_637_909)
        .unwrap()
        .into_bytes();
    expected.extend(
        rsa.sign(RFC8463_MESSAGE, 1_528_637_909)
            .unwrap()
            .into_bytes(),
    );
    assert_eq!(headers, expected);
    // Each verifies with the other signature present above it.
    let split = headers
        .windows(16)
        .rposition(|w| w == b"DKIM-Signature: ")
        .unwrap();
    let mut second = headers[split..].to_vec();
    second.extend_from_slice(RFC8463_MESSAGE);
    verify(&second, &rsa_key);
}

#[test]
fn test_key_sizes_t21() {
    for (bits, file) in [
        (1023, "rsa-1023.pem"),
        (1024, "rsa-1024.pem"),
        (2047, "rsa-2047.pem"),
    ] {
        assert_eq!(
            DkimKey::rsa_from_pem(&fixture(file)).unwrap_err(),
            DkimError::KeyTooSmall {
                bits,
                minimum: 2048
            }
        );
    }
    assert_eq!(
        DkimKey::rsa_from_pem(&fixture("rsa-4098.pem")).unwrap_err(),
        DkimError::KeyTooLarge { bits: 4098 }
    );
    for file in ["rsa-2048.pem", "rsa-2048-pkcs1.pem", "rsa-4096.pem"] {
        let key = DkimKey::rsa_from_pem(&fixture(file)).unwrap();
        assert_eq!(key.algorithm(), DkimAlgorithm::RsaSha256);
    }
    let der = std::fs::read(format!(
        "{}/tests/fixtures/dkim/rsa-2048.der",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(DkimKey::rsa_from_der(&der).unwrap().rsa_bits(), Some(2048));
    assert!(
        DkimKey::rsa_from_pem(&fixture("rsa-4096.pem"))
            .unwrap()
            .dns_record()
            .starts_with("v=DKIM1; k=rsa; p=MIIC")
    );
}

#[test]
fn test_key_formats_refused() {
    assert_eq!(
        DkimKey::rsa_from_pem(&fixture("rsa-2048-encrypted.pem")).unwrap_err(),
        DkimError::KeyFormat
    );
    assert_eq!(
        DkimKey::rsa_from_pem(&fixture("ed25519.pem")).unwrap_err(),
        DkimError::KeyFormat
    );
    assert_eq!(
        DkimKey::ed25519_from_pkcs8_pem(&fixture("rsa-2048.pem")).unwrap_err(),
        DkimError::KeyFormat
    );
    assert_eq!(
        DkimKey::ed25519_from_pkcs8_pem(&fixture("rsa-2048-pkcs1.pem")).unwrap_err(),
        DkimError::KeyFormat
    );
    let ed = DkimKey::ed25519_from_pkcs8_pem(&fixture("ed25519.pem")).unwrap();
    assert_eq!(ed.algorithm(), DkimAlgorithm::Ed25519Sha256);
    for bad in [
        "",
        "-----BEGIN PRIVATE KEY-----\nAAAA",
        "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
    ] {
        assert_eq!(
            DkimKey::ed25519_from_pkcs8_pem(bad).unwrap_err(),
            DkimError::KeyFormat
        );
    }
    assert_eq!(
        DkimKey::rsa_from_der(&[0x30, 0x03, 0x02, 0x01]).unwrap_err(),
        DkimError::KeyFormat
    );
}

#[test]
fn test_debug_never_prints_key_material_t22() {
    let key = rfc_key();
    assert_eq!(
        format!("{key:?}"),
        "DkimKey { algorithm: Ed25519Sha256, .. }"
    );
    let rsa = DkimKey::rsa_from_pem(&fixture("rsa-2048.pem")).unwrap();
    assert_eq!(
        format!("{rsa:?}"),
        "DkimKey { algorithm: RsaSha256, bits: 2048, .. }"
    );
    let signer = DkimSigner::new("example.com", "s", key).unwrap();
    assert!(!format!("{signer:?}").contains(RFC8463_SEED));
}

#[test]
fn test_signer_configuration_checks() {
    let key = rfc_key();
    assert_eq!(
        DkimSigner::new("exa mple.com", "s", key.clone()).unwrap_err(),
        DkimError::InvalidDomain
    );
    assert_eq!(
        DkimSigner::new("bücher.example", "s", key.clone()).unwrap_err(),
        DkimError::InvalidDomain
    );
    for bad in ["", "-s", "s-", "a..b", "s_1", "x.", &"a".repeat(64)] {
        assert_eq!(
            DkimSigner::new("example.com", bad, key.clone()).unwrap_err(),
            DkimError::InvalidSelector,
            "{bad:?}"
        );
    }
    let s = DkimSigner::new("Example.COM", "mail.2026-a", key).unwrap();
    assert_eq!(s.domain(), "example.com");
    assert_eq!(
        s.clone().headers(&["bad name"]).unwrap_err(),
        DkimError::InvalidHeaderName
    );
    assert_eq!(
        s.clone().oversign(&["x:y"]).unwrap_err(),
        DkimError::InvalidHeaderName
    );

    let inside = Address::parse("news=letter;x@mail.example.com")
        .unwrap_or_else(|_| Address::parse("news=letter@mail.example.com").unwrap());
    let s2 = s.clone().identity(&inside).unwrap();
    let flat = s2
        .sign(b"From: a@example.com\r\n\r\n", 0)
        .unwrap()
        .replace("\r\n ", "");
    assert!(flat.contains("i=news=3Dletter@mail.example.com;"), "{flat}");
    for outside in ["a@example.org", "a@badexample.com", "a@com"] {
        assert_eq!(
            s.clone()
                .identity(&Address::parse(outside).unwrap())
                .unwrap_err(),
            DkimError::IdentityOutsideDomain,
            "{outside}"
        );
    }
}

#[test]
fn test_message_checks() {
    let s = DkimSigner::new("example.com", "s", rfc_key()).unwrap();
    assert_eq!(
        s.sign(b"Subject: x\r\n\r\nbody\r\n", 0).unwrap_err(),
        DkimError::MissingFrom
    );
    assert_eq!(
        s.sign(b" folded first\r\nFrom: a@example.com\r\n\r\n", 0)
            .unwrap_err(),
        DkimError::MalformedMessage { line: 1 }
    );
    assert_eq!(
        s.sign(b"From: a@example.com\r\nno colon here\r\n\r\n", 0)
            .unwrap_err(),
        DkimError::MalformedMessage { line: 2 }
    );
    assert_eq!(
        s.sign(b"From: a@example.com\nX: y\r\n\r\n", 0).unwrap_err(),
        DkimError::MalformedMessage { line: 1 }
    );
    assert_eq!(
        s.sign(b"From: a@example.com\r\n", 0).unwrap_err(),
        DkimError::MalformedMessage { line: 2 }
    );
    let mut big = b"From: a@example.com\r\n".to_vec();
    while big.len() <= MAX_HEADER_BLOCK {
        big.extend_from_slice(b"X-Filler: 0123456789012345678901234567890123456789\r\n");
    }
    big.extend_from_slice(b"\r\nbody\r\n");
    assert_eq!(s.sign(&big, 0).unwrap_err(), DkimError::HeaderBlockTooLarge);
    // Both From instances are signed when a message has two.
    let flat = s
        .sign(b"From: a@example.com\r\nFrom: b@example.com\r\n\r\n", 0)
        .unwrap()
        .replace("\r\n ", "");
    assert!(flat.contains("h=from:from:from:"), "{flat}");
}

#[test]
fn test_obsolete_name_spacing_is_matched() {
    let key = rfc_key();
    let s = DkimSigner::new("example.com", "s", key.clone()).unwrap();
    let msg = b"From : a@example.com\r\nSubject\t:  hello\r\n  world\r\n\r\nx\r\n";
    let flat = s.sign(msg, 0).unwrap().replace("\r\n ", "");
    assert!(flat.contains("h=from:subject:"), "{flat}");
    verify(&signed_with(&s, msg), &key);
}
