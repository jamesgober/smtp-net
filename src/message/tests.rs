use alloc::{format, string::String, vec, vec::Vec};

use super::part::TransferEncoding;
use super::*;
use crate::address::Address;
use crate::error::{AddressError, ErrorKind};

/// A source that repeats a byte pattern, for deterministic output.
struct Counter(u8);
impl RandomSource for Counter {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

struct Failing;
impl RandomSource for Failing {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::new(ErrorKind::Random))
    }
}

const T: u64 = 1_792_591_385; // 2026-10-21 14:03:05 UTC

fn base() -> MessageBuilder {
    Message::builder()
        .from("Example <no-reply@example.com>")
        .unwrap()
        .to("user@example.org")
        .unwrap()
}

fn bytes(m: &Message) -> String {
    let b = m.to_bytes().unwrap();
    assert_eq!(b.len() as u64, m.encoded_len(), "encoded_len must be exact");
    String::from_utf8(b).unwrap()
}

fn check_wire_rules(s: &str) {
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'\n' {
            assert_eq!(b.get(i.wrapping_sub(1)), Some(&b'\r'), "bare LF at {i}");
        }
        if c == b'\r' {
            assert_eq!(b.get(i + 1), Some(&b'\n'), "bare CR at {i}");
        }
    }
    for line in s.split("\r\n") {
        assert!(line.len() <= 998, "line of {} octets", line.len());
    }
    let head = s.split("\r\n\r\n").next().unwrap();
    assert!(
        !head.to_ascii_lowercase().contains("\nbcc:")
            && !head.to_ascii_lowercase().starts_with("bcc:")
    );
}

#[test]
fn test_text_message_golden() {
    let m = base()
        .subject("Confirm your email address")
        .unwrap()
        .text("Open this link.\nThanks")
        .unwrap()
        .date_unix(T)
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    let want = "Date: Wed, 21 Oct 2026 14:03:05 +0000\r\n\
From: Example <no-reply@example.com>\r\n\
To: user@example.org\r\n\
Subject: Confirm your email address\r\n\
Message-ID: <aaaqeayeaudaocajbifqydiob4@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 7bit\r\n\
\r\n\
Open this link.\r\nThanks";
    assert_eq!(s, want);
    assert_eq!(m.message_id(), "aaaqeayeaudaocajbifqydiob4@example.com");
    assert_eq!(
        m.headers().get("subject"),
        Some("Confirm your email address")
    );
}

#[test]
fn test_same_inputs_same_bytes() {
    let build = || {
        base()
            .subject("x")
            .unwrap()
            .text("y")
            .unwrap()
            .html("<p>y</p>")
            .unwrap()
            .build_with(&mut Counter(7), T)
            .unwrap()
    };
    assert_eq!(build().to_bytes().unwrap(), build().to_bytes().unwrap());
}

#[test]
fn test_html_is_alternative_text_first() {
    let m = base()
        .text("plain")
        .unwrap()
        .html("<p>rich</p>")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    check_wire_rules(&s);
    let ct = m.headers().get("Content-Type").unwrap();
    assert!(
        ct.starts_with("multipart/alternative; boundary=\"=_"),
        "{ct}"
    );
    let t = s.find("text/plain").unwrap();
    let h = s.find("text/html").unwrap();
    assert!(t < h);
    let boundary = ct
        .split("boundary=\"")
        .nth(1)
        .unwrap()
        .trim_end_matches('"');
    assert!(s.ends_with(&format!("--{boundary}--\r\n")));
    assert_eq!(s.matches(&format!("--{boundary}\r\n")).count(), 2);
}

#[test]
fn test_full_tree_mixed_related_alternative() {
    let m = base()
        .text("t")
        .unwrap()
        .html("<img src=\"cid:logo@example.com\">")
        .unwrap()
        .inline(Inline::new("<logo@example.com>", "image/png", vec![0x89, 0x50]).unwrap())
        .unwrap()
        .attachment(
            Attachment::new(
                "caf\u{e9} r\u{e9}sum\u{e9}.pdf",
                "application/pdf",
                vec![1u8; 200],
            )
            .unwrap(),
        )
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    check_wire_rules(&s);
    let mixed = s.find("multipart/mixed").unwrap();
    let related = s.find("multipart/related").unwrap();
    let alt = s.find("multipart/alternative").unwrap();
    assert!(mixed < related && related < alt);
    assert!(s.contains("Content-ID: <logo@example.com>"));
    assert!(s.contains("Content-Disposition: inline"));
    assert!(s.contains("filename*"), "RFC 2231 file name");
    assert!(s.is_ascii());
}

#[test]
fn test_inline_without_html_refused_and_duplicate_cid() {
    let e = base()
        .text("t")
        .unwrap()
        .inline(Inline::new("a@b", "image/png", vec![]).unwrap())
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::InlineWithoutHtml)
    ));
    let e = base()
        .inline(Inline::new("a@b", "image/png", vec![]).unwrap())
        .unwrap()
        .inline(Inline::new("<a@b>", "image/gif", vec![]).unwrap())
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::DuplicateContentId)
    ));
}

#[test]
fn test_bcc_never_serialized_but_in_envelope() {
    let m = base()
        .bcc("hidden@example.net")
        .unwrap()
        .cc("seen@example.net")
        .unwrap()
        .text("x")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    assert!(!s.contains("hidden@example.net"));
    assert!(m.headers().get("bcc").is_none());
    let env = m.envelope().unwrap();
    let rc: Vec<&str> = env.recipients().iter().map(Address::as_str).collect();
    assert_eq!(
        rc,
        ["user@example.org", "seen@example.net", "hidden@example.net"]
    );
    assert_eq!(env.return_path().unwrap().as_str(), "no-reply@example.com");
}

#[test]
fn test_bcc_only_message_has_no_to_header() {
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .bcc("b@example.org")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    assert!(!s.contains("b@example.org"));
}

#[test]
fn test_envelope_uses_sender_and_dedups() {
    let m = base()
        .sender("bounces@example.com")
        .unwrap()
        .cc("USER@example.org")
        .unwrap()
        .bcc("user@EXAMPLE.ORG")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let env = m.envelope().unwrap();
    assert_eq!(env.return_path().unwrap().as_str(), "bounces@example.com");
    assert_eq!(env.recipients().len(), 2);
}

#[test]
fn test_header_injection_refused_in_every_field() {
    let attacks = ["\r", "\n", "\r\n", "\0", "\u{85}", "\u{2028}"];
    for a in attacks {
        let evil = format!("x{a}Bcc: victim@example.net");
        assert!(Message::builder().subject(&evil).is_err(), "subject {a:?}");
        assert!(
            Message::builder()
                .from(format!("{evil} <a@example.com>").as_str())
                .is_err(),
            "from name {a:?}"
        );
        assert!(
            Message::builder()
                .to(format!("{evil} <a@example.com>").as_str())
                .is_err(),
            "to name {a:?}"
        );
        assert!(
            Message::builder().header("X-Custom", &evil).is_err(),
            "custom {a:?}"
        );
        assert!(
            Attachment::new(&evil, "text/plain", vec![]).is_err(),
            "file name {a:?}"
        );
        assert!(
            Inline::new(&format!("a{a}@b"), "image/png", vec![]).is_err(),
            "content id {a:?}"
        );
        assert!(
            Message::builder().message_id(&format!("a{a}@b")).is_err(),
            "message id {a:?}"
        );
        assert!(
            Message::builder().in_reply_to(&format!("a{a}@b")).is_err(),
            "in-reply-to {a:?}"
        );
        assert!(
            Message::builder()
                .references(&["ok@x", &format!("a{a}@b")])
                .is_err(),
            "references {a:?}"
        );
        assert!(
            Message::builder()
                .to(format!("a{a}@b.example").as_str())
                .is_err(),
            "address {a:?}"
        );
    }
}

#[test]
fn test_header_count_matches_builder_input() {
    // No input can add a header line: the output has exactly the fields the builder wrote.
    let m = base()
        .subject("a: b\tc")
        .unwrap()
        .header("X-A", "Bcc: no")
        .unwrap()
        .text("Bcc: body")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    let head = s.split("\r\n\r\n").next().unwrap();
    let fields = head
        .split("\r\n")
        .filter(|l| !l.starts_with(' ') && !l.starts_with('\t'))
        .count();
    assert_eq!(fields, m.headers().len());
}

#[test]
fn test_custom_header_names() {
    assert!(Message::builder().header("", "x").is_err());
    assert!(Message::builder().header(&"a".repeat(76), "x").is_ok());
    assert!(Message::builder().header(&"a".repeat(77), "x").is_err());
    assert!(Message::builder().header("X:Y", "x").is_err());
    assert!(Message::builder().header("X Y", "x").is_err());
    for r in [
        "From",
        "bCc",
        "Subject",
        "Content-Type",
        "content-disposition",
        "DKIM-Signature",
        "Received",
        "MIME-Version",
    ] {
        let e = Message::builder().header(r, "x").unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::Header(HeaderError::Reserved)),
            "{r}"
        );
    }
}

#[test]
fn test_custom_header_limit() {
    let mut b = Message::builder();
    for i in 0..100 {
        b = b.header(&format!("X-H{i}"), "v").unwrap();
    }
    assert!(matches!(
        b.header("X-Last", "v").unwrap_err().kind(),
        ErrorKind::Build(BuildError::TooManyHeaders)
    ));
}

#[test]
fn test_recipient_limits() {
    let mut b = Message::builder().from("a@example.com").unwrap();
    for i in 0..100 {
        b = b.to(format!("u{i}@example.org").as_str()).unwrap();
    }
    assert!(matches!(
        b.clone().bcc("x@example.org").unwrap_err().kind(),
        ErrorKind::Build(BuildError::TooManyRecipients { limit: 100 })
    ));
    assert!(b.build_with(&mut Counter(0), T).is_ok());
    assert!(matches!(
        Message::builder()
            .from("a@example.com")
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap_err()
            .kind(),
        ErrorKind::Build(BuildError::NoRecipients)
    ));
    assert!(matches!(
        Message::builder()
            .to("a@example.com")
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap_err()
            .kind(),
        ErrorKind::Build(BuildError::MissingFrom)
    ));
}

#[test]
fn test_references_limits_and_threading_headers() {
    let ids: Vec<String> = (0..51).map(|i| format!("id{i}@example.com")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert!(base().references(&refs[..50]).is_ok());
    assert!(base().references(&refs).is_err());
    let m = base()
        .in_reply_to("<parent@example.com>")
        .unwrap()
        .references(&refs[..3])
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(m.headers().get("In-Reply-To"), Some("<parent@example.com>"));
    assert_eq!(
        m.headers().get("References"),
        Some("<id0@example.com> <id1@example.com> <id2@example.com>")
    );
}

#[test]
fn test_message_id_supplied_forms() {
    let m = base()
        .message_id("<given.1@example.com>")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(m.message_id(), "given.1@example.com");
    assert!(base().message_id("given 1@example.com").is_err());
    assert!(base().message_id("a@[192.0.2.1]").is_err());
    let m = base()
        .message_id_domain("mail.example.net")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert!(m.message_id().ends_with("@mail.example.net"));
}

#[test]
fn test_message_id_never_uses_host_name_and_needs_ascii_domain() {
    let m = Message::builder()
        .from("j@b\u{fc}cher.example")
        .unwrap()
        .to("x@example.org")
        .unwrap()
        .build_with(&mut Counter(0), T);
    assert!(matches!(
        m.unwrap_err().kind(),
        ErrorKind::Header(HeaderError::InvalidMessageId)
    ));
}

#[test]
fn test_date_boundaries() {
    for (t, want) in [
        (0u64, "Thu, 01 Jan 1970 00:00:00 +0000"),
        (2_147_483_648, "Tue, 19 Jan 2038 03:14:08 +0000"),
        (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 +0000"),
    ] {
        let m = base().build_with(&mut Counter(0), t).unwrap();
        assert_eq!(m.headers().get("Date"), Some(want));
    }
    assert!(base().build_with(&mut Counter(0), 253_402_300_800).is_err());
}

#[test]
fn test_random_failure_is_an_error_never_a_fallback() {
    let e = base().build_with(&mut Failing, T).unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Random));
    assert!(e.is_temporary());
}

/// Returns the bytes that make the first boundary, then fresh bytes.
struct Collide {
    first: Option<[u8; 20]>,
    inner: Counter,
}
impl RandomSource for Collide {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() == 20 {
            if let Some(f) = self.first.take() {
                buf.copy_from_slice(&f);
                return Ok(());
            }
        }
        self.inner.fill(buf)
    }
}

#[test]
fn test_boundary_redrawn_when_content_contains_it() {
    let fixed = [9u8; 20];
    let b = id::boundary(&mut Counter(9)).unwrap();
    let _ = b;
    let colliding = id::boundary(&mut Collide {
        first: Some(fixed),
        inner: Counter(0),
    })
    .unwrap();
    let text = format!("line\n--{colliding}\nmore");
    let m = base()
        .text(&text)
        .unwrap()
        .html("<p>x</p>")
        .unwrap()
        .build_with(
            &mut Collide {
                first: Some(fixed),
                inner: Counter(0),
            },
            T,
        )
        .unwrap();
    let ct = m.headers().get("Content-Type").unwrap();
    assert!(!ct.contains(&*colliding), "boundary must be redrawn");
    let s = bytes(&m);
    check_wire_rules(&s);
}

#[test]
fn test_body_line_endings() {
    assert!(matches!(
        base().text("a\rb").unwrap_err().kind(),
        ErrorKind::Build(BuildError::BareCarriageReturn { position: 1 })
    ));
    let m = base()
        .text("a\r\nb\nc\r\n")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert!(bytes(&m).ends_with("\r\n\r\na\r\nb\r\nc\r\n"));
}

#[test]
fn test_transfer_encodings_chosen_per_part() {
    let qp = base()
        .text("caf\u{e9} au lait")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        qp.headers().get("Content-Transfer-Encoding"),
        Some("quoted-printable")
    );
    assert!(bytes(&qp).ends_with("caf=C3=A9 au lait"));
    let b64 = base()
        .text(&"\u{65e5}\u{672c}\u{8a9e}".repeat(30))
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        b64.headers().get("Content-Transfer-Encoding"),
        Some("base64")
    );
    let eight = base()
        .text("caf\u{e9}")
        .unwrap()
        .allow_8bit(true)
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        eight.headers().get("Content-Transfer-Encoding"),
        Some("8bit")
    );
    assert!(eight.has_8bit());
    let long = base()
        .text(&"x".repeat(999))
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        long.headers().get("Content-Transfer-Encoding"),
        Some("quoted-printable")
    );
    check_wire_rules(&bytes(&long));
    let dots = base()
        .text(".hidden\nFrom here\n")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        dots.headers().get("Content-Transfer-Encoding"),
        Some("7bit")
    );
}

#[test]
fn test_subject_encoding_and_lookalike() {
    let m = base()
        .subject("R\u{e9}sum\u{e9} \u{1f600}")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    let s = bytes(&m);
    assert!(s.is_ascii());
    // Mostly non-ASCII octets (the emoji is four): B, the shorter form (D-082).
    assert!(
        m.headers()
            .get("Subject")
            .unwrap()
            .starts_with("=?UTF-8?B?")
    );
    let m = base()
        .subject("=?utf-8?q?Bank_alert?=")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert!(
        m.headers()
            .get("Subject")
            .unwrap()
            .starts_with("=?UTF-8?Q?")
    );
    let m = base()
        .subject("")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(m.headers().get("Subject"), Some(""));
}

#[test]
fn test_subject_long_folds_and_unbreakable_refused() {
    let m = base()
        .subject("word ".repeat(2000).trim_end())
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    check_wire_rules(&bytes(&m));
    let e = base()
        .subject(&"x".repeat(1000))
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Header(HeaderError::LineTooLong)
    ));
}

#[test]
fn test_long_display_names_fold_and_the_payload_decodes() {
    // T-36: a display name is folded at its spaces (atoms or one quoted
    // string), or written as RFC 2047 words when a word is too long for a
    // line, so no line of From, To, or Cc passes 998 octets, and the job
    // payload of the message decodes again.
    let quoted = format!("{}x", "x, ".repeat(400));
    let atoms = "word ".repeat(300);
    let one_word = "y".repeat(1200);
    let escaped = format!("{}z", "a \\ \" b ".repeat(150));
    let unicode = format!("{}\u{e9}", "J\u{f6}rg ".repeat(200));
    for name in [
        quoted.as_str(),
        atoms.trim_end(),
        one_word.as_str(),
        escaped.as_str(),
        unicode.as_str(),
    ] {
        let mailbox = Mailbox::new(Some(name), Address::parse("a@example.com").unwrap()).unwrap();
        let m = Message::builder()
            .from(mailbox.clone())
            .unwrap()
            .to(mailbox.clone())
            .unwrap()
            .cc(mailbox.clone())
            .unwrap()
            .text("hello")
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap();
        let s = bytes(&m);
        check_wire_rules(&s);
        let payload = m.prepare().unwrap().encode();
        let back = super::prepared::PreparedMessage::decode(&payload).unwrap();
        assert_eq!(back.bytes(), s.as_bytes());
        // The unfolded To header reads back as the same mailbox.
        let to = m.headers().get("To").unwrap();
        if name.is_ascii() && name.len() < 900 {
            let parsed = Mailbox::parse(to).unwrap();
            assert_eq!(parsed.display_name(), Some(name), "{to}");
        }
        assert!(!mailbox.to_string().contains('\r'));
        assert!(!mailbox.to_string().contains('\n'));
    }
}

#[test]
fn test_display_name_over_the_header_value_budget_is_refused() {
    let name = "n ".repeat(9000);
    let e = Message::builder()
        .from(
            Mailbox::new(
                Some(name.trim_end()),
                Address::parse("a@example.com").unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
        .to("b@example.org")
        .unwrap()
        .text("hello")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::TooLarge { .. })
    ));
}

#[test]
fn test_every_utf8_width_at_every_split_in_subject() {
    for ch in ['a', '\u{e9}', '\u{20ac}', '\u{1f600}'] {
        for n in 1..40 {
            let text: String = core::iter::repeat_n(ch, n).collect();
            let m = base()
                .subject(&format!("x{text}"))
                .unwrap()
                .build_with(&mut Counter(0), T)
                .unwrap();
            let s = bytes(&m);
            for word in s
                .split(|c: char| c.is_whitespace())
                .filter(|w| w.starts_with("=?"))
            {
                assert!(word.len() <= 75);
            }
        }
    }
}

#[test]
fn test_size_limit_checked_before_encoding() {
    let limits = MessageLimits {
        max_message_size: 1000,
        ..MessageLimits::default()
    };
    let e = base()
        .limits(limits)
        .attachment(Attachment::new("a.bin", "application/octet-stream", vec![0u8; 1001]).unwrap())
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::TooLarge { .. })
    ));
    let e = base()
        .limits(limits)
        .attachment(Attachment::new("a.bin", "application/octet-stream", vec![0u8; 700]).unwrap())
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::TooLarge { .. })
    ));
}

#[test]
fn test_long_parameters_keep_header_lines_within_78_columns() {
    // RFC 2231 sections are sized to the column they start at
    // (parse-net's write_mime_param_at), so no parameter line passes 78
    // columns, whatever text was on the line before it.
    for name in [
        "Résumé et lettre de motivation pour le poste de responsable.pdf",
        "quarterly report for the northern region, final version 2026.pdf",
        &"é".repeat(120),
        "a.pdf",
    ] {
        let m = base()
            .text("see attached")
            .unwrap()
            .attachment(Attachment::new(name, "application/pdf", b"%PDF".to_vec()).unwrap())
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap();
        let s = bytes(&m);
        check_wire_rules(&s);
        for part_head in s.split("\r\n\r\n") {
            for line in part_head.split("\r\n") {
                if line.starts_with("Content-") || line.starts_with(' ') {
                    assert!(line.len() <= 78, "{} columns: {line}", line.len());
                }
            }
        }
    }
}

#[test]
fn test_attachment_edge_sizes_and_parts_limit() {
    for n in [0usize, 1, 56, 57, 58, 1024] {
        let m = base()
            .attachment(
                Attachment::new("a.bin", "application/octet-stream", vec![0xab; n]).unwrap(),
            )
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap();
        check_wire_rules(&bytes(&m));
    }
    let limits = MessageLimits {
        max_parts: 4,
        ..MessageLimits::default()
    };
    let b = base()
        .limits(limits)
        .attachment(Attachment::new("1", "text/plain", vec![]).unwrap())
        .unwrap();
    assert!(
        b.clone()
            .attachment(Attachment::new("2", "text/plain", vec![]).unwrap())
            .is_err()
    );
    assert!(b.build_with(&mut Counter(0), T).is_ok());
}

#[test]
fn test_display_names_quote_and_encode() {
    let m = Message::builder()
        .from(Mailbox::new(Some("Doe, Jane"), Address::parse("j@example.com").unwrap()).unwrap())
        .unwrap()
        .to(Mailbox::new(Some("Jos\u{e9}"), Address::parse("x@example.org").unwrap()).unwrap())
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        m.headers().get("From"),
        Some("\"Doe, Jane\" <j@example.com>")
    );
    assert_eq!(
        m.headers().get("To"),
        Some("=?UTF-8?Q?Jos=C3=A9?= <x@example.org>")
    );
}

#[test]
fn test_utf8_address_flags_smtputf8() {
    let m = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("j\u{f6}rg@example.org")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert!(m.needs_smtputf8());
    let p = m.prepare().unwrap();
    assert!(p.needs_smtputf8() && p.has_8bit());
}

#[test]
fn test_mailbox_conversions_into_builder() {
    let a = Address::parse("a@example.com").unwrap();
    assert!(Message::builder().from(a.clone()).is_ok());
    assert!(Message::builder().from(Mailbox::from(a)).is_ok());
    let e = Message::builder().from("nope").unwrap_err();
    assert!(matches!(e.kind(), ErrorKind::Address(_)));
    let _ = AddressError::Empty;
}

#[test]
fn test_write_to_sink_errors_surface() {
    struct Small(usize);
    impl Sink for Small {
        fn write(&mut self, b: &[u8]) -> Result<(), crate::error::SinkError> {
            if self.0 < b.len() {
                return Err(crate::error::SinkError::Full);
            }
            self.0 -= b.len();
            Ok(())
        }
    }
    let m = base()
        .text("hello")
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert!(m.write_to(&mut Small(10)).is_err());
    assert!(m.write_to(&mut Small(m.encoded_len() as usize)).is_ok());
}

#[cfg(feature = "std")]
#[test]
fn test_tier1_constructors() {
    let m = Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Hi",
        "Body",
    )
    .unwrap();
    assert!(m.headers().get("Date").is_some());
    assert_eq!(m.message_id().len(), 26 + 1 + "example.com".len());
    let h = Message::html("a@example.com", "b@example.org", "Hi", "<p>x</p>", "x").unwrap();
    assert!(
        h.headers()
            .get("Content-Type")
            .unwrap()
            .starts_with("multipart/alternative")
    );
    assert_ne!(
        Message::text("a@example.com", "b@example.org", "s", "b")
            .unwrap()
            .message_id(),
        m.message_id()
    );
}

#[test]
fn test_date_unix_is_used_and_offset_shown_local() {
    // Regression: 0.3.0 ignored date_unix and stamped the build time.
    let m = base().date_unix(0).build_with(&mut Counter(0), T).unwrap();
    assert_eq!(
        m.headers().get("Date"),
        Some("Thu, 01 Jan 1970 00:00:00 +0000")
    );
    let m = base()
        .date_unix_with_offset(0, 120)
        .unwrap()
        .build_with(&mut Counter(0), T)
        .unwrap();
    assert_eq!(
        m.headers().get("Date"),
        Some("Thu, 01 Jan 1970 02:00:00 +0200")
    );
    let m = base()
        .date_unix_with_offset(T, -1439)
        .unwrap()
        .build_with(&mut Counter(0), 0)
        .unwrap();
    assert!(m.headers().get("Date").unwrap().ends_with("-2359"));
    assert!(base().date_unix_with_offset(0, 1440).is_err());
    assert!(base().date_unix_with_offset(0, -1440).is_err());
}

#[test]
fn test_caller_built_tree_and_forced_encodings() {
    let tree = Part::multipart(
        Multipart::Mixed,
        vec![
            Part::text("text/plain", "hello\n").unwrap(),
            Part::binary("application/octet-stream", vec![0, 1, 2]).unwrap(),
            Part::text("text/plain", "caf\u{e9}")
                .unwrap()
                .transfer_encoding(TransferEncoding::Base64)
                .unwrap(),
        ],
    );
    let m = base().body(tree).build_with(&mut Counter(0), T).unwrap();
    let s = bytes(&m);
    check_wire_rules(&s);
    assert!(
        m.headers()
            .get("Content-Type")
            .unwrap()
            .starts_with("multipart/mixed")
    );
    assert_eq!(s.matches("Content-Transfer-Encoding: base64").count(), 2);
    assert!(
        Part::text("image/png", "x").is_err(),
        "text parts need text/*"
    );
    assert!(Part::text("text/plain", "a\rb").is_err());
    assert!(Part::binary("bad", vec![]).is_err());
    let e = Part::binary("application/pdf", vec![])
        .unwrap()
        .transfer_encoding(TransferEncoding::QuotedPrintable)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::EncodingMismatch)
    ));
    assert!(
        Part::text("text/plain", &"x".repeat(999))
            .unwrap()
            .transfer_encoding(TransferEncoding::EightBit)
            .is_err()
    );
    assert!(
        Part::text("text/plain", "caf\u{e9}")
            .unwrap()
            .transfer_encoding(TransferEncoding::EightBit)
            .is_ok()
    );
    assert!(
        Part::multipart(Multipart::Related, vec![])
            .transfer_encoding(TransferEncoding::Base64)
            .is_err()
    );
}

#[test]
fn test_caller_tree_depth_and_count_checked_at_build() {
    let mut p = Part::text("text/plain", "x").unwrap();
    for _ in 0..9 {
        p = Part::multipart(Multipart::Mixed, vec![p]);
    }
    let e = base().body(p).build_with(&mut Counter(0), T).unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::DepthExceeded)
    ));
    let many: Vec<Part> = (0..101)
        .map(|_| Part::text("text/plain", "x").unwrap())
        .collect();
    let e = base()
        .body(Part::multipart(Multipart::Mixed, many))
        .build_with(&mut Counter(0), T)
        .unwrap_err();
    assert!(matches!(
        e.kind(),
        ErrorKind::Build(BuildError::TooManyParts)
    ));
}

#[cfg(feature = "std")]
mod streamed {
    use alloc::boxed::Box;

    use super::*;
    use crate::error::SourceError;
    use crate::message::part::{Attachment, BodySource, ReadSource};

    /// Hands out `data` at most `step` octets per read.
    struct Trickle {
        data: Vec<u8>,
        at: usize,
        step: usize,
    }
    impl BodySource for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, SourceError> {
            let n = self.step.min(buf.len()).min(self.data.len() - self.at);
            buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    struct Broken;
    impl BodySource for Broken {
        fn read(&mut self, _: &mut [u8]) -> Result<usize, SourceError> {
            Err(SourceError::Failed("disk unplugged"))
        }
    }

    fn with(a: Attachment) -> Message {
        Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .text("see attached")
            .unwrap()
            .attachment(a)
            .unwrap()
            .build_with(&mut Counter(0), T)
            .unwrap()
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn test_streamed_output_matches_in_memory() {
        for n in [0, 1, 56, 57, 58, 3647, 3648, 3649, 10_000] {
            let mem = with(Attachment::new("f.bin", "application/octet-stream", data(n)).unwrap());
            for step in [1, 13, 4096] {
                let src = Trickle {
                    data: data(n),
                    at: 0,
                    step,
                };
                let a = Attachment::from_source(
                    "f.bin",
                    "application/octet-stream",
                    n as u64,
                    Box::new(src),
                )
                .unwrap();
                assert!(a.is_streamed());
                let streamed = with(a);
                assert_eq!(streamed.encoded_len(), mem.encoded_len(), "{n}");
                let bytes = streamed.to_bytes().unwrap();
                assert_eq!(bytes, mem.to_bytes().unwrap(), "{n} {step}");
                assert_eq!(bytes.len() as u64, streamed.encoded_len());
            }
        }
    }

    #[test]
    fn test_declared_length_is_exact() {
        for (declared, actual) in [(100u64, 99usize), (100, 101), (0, 1)] {
            let src = ReadSource::new(std::io::Cursor::new(data(actual)));
            let m = with(
                Attachment::from_source("f", "application/pdf", declared, Box::new(src)).unwrap(),
            );
            let e = m.to_bytes().unwrap_err();
            assert!(
                matches!(e.kind(), ErrorKind::Build(BuildError::LengthMismatch { declared: d, .. }) if *d == declared),
                "{e:?}"
            );
        }
    }

    #[test]
    fn test_source_is_read_once_and_errors_propagate() {
        let src = ReadSource::new(std::io::Cursor::new(data(10)));
        let m = with(Attachment::from_source("f", "application/pdf", 10, Box::new(src)).unwrap());
        let copy = m.clone();
        m.prepare().unwrap();
        let e = copy.prepare().unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::Source(SourceError::Consumed));
        assert!(e.is_permanent());

        let m =
            with(Attachment::from_source("f", "application/pdf", 10, Box::new(Broken)).unwrap());
        let e = m.to_bytes().unwrap_err();
        assert_eq!(
            e.kind(),
            &ErrorKind::Source(SourceError::Failed("disk unplugged"))
        );
        assert!(e.to_string().contains("disk unplugged"));
    }

    #[test]
    fn test_declared_length_counts_against_the_budget() {
        let src = ReadSource::new(std::io::Cursor::new(Vec::new()));
        let huge = Attachment::from_source("f", "application/pdf", 1 << 40, Box::new(src)).unwrap();
        let e = Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.org")
            .unwrap()
            .attachment(huge)
            .unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::Build(BuildError::TooLarge { .. })),
            "{e:?}"
        );
    }
}
