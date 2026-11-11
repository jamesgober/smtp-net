//! Every conversation in `tests/transcripts/` runs against a fresh session,
//! whole and with server and client bytes split into pieces of 1 to 16 octets.
//!
//! Header comments in each file configure the run:
//! `# config:` (`loopback`, `remote-plain`, `starttls`, `implicit`, `policy-all`,
//! `no-pipelining`, `no-chunking`, `auth`, `auth-login`, `xoauth2`, `scram`
//! (RFC 7677's example; skipped without the `scram` feature)), `# envelope:` (recipients), `# raw: 8bit`, `# messages:`
//! (how many copies to send), `# expect:` (`ok`, `temp`, or `perm` per
//! message), and `# closed:` (`none`, or `temp`/`perm` with `possibly` and
//! `security`).

use std::{fs, path::Path};

use smtp_net::protocol::{Auth, MechanismList, Millis, Session, SessionConfig, SessionSecurity};
use smtp_net::testing::{ScriptedServer, Transcript};
use smtp_net::{
    Address, Credentials, Dsn, DsnNotify, DsnPolicy, DsnReturn, Envelope, MechanismName,
    PreparedMessage, RecipientPolicy,
};

struct Case {
    name: String,
    text: String,
    config: SessionConfig,
    messages: Vec<PreparedMessage>,
    expect: Vec<String>,
    closed: Vec<String>,
}

fn header<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| {
        l.strip_prefix("# ")
            .and_then(|l| l.strip_prefix(key))
            .map(str::trim)
    })
}

/// The case, or `None` when it needs a feature this build does not have.
fn load(path: &Path) -> Option<Case> {
    let text = fs::read_to_string(path).unwrap();
    let mut config = SessionConfig::default();
    for word in header(&text, "config:")
        .unwrap_or("loopback")
        .split_whitespace()
    {
        match word {
            "loopback" => {
                config.security = SessionSecurity::Plaintext {
                    peer_is_loopback: true,
                }
            }
            "remote-plain" => {
                config.security = SessionSecurity::Plaintext {
                    peer_is_loopback: false,
                }
            }
            "starttls" => config.security = SessionSecurity::StartTlsRequired,
            "implicit" => config.security = SessionSecurity::ImplicitTls,
            "policy-all" => config.recipient_policy = RecipientPolicy::All,
            "no-pipelining" => config.pipelining = false,
            "no-chunking" => config.chunking = false,
            "auth" => config.auth = Some(Auth::new(Credentials::password("user", "pass"))),
            "auth-login" => {
                config.auth = Some(
                    Auth::new(Credentials::password("user", "pass"))
                        .mechanisms(MechanismList::new(&[MechanismName::Login]).unwrap()),
                );
            }
            "xoauth2" => {
                config.auth = Some(Auth::new(Credentials::oauth2(
                    "someuser@example.com",
                    "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg",
                )));
            }
            #[cfg(feature = "scram")]
            "scram" => {
                // RFC 7677 section 3.
                config.auth = Some(
                    Auth::new(Credentials::password("user", "pencil"))
                        .mechanisms(MechanismList::new(&[MechanismName::ScramSha256]).unwrap())
                        .scram_nonce("rOprNGfwEbeRWgbNEkqO")
                        .unwrap(),
                );
            }
            #[cfg(not(feature = "scram"))]
            "scram" => return None,
            other => panic!("{}: unknown config {other}", path.display()),
        }
    }
    let recipients: Vec<Address> = header(&text, "envelope:")
        .unwrap_or("b@example.org")
        .split(',')
        .map(|r| Address::parse(r.trim()).unwrap())
        .collect();
    let mut envelope = if header(&text, "from:") == Some("<>") {
        Envelope::null_sender(&recipients).unwrap()
    } else {
        Envelope::new(Address::parse("a@example.com").unwrap(), &recipients).unwrap()
    };
    if let Some(spec) = header(&text, "dsn:") {
        let mut words = spec.split_whitespace();
        let notify = words
            .next()
            .unwrap_or("never")
            .split(',')
            .fold(DsnNotify::NEVER, |n, w| match w {
                "success" => n | DsnNotify::SUCCESS,
                "failure" => n | DsnNotify::FAILURE,
                "delay" => n | DsnNotify::DELAY,
                _ => n,
            });
        let mut dsn = Dsn::new(notify);
        for w in words {
            match w {
                "hdrs" => dsn = dsn.with_return_content(DsnReturn::Headers),
                "full" => dsn = dsn.with_return_content(DsnReturn::Full),
                "required" => dsn = dsn.with_policy(DsnPolicy::Required),
                other => {
                    dsn = dsn
                        .with_envelope_id(other.strip_prefix("envid=").unwrap())
                        .unwrap()
                }
            }
        }
        envelope = envelope.with_dsn(dsn);
    }
    let body: &[u8] = if header(&text, "raw:") == Some("8bit") {
        b"caf\xc3\xa9\r\n"
    } else {
        b"hello!\r\n"
    };
    let raw = [&b"From: a@example.com\r\nSubject: t\r\n\r\n"[..], body].concat();
    let count: usize = header(&text, "messages:").map_or(1, |n| n.parse().unwrap());
    let messages = (0..count)
        .map(|_| PreparedMessage::from_raw(envelope.clone(), raw.clone()).unwrap())
        .collect();
    let words = |k| {
        header(&text, k)
            .unwrap_or("")
            .split_whitespace()
            .map(String::from)
            .collect::<Vec<_>>()
    };
    Some(Case {
        name: path.file_name().unwrap().to_string_lossy().into_owned(),
        expect: words("expect:"),
        closed: words("closed:"),
        text,
        config,
        messages,
    })
}

fn check(case: &Case, split: usize) {
    let transcript = Transcript::parse(&case.text).unwrap();
    let mut session = Session::new(case.config.clone(), Millis(0)).unwrap();
    let outcome = ScriptedServer::new(transcript)
        .run_split(&mut session, &case.messages, split)
        .unwrap_or_else(|m| panic!("{} split {split}: {m}", case.name));
    let got: Vec<&str> = outcome
        .messages
        .iter()
        .map(|r| match r {
            Ok(()) => "ok",
            Err(e) if e.is_temporary() => "temp",
            Err(_) => "perm",
        })
        .collect();
    assert_eq!(
        got, case.expect,
        "{} split {split}: {:?}",
        case.name, outcome.messages
    );
    match (&outcome.closed, case.closed.first().map(String::as_str)) {
        (None, Some("none") | None) => {}
        (Some(e), Some(want @ ("temp" | "perm"))) => {
            assert_eq!(
                e.is_temporary(),
                want == "temp",
                "{} split {split}: {e:?}",
                case.name
            );
            let possibly = case.closed.iter().any(|w| w == "possibly");
            assert_eq!(
                e.possibly_delivered(),
                possibly,
                "{} split {split}: {e:?}",
                case.name
            );
            let security = case.closed.iter().any(|w| w == "security");
            assert_eq!(
                e.is_security_event(),
                security,
                "{} split {split}: {e:?}",
                case.name
            );
        }
        (got, want) => panic!(
            "{} split {split}: closed {got:?}, expected {want:?}",
            case.name
        ),
    }
}

#[test]
fn test_every_transcript_whole_and_split() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/transcripts");
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    assert!(paths.len() >= 30, "transcripts missing");
    for path in paths {
        let Some(case) = load(&path) else {
            continue;
        };
        check(&case, usize::MAX);
        for split in 1..=16 {
            check(&case, split);
        }
    }
}
