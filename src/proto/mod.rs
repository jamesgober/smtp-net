//! The sans-IO protocol core: replies, capabilities, commands, dot-stuffing,
//! and the session state machine.

mod capability;
mod classify;
pub(crate) mod command;
mod reply;
mod sasl;
#[cfg(feature = "scram")]
mod scram;
mod session;
mod stuff;
mod timeouts;

pub use capability::Capabilities;
pub use command::{ClientName, MAX_COMMAND_LINE, MAX_TEXT_LINE};
pub use reply::{EnhancedCode, Reply, ReplyCode, ReplyLimits, ReplyParser, TextLossy};
pub use sasl::{
    Auth, Credentials, CustomMechanism, MAX_AUTH_LINE, Mechanism, MechanismList, MechanismName,
    SaslError, Secret, Step,
};
pub use session::{
    BodyFlags, Event, RecipientPolicy, Session, SessionConfig, SessionSecurity, SessionState,
    TlsInfo, TlsProtocol,
};
pub use timeouts::{Millis, Timeouts};
