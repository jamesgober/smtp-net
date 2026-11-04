//! Reply and failure classification (PLAN 7.7).

use super::{Reply, ReplyCode};
use crate::error::{Disposition, Error, ErrorKind, Stage};

/// The disposition of a refusal by its code: `4yz` temporary, everything
/// else permanent.
pub(crate) fn rejected_disposition(code: ReplyCode) -> Disposition {
    if code.is_transient() {
        Disposition::Temporary
    } else {
        Disposition::Permanent
    }
}

/// The error for a refusal at `stage`.
pub(crate) fn reply_error(stage: Stage, reply: Reply) -> Error {
    let disposition = rejected_disposition(reply.code());
    Error::new(ErrorKind::Rejected)
        .at(stage)
        .with_disposition(disposition)
        .with_reply(reply)
}

/// The error for a refused AUTH (PLAN 7.7): `454` temporary; `432` (password
/// transition needed) permanent, since an operator must act; any other `4yz`
/// temporary; everything else permanent.
pub(crate) fn auth_error(reply: Reply) -> Error {
    let code = reply.code().get();
    let disposition = if code == 432 || !reply.code().is_transient() {
        Disposition::Permanent
    } else {
        Disposition::Temporary
    };
    Error::new(ErrorKind::AuthFailed)
        .at(Stage::Auth)
        .with_disposition(disposition)
        .with_reply(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(code: u16) -> Reply {
        Reply::synthetic(ReplyCode::new(code).unwrap(), b"x")
    }

    #[test]
    fn test_classification_by_code_class() {
        assert!(reply_error(Stage::Greeting, r(421)).is_temporary());
        assert!(reply_error(Stage::Greeting, r(554)).is_permanent());
        assert!(reply_error(Stage::StartTls, r(454)).is_temporary());
        assert!(reply_error(Stage::StartTls, r(501)).is_permanent());
        assert!(reply_error(Stage::Mail, r(451)).is_temporary());
        assert!(reply_error(Stage::Mail, r(550)).is_permanent());
        assert!(reply_error(Stage::DataEnd, r(452)).is_temporary());
        assert!(reply_error(Stage::DataEnd, r(554)).is_permanent());
        assert_eq!(
            reply_error(Stage::Rcpt, r(550))
                .reply()
                .unwrap()
                .code()
                .get(),
            550
        );
    }
}
