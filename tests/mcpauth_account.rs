#![cfg(feature = "mcp")]

use porte::mcpauth::{NoAccount, account_exists};
use tronc::mcp::TokenInfo;

#[tokio::test]
async fn account_exists_reads_the_tokens_account() {
    let lookup = |user_id: i64| async move {
        match user_id {
            7 => Ok("seven"),
            _ => Err("no such user"),
        }
    };
    let info = |user_id: &str| TokenInfo { user_id: user_id.into(), ..TokenInfo::default() };
    assert_eq!(account_exists(Some(&info("7")), lookup).await.unwrap(), "seven");
    for (name, refused) in [
        ("no user id", Some(info(""))),
        ("not a number", Some(info("x"))),
        ("a deleted account", Some(info("8"))),
        ("no info", None),
    ] {
        let error: NoAccount = account_exists(refused.as_ref(), lookup).await.unwrap_err();
        assert!(error.to_string().starts_with("porte/mcpauth: the token names no account"), "{name}: {error}");
    }
    let gone = account_exists(Some(&info("8")), lookup).await.unwrap_err();
    assert_eq!(gone.to_string(), "porte/mcpauth: the token names no account: no such user");
    assert!(std::error::Error::source(&gone).is_some(), "the lookup's error is not the source");
}
