use assert_cmd::cmd::Command;
use predicates::str::contains;

mod server;

fn get_command() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("xh"));
    cmd.env("XH_TEST_MODE", "1");
    cmd.env("XH_TEST_MODE_TERM", "1");
    cmd
}

#[test]
fn message_signature_auth_with_manual_input() {
    // Ed25519 private key (32 bytes)
    // base64(0000...00) -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    let key = "IyMjc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M="; // "###777..."

    let server = server::http(|req| async move {
        assert_eq!(req.method(), "POST");
        assert!(req.headers().contains_key("Signature"));
        assert!(req.headers().contains_key("Signature-Input"));

        let sig_input = req.headers()["Signature-Input"].to_str().unwrap();
        assert!(
            sig_input.contains(r#"sig1=("@method" "@target-uri" "content-digest");alg="ed25519""#)
        );

        hyper::Response::default()
    });

    get_command()
        .arg("--auth-type=message-signature")
        .arg(format!("--auth={}", key))
        .arg("post")
        .arg(server.base_url())
        .arg("foo=bar")
        // Manually provide Signature-Input as currently required
        .arg(
            "Signature-Input:sig1=(\"@method\" \"@target-uri\" \"content-digest\");alg=\"ed25519\"",
        )
        .assert()
        .success();
}

#[test]
fn message_signature_defaults_to_ed25519() {
    let key = "IyMjc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=";
    let server = server::http(|req| async move {
        assert_eq!(req.method(), "POST");
        assert!(req.headers().contains_key("Signature"));
        assert!(req.headers().contains_key("Signature-Input"));

        let sig_input = req.headers()["Signature-Input"].to_str().unwrap();
        // Expect default generation to include content-digest because we send a body
        assert!(
            sig_input.contains(r#"sig1=("@method" "@target-uri" "content-digest");alg="ed25519""#)
        );

        hyper::Response::default()
    });

    get_command()
        .arg("--auth-type=message-signature")
        .arg(format!("--auth={}", key))
        .arg("post")
        .arg(server.base_url())
        .arg("foo=bar")
        .assert()
        .success();
}
