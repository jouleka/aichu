// aichu — CLI entry point.
//
// The `aichu` binary wires together the per-user CA directory, the redaction
// pipeline (`proxy-core`), and the Hudsucker MITM proxy (`proxy-mitm`).
//
// v0 surface:
//   - `aichu` / `aichu run`   — start the proxy (default)
//   - `aichu trust`           — install the local CA into the macOS System keychain
//   - `aichu untrust`         — remove the local CA from the macOS System keychain
//
// `aichu doctor` lands in a follow-up slice. Subcommands are NEVER stubbed —
// no speculative code (CLAUDE.md Rule 2).

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Local HTTPS proxy that redacts secrets from prompts sent to AI coding
/// agents, then restores them in responses.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Start the proxy on 127.0.0.1:8788 (default if no subcommand given).
    Run,
    /// Install the local CA into the macOS System keychain (requires sudo).
    Trust,
    /// Remove the local CA from the macOS System keychain (requires sudo).
    Untrust,
}

impl Cli {
    /// Resolve the user-issued subcommand, defaulting to `Run` when none
    /// was given. Centralizing the default here means tests can assert
    /// the defaulting policy without re-parsing argv shapes.
    fn command(&self) -> Commands {
        self.command.clone().unwrap_or(Commands::Run)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command() {
        Commands::Run => run().await,
        Commands::Trust => handle_trust(),
        Commands::Untrust => handle_untrust(),
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
}

/// Spin up the MITM proxy on `127.0.0.1:8788`, persisting the CA under
/// `$HOME/.aichu/ca/` (or `%USERPROFILE%\.aichu\ca\` on Windows). Runs
/// until the user sends SIGINT (Ctrl-C).
///
/// The bind address and CA path are intentionally hardcoded for v0.
/// They will become flags only when there is observed user demand —
/// premature flags become permanent surface area.
async fn run() -> Result<()> {
    let ca_dir = ca_dir()?;

    // `load_or_create_ca` is responsible for creating `ca_dir` on first
    // run; no need to pre-create it here.
    let ca = proxy_mitm::ca::load_or_create_ca(&ca_dir)?;
    let cert_path = ca_dir.join(proxy_mitm::ca::CERT_FILENAME);
    tracing::info!(
        "CA ready — public cert at {} (install with `aichu trust`)",
        cert_path.display()
    );

    let addr: SocketAddr = "127.0.0.1:8788".parse().expect("hardcoded addr parses");
    let handler = proxy_mitm::handler::AichuHandler::new();

    tracing::info!(%addr, "proxy listening — Ctrl-C to stop");
    proxy_mitm::run_proxy(addr, ca.authority, handler, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Resolve `~/.aichu/ca/`, the directory holding the CA cert + key.
fn ca_dir() -> Result<PathBuf> {
    Ok(default_aichu_dir()?.join("ca"))
}

/// macOS system root keychain. The `-d` flag of `add-trusted-cert` and the
/// final positional arg of `delete-certificate` both expect this exact path.
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Install the CA cert into the macOS System keychain as a root-trusted
/// certificate. Wraps `sudo security add-trusted-cert -d -r trustRoot -k <kc>
/// <cert>`; the user is expected to authenticate via sudo's TTY prompt.
#[cfg(target_os = "macos")]
fn handle_trust() -> Result<()> {
    let cert_path = ca_dir()?.join(proxy_mitm::ca::CERT_FILENAME);
    if !cert_path.exists() {
        anyhow::bail!(
            "CA not generated yet — run `aichu run` once to create it at {}, \
             then re-run `aichu trust`",
            cert_path.display()
        );
    }
    let mut cmd = trust_command(&cert_path, Path::new(MACOS_SYSTEM_KEYCHAIN));
    tracing::info!(
        "installing CA — sudo will prompt for your login password (cert: {})",
        cert_path.display()
    );
    run_or_bail(&mut cmd, "trust install")?;
    tracing::info!("CA installed into the macOS System keychain ✓");
    Ok(())
}

/// Remove the CA cert from the macOS System keychain. Identifies the cert
/// by its Common Name (`proxy_mitm::ca::COMMON_NAME`) — the local PEM file
/// is not consulted, so `aichu untrust` works even after the user has
/// nuked `~/.aichu/`.
#[cfg(target_os = "macos")]
fn handle_untrust() -> Result<()> {
    let mut cmd = untrust_command(proxy_mitm::ca::COMMON_NAME, Path::new(MACOS_SYSTEM_KEYCHAIN));
    tracing::info!(
        "removing CA \"{}\" — sudo will prompt for your login password",
        proxy_mitm::ca::COMMON_NAME
    );
    run_or_bail(&mut cmd, "trust removal")?;
    tracing::info!("CA removed from the macOS System keychain ✓");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn handle_trust() -> Result<()> {
    anyhow::bail!(
        "`aichu trust` is macOS-only in v0; for Linux/Windows, install \
         `~/.aichu/ca/aichu-ca.pem` into your platform's root store manually"
    )
}

#[cfg(not(target_os = "macos"))]
fn handle_untrust() -> Result<()> {
    anyhow::bail!(
        "`aichu untrust` is macOS-only in v0; remove the CA manually from \
         your platform's root store"
    )
}

/// Build `sudo security add-trusted-cert -d -r trustRoot -k <keychain> <cert>`.
/// Pure builder so unit tests can verify the exact argv shape without
/// actually invoking `sudo` (which is destructive and requires a TTY).
///
/// Compiles on every target so the argv-shape tests run cross-platform,
/// but is dead code anywhere `handle_trust` short-circuits before reaching
/// it — hence the `cfg_attr(allow(dead_code))` on non-macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn trust_command(cert_path: &Path, keychain: &Path) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("security")
        .arg("add-trusted-cert")
        .arg("-d")
        .arg("-r")
        .arg("trustRoot")
        .arg("-k")
        .arg(keychain)
        .arg(cert_path);
    cmd
}

/// Build `sudo security delete-certificate -c <common_name> <keychain>`.
/// See `trust_command` doc for the testability + dead-code rationale.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn untrust_command(common_name: &str, keychain: &Path) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("security")
        .arg("delete-certificate")
        .arg("-c")
        .arg(common_name)
        .arg(keychain);
    cmd
}

/// Spawn a `Command` synchronously, bail with the original exit code if it
/// fails. Centralized so trust + untrust report errors the same way.
#[cfg(target_os = "macos")]
fn run_or_bail(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("invoke `sudo` for {what}"))?;
    if !status.success() {
        // `security(1)` inherits our stdio, so its own error has already
        // printed to the user's terminal above this bail message — point
        // them there rather than promising tracing detail we don't have.
        anyhow::bail!(
            "{what} failed (exit code {:?}); see `security` output above for the cause",
            status.code()
        );
    }
    Ok(())
}

/// Default aichu data directory: `$HOME/.aichu` on Unix, `%USERPROFILE%\.aichu`
/// on Windows. Self-contained, easy to nuke (`rm -rf ~/.aichu`).
fn default_aichu_dir() -> Result<PathBuf> {
    aichu_dir_from(|k| std::env::var_os(k))
}

/// Pure helper backing `default_aichu_dir`. The `env` closure is the only
/// dependency on process state, so unit tests can inject deterministic
/// HOME/USERPROFILE values without racing the global env table.
fn aichu_dir_from<F>(env: F) -> Result<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    let home = env("HOME")
        .or_else(|| env("USERPROFILE"))
        .context("could not resolve home directory (neither HOME nor USERPROFILE is set)")?;
    Ok(PathBuf::from(home).join(".aichu"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_defaults_to_run() {
        let cli = Cli::parse_from(["aichu"]);
        assert!(matches!(cli.command(), Commands::Run));
    }

    #[test]
    fn explicit_run_subcommand_resolves_to_run() {
        let cli = Cli::parse_from(["aichu", "run"]);
        assert!(matches!(cli.command(), Commands::Run));
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        // Locks the contract: typos in subcommand names must fail loudly,
        // not silently fall through to the default. Surfaces a future
        // regression where `Option<Commands>` swallows clap's error.
        let result = Cli::try_parse_from(["aichu", "doctor"]);
        assert!(
            result.is_err(),
            "expected `aichu doctor` to error (subcommand not yet implemented)"
        );
    }

    #[test]
    fn aichu_dir_uses_home_when_set() {
        let path = aichu_dir_from(|k| match k {
            "HOME" => Some("/tmp/fake-home".into()),
            _ => None,
        })
        .expect("HOME set should resolve");
        assert_eq!(path, PathBuf::from("/tmp/fake-home/.aichu"));
    }

    #[test]
    fn aichu_dir_prefers_home_over_userprofile_when_both_set() {
        // Locks Unix-first priority: HOME is consulted before USERPROFILE.
        // A future refactor that swaps `.or_else` order would break Unix
        // users silently without this test.
        let path = aichu_dir_from(|k| match k {
            "HOME" => Some("/from-home".into()),
            "USERPROFILE" => Some("/from-userprofile".into()),
            _ => None,
        })
        .expect("HOME set should resolve");
        assert_eq!(path, PathBuf::from("/from-home/.aichu"));
    }

    #[test]
    fn aichu_dir_falls_back_to_userprofile_when_home_absent() {
        // Path string is intentionally separator-neutral: the contract under
        // test is "USERPROFILE is the fallback when HOME is missing, and
        // `.aichu` is appended". The host OS's path separator is irrelevant
        // to that contract, and asserting a Windows-y `C:\` literal would
        // break on Unix where `\` is not a path separator.
        let path = aichu_dir_from(|k| match k {
            "USERPROFILE" => Some("/some/user/home".into()),
            _ => None,
        })
        .expect("USERPROFILE set should resolve");
        assert_eq!(path, PathBuf::from("/some/user/home/.aichu"));
    }

    #[test]
    fn aichu_dir_errors_when_neither_env_is_set() {
        // Fail loud — silent fallback to `/.aichu` or `cwd/.aichu` would
        // hide a misconfigured environment from the user (Rule 12).
        let result = aichu_dir_from(|_| None);
        assert!(result.is_err());
    }

    #[test]
    fn trust_command_builds_macos_security_invocation() {
        // Pin the exact `sudo security add-trusted-cert ...` shape that's
        // documented as the manual install in the e01 README. Drift here
        // would break the install UX silently — the surfacing failure
        // would only happen at sudo invocation time on real macOS.
        let cmd = trust_command(
            Path::new("/some/ca/aichu-ca.pem"),
            Path::new("/Library/Keychains/System.keychain"),
        );
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(
            args,
            vec![
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                "/some/ca/aichu-ca.pem",
            ]
        );
    }

    #[test]
    fn untrust_command_identifies_cert_by_common_name() {
        // The `-c <CN>` form (not `-Z <SHA1>`) is deliberate: it lets the
        // user run `aichu untrust` even after `rm -rf ~/.aichu` — only the
        // CN matters, not the on-disk cert. Locking the args also catches
        // drift from a future refactor that switches to SHA1-based ID.
        let cmd = untrust_command(
            proxy_mitm::ca::COMMON_NAME,
            Path::new("/Library/Keychains/System.keychain"),
        );
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(
            args,
            vec![
                "security",
                "delete-certificate",
                "-c",
                "aichu local proxy CA",
                "/Library/Keychains/System.keychain",
            ]
        );
    }

    #[test]
    fn untrust_command_threads_common_name_through_unchanged() {
        // Guard against any future "normalize this string" reflex on the
        // CN — `security delete-certificate` matches the CN literally,
        // including spaces and case. Any transformation here would orphan
        // installs that used the original CN.
        let cmd = untrust_command(
            "weird CN with spaces & symbols!",
            Path::new("/Library/Keychains/System.keychain"),
        );
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(args[2], "-c");
        assert_eq!(args[3], "weird CN with spaces & symbols!");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn handle_trust_returns_unsupported_on_non_macos() {
        // The non-macOS error must name the platform constraint so users
        // know it's deliberate, not a missing dependency. Compare-by-
        // substring is intentionally loose to allow message tweaks.
        let err = handle_trust().expect_err("non-macOS trust should error");
        let msg = err.to_string();
        assert!(
            msg.contains("macOS"),
            "non-macOS trust error should mention macOS: {msg}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn handle_untrust_returns_unsupported_on_non_macos() {
        let err = handle_untrust().expect_err("non-macOS untrust should error");
        let msg = err.to_string();
        assert!(
            msg.contains("macOS"),
            "non-macOS untrust error should mention macOS: {msg}"
        );
    }
}
