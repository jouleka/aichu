// aichu — CLI entry point.
//
// The `aichu` binary wires together the per-user CA directory, the redaction
// pipeline (`proxy-core`), and the Hudsucker MITM proxy (`proxy-mitm`).
//
// v0 surface: `aichu run` (default) starts the proxy. Subsequent slices add
// `aichu trust` / `aichu untrust` / `aichu doctor`. They are intentionally
// NOT stubbed here — no speculative code (CLAUDE.md Rule 2).

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    let aichu_dir = default_aichu_dir()?;
    let ca_dir = aichu_dir.join("ca");

    // `load_or_create_ca` is responsible for creating `ca_dir` on first
    // run; no need to pre-create it here.
    let ca = proxy_mitm::ca::load_or_create_ca(&ca_dir)?;
    let cert_path = ca_dir.join("aichu-ca.pem");
    tracing::info!(
        "CA ready — public cert at {} (install with `aichu trust` in an upcoming release)",
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
}
