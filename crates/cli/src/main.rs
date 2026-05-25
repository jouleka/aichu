// aichu — CLI entry point.
//
// The `aichu` binary wires together the per-user CA directory, the redaction
// pipeline (`proxy-core`), and the Hudsucker MITM proxy (`proxy-mitm`).
//
// v0 surface:
//   - `aichu` / `aichu run`   — start the proxy (default)
//   - `aichu trust`           — install the local CA into the OS trust store
//   - `aichu untrust`         — remove the local CA from the OS trust store
//   - `aichu doctor`          — diagnose common setup issues
//
// Trust automation is implemented for macOS (System keychain) and
// Linux (Debian-family via `/usr/local/share/ca-certificates/`, Red Hat-
// family via `/etc/pki/ca-trust/source/anchors/`, Arch-family via
// `/etc/ca-certificates/trust-source/anchors/`); other OSes get a bail
// with manual instructions.
//
// Subcommands are NEVER stubbed — no speculative code (CLAUDE.md Rule 2).

use std::ffi::OsString;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
    /// `--no-system-prompt` disables the preserve-tokens system prompt
    /// the proxy normally injects into forwarded prompt-endpoint
    /// bodies (default ON; the e03 eval measured it lifts secret-
    /// placeholder echo accuracy from 12% to 96% on gpt-5-mini).
    Run(RunArgs),
    /// Install the local CA into the OS trust store (macOS System keychain
    /// or Linux: Debian/Red Hat/Arch families; requires sudo).
    Trust,
    /// Remove the local CA from the OS trust store (macOS or Linux:
    /// Debian/Red Hat/Arch families; requires sudo).
    Untrust,
    /// Diagnose common setup issues (CA presence, trust-store install, HTTPS_PROXY, port).
    Doctor,
}

/// Arguments to `aichu run`. Kept as its own struct so clap can
/// surface defaults and the long-form help nicely, and so the unit
/// test that pins flag parsing can construct the args directly.
#[derive(clap::Args, Debug, Clone)]
struct RunArgs {
    /// Disable the preserve-tokens system prompt the proxy normally
    /// prepends to forwarded prompt-endpoint requests. The prompt
    /// tells the model to echo `«SECRET_TYPE_NNN»` placeholders
    /// verbatim so the response-side reverse pass can restore the
    /// original secrets — disabling it brings back the model-
    /// dependent behavior the e03 eval measured at as low as 12%
    /// preservation on gpt-5-mini.
    #[arg(long, default_value_t = false)]
    no_system_prompt: bool,
}

impl Cli {
    /// Resolve the user-issued subcommand, defaulting to `Run` (with
    /// default `RunArgs`) when none was given. Centralizing the default
    /// here means tests can assert the defaulting policy without
    /// re-parsing argv shapes.
    fn command(&self) -> Commands {
        self.command
            .clone()
            .unwrap_or(Commands::Run(RunArgs { no_system_prompt: false }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command() {
        Commands::Run(args) => run(args).await,
        Commands::Trust => handle_trust(),
        Commands::Untrust => handle_untrust(),
        Commands::Doctor => handle_doctor(),
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
async fn run(args: RunArgs) -> Result<()> {
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
    // `--no-system-prompt` flips the default-ON injection off. The
    // negation is at the flag layer (clap), not here — `args.no_system_prompt`
    // arrives as the user's literal intent, and we invert it once
    // when constructing the handler.
    let inject_system_prompt = !args.no_system_prompt;
    let handler = proxy_mitm::handler::AichuHandler::new()
        .with_inject_system_prompt(inject_system_prompt);
    if !inject_system_prompt {
        tracing::info!(
            "preserve-tokens system prompt injection disabled (--no-system-prompt)",
        );
    }

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

// ---- Linux trust automation (Debian-family only, v0) ---------------------

/// On Debian-family distros, certs in this directory are picked up by
/// `update-ca-certificates` and concatenated into the system bundle at
/// `/etc/ssl/certs/ca-certificates.crt`. `.crt` extension is mandatory
/// (the Debian update tool ignores other extensions in this dir).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_DEBIAN_CERT_DEST: &str = "/usr/local/share/ca-certificates/aichu-ca.crt";

/// Path consulted to detect whether we're on a Debian-family distro.
/// Shipped by the mandatory `base-files` package on Debian, Ubuntu,
/// Mint, Pop!_OS, Kali, Raspberry Pi OS, elementary, Zorin, MX,
/// antiX, Deepin, Parrot, Devuan, PureOS. No known non-Debian distro
/// ships this file.
///
/// Compiled on every target so the `is_debian_family` unit tests can
/// run cross-OS; only the Linux handlers actually read it at runtime.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_DEBIAN_SENTINEL: &str = "/etc/debian_version";

/// On Red Hat-family distros (RHEL, Fedora, CentOS, Rocky, AlmaLinux),
/// certs in `/etc/pki/ca-trust/source/anchors/` are picked up by
/// `update-ca-trust` and consolidated into the system bundles at
/// `/etc/pki/ca-trust/extracted/`. `.crt` extension is conventional
/// (`update-ca-trust` accepts other extensions too, but `.crt` is
/// what every guide and existing distro cert uses).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_REDHAT_CERT_DEST: &str = "/etc/pki/ca-trust/source/anchors/aichu-ca.crt";

/// On Arch-family distros, certs in `/etc/ca-certificates/trust-source/anchors/`
/// are picked up by `trust extract-compat` (from p11-kit, which Arch
/// ships in the `base` group) and merged into
/// `/etc/ssl/certs/ca-certificates.crt`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_ARCH_CERT_DEST: &str = "/etc/ca-certificates/trust-source/anchors/aichu-ca.crt";

/// Path consulted to learn the distro family on non-Debian Linux. The
/// freedesktop.org standard (`os-release(5)`) — shipped by every
/// modern systemd-using distro, which is the entire Fedora/Arch
/// universe we care about here.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const LINUX_OS_RELEASE: &str = "/etc/os-release";

/// The non-Debian Linux distro families we automate trust install for.
/// Kept as an enum (rather than a string ID) so the `match` in
/// `linux_family_install_path` is exhaustive — adding a future family
/// without wiring up its install path becomes a compile error.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxFamily {
    /// RHEL, Fedora, CentOS, Rocky, AlmaLinux — anything that ships
    /// `update-ca-trust` and the `/etc/pki/ca-trust/source/anchors/`
    /// layout.
    RedHat,
    /// Arch, Manjaro, EndeavourOS — anything that ships
    /// `trust extract-compat` (p11-kit) and the
    /// `/etc/ca-certificates/trust-source/anchors/` layout.
    Arch,
}

#[cfg(target_os = "linux")]
fn handle_trust() -> Result<()> {
    let cert_src = ca_dir()?.join(proxy_mitm::ca::CERT_FILENAME);
    if !cert_src.exists() {
        anyhow::bail!(
            "CA not generated yet — run `aichu run` once to create it at {}, \
             then re-run `aichu trust`",
            cert_src.display()
        );
    }

    // Debian-family kept on the sentinel-file check for stability (Rule
    // 3 — don't refactor what isn't broken). RH/Arch families come from
    // `/etc/os-release` (freedesktop.org standard); see
    // `linux_family_from_os_release` for the rationale.
    if is_debian_family(|p| Path::new(p).exists()) {
        let dest = Path::new(LINUX_DEBIAN_CERT_DEST);
        let mut cp = linux_trust_copy_command(&cert_src, dest);
        tracing::info!(
            "copying CA into the system trust source — sudo will prompt for your password (src: {})",
            cert_src.display()
        );
        run_or_bail(&mut cp, "CA copy")?;
        let mut upd = linux_trust_update_command();
        tracing::info!("rebuilding system trust bundle (update-ca-certificates)...");
        run_or_bail(&mut upd, "trust update")?;
        tracing::info!("CA installed into the system trust store ✓");
        return Ok(());
    }

    let family = read_os_release()
        .as_deref()
        .and_then(linux_family_from_os_release);
    match family {
        Some(fam) => {
            let dest_str = linux_family_install_path(fam);
            let dest = Path::new(dest_str);
            let mut cp = linux_trust_copy_command(&cert_src, dest);
            tracing::info!(
                "copying CA into the system trust source — sudo will prompt for your password (src: {})",
                cert_src.display()
            );
            run_or_bail(&mut cp, "CA copy")?;
            let mut upd = linux_family_refresh_command(fam);
            tracing::info!("rebuilding system trust bundle ({})...", linux_family_refresh_label(fam));
            run_or_bail(&mut upd, "trust update")?;
            tracing::info!("CA installed into the system trust store ✓");
            Ok(())
        }
        None => anyhow::bail!(
            "`aichu trust` on Linux supports Debian-family, Red Hat-family, \
             and Arch-family distros. Could not determine your distro family \
             from `/etc/os-release`. Copy {} into your distro's trust-anchor \
             directory and run the appropriate update command manually \
             (e.g. `update-ca-trust`, `trust extract-compat`, `trust anchor`).",
            cert_src.display()
        ),
    }
}

#[cfg(target_os = "linux")]
fn handle_untrust() -> Result<()> {
    if is_debian_family(|p| Path::new(p).exists()) {
        let dest = Path::new(LINUX_DEBIAN_CERT_DEST);
        let mut rm = linux_untrust_remove_command(dest);
        tracing::info!(
            "removing CA from {} — sudo will prompt for your password",
            LINUX_DEBIAN_CERT_DEST
        );
        run_or_bail(&mut rm, "CA removal")?;
        let mut upd = linux_trust_update_command();
        tracing::info!("rebuilding system trust bundle (update-ca-certificates)...");
        run_or_bail(&mut upd, "trust update")?;
        tracing::info!("CA removed from the system trust store ✓");
        return Ok(());
    }

    let family = read_os_release()
        .as_deref()
        .and_then(linux_family_from_os_release);
    match family {
        Some(fam) => {
            let dest_str = linux_family_install_path(fam);
            let dest = Path::new(dest_str);
            let mut rm = linux_untrust_remove_command(dest);
            tracing::info!(
                "removing CA from {} — sudo will prompt for your password",
                dest_str
            );
            run_or_bail(&mut rm, "CA removal")?;
            let mut upd = linux_family_refresh_command(fam);
            tracing::info!("rebuilding system trust bundle ({})...", linux_family_refresh_label(fam));
            run_or_bail(&mut upd, "trust update")?;
            tracing::info!("CA removed from the system trust store ✓");
            Ok(())
        }
        None => anyhow::bail!(
            "`aichu untrust` on Linux supports Debian-family, Red Hat-family, \
             and Arch-family distros. Could not determine your distro family \
             from `/etc/os-release`. Remove the CA manually and re-run your \
             distro's trust-update command."
        ),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn handle_trust() -> Result<()> {
    anyhow::bail!(
        "`aichu trust` is macOS- and Linux-only in v0. On Windows, install \
         `~/.aichu/ca/aichu-ca.pem` into the Local Machine \\ Trusted Root \
         Certification Authorities store via `certutil -addstore root <pem>` \
         from an elevated shell."
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn handle_untrust() -> Result<()> {
    anyhow::bail!(
        "`aichu untrust` is macOS- and Linux-only in v0. On Windows, remove \
         the CA via `certutil -delstore root \"aichu local proxy CA\"` from \
         an elevated shell."
    )
}

/// Detect whether we're on a Debian-family Linux distro by checking for the
/// presence of `/etc/debian_version`. Pure — `exists` is injected so tests
/// can drive the both-branches behavior deterministically.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_debian_family<F: Fn(&str) -> bool>(exists: F) -> bool {
    exists(LINUX_DEBIAN_SENTINEL)
}

/// Build `sudo install -m 644 <src> <dest>`. We use `install(1)` rather
/// than `cp` so the destination mode is explicit in the argv — readers
/// (and future maintainers) don't have to reason about how `cp` and the
/// running umask interact, and the cert stays world-readable regardless
/// of how the source file's mode is set today or in the future. (Today
/// `aichu-ca.pem` is 0o644 from `fs::write`; the key file is 0o600, but
/// only the cert is ever passed here.)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_trust_copy_command(cert_src: &Path, cert_dest: &Path) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("install")
        .arg("-m")
        .arg("644")
        .arg(cert_src)
        .arg(cert_dest);
    cmd
}

/// Build `sudo update-ca-certificates`. Idempotent — runs even if no source
/// changed; on Debian it diffs the source dirs against the bundle and only
/// rewrites when needed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_trust_update_command() -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("update-ca-certificates");
    cmd
}

/// Build `sudo rm -f <cert_dest>`. The `-f` flag means rm succeeds (exit 0)
/// even if the file is already gone — makes `aichu untrust` idempotent
/// against a half-cleaned-up state.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_untrust_remove_command(cert_dest: &Path) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("rm").arg("-f").arg(cert_dest);
    cmd
}

/// Read `/etc/os-release` at runtime. Only called from the Linux trust
/// handlers; tests drive `linux_family_from_os_release` directly with
/// fixture strings (no filesystem dependency in the test path).
#[cfg(target_os = "linux")]
fn read_os_release() -> Option<String> {
    std::fs::read_to_string(LINUX_OS_RELEASE).ok()
}

/// Parse a `/etc/os-release` body and resolve it to a known
/// `LinuxFamily`, or `None` if neither `ID` nor `ID_LIKE` identifies a
/// family we automate.
///
/// Per `os-release(5)`: keys are `KEY=VALUE`, optionally with the
/// value double-quoted; `ID_LIKE` is space-separated. We tokenize
/// both and match any token against known IDs. Comments and blank
/// lines are skipped.
///
/// Order matters: `ID` is checked before `ID_LIKE`. A Manjaro box
/// ships `ID=manjaro ID_LIKE=arch` — the `ID` half is what makes us
/// confident the user is on an Arch derivative; `ID_LIKE` alone
/// (e.g. `ID=somefork ID_LIKE=arch`) is a softer signal but we accept
/// it because that's why the spec defines `ID_LIKE` in the first
/// place.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_family_from_os_release(body: &str) -> Option<LinuxFamily> {
    let (mut id, mut id_like): (Option<String>, Option<String>) = (None, None);
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "ID" => id = Some(v),
            "ID_LIKE" => id_like = Some(v),
            _ => {}
        }
    }

    // Collect every candidate token (ID + ID_LIKE words) into a list,
    // lowercased — `os-release` doesn't formally require lowercase but
    // every real-world distro uses it; this is defensive.
    let mut tokens: Vec<String> = Vec::new();
    if let Some(s) = id {
        tokens.push(s.to_lowercase());
    }
    if let Some(s) = id_like {
        tokens.extend(s.split_whitespace().map(|t| t.to_lowercase()));
    }

    // Order of the family checks doesn't matter — the token sets are
    // disjoint (no distro identifies as both red-hat-family and arch-
    // family). If that ever changes, the first match wins and we'd
    // need to revisit.
    const REDHAT_IDS: &[&str] = &[
        "fedora", "rhel", "centos", "rocky", "almalinux", "ol", "oracle",
    ];
    // Derivatives that ship `ID_LIKE=arch` (Garuda, ArcoLinux, etc.) are
    // caught by the ID_LIKE token sweep above — kept off the explicit
    // list to keep it minimal (Rule 2). Only `ID=` values that derivatives
    // are likely to use AS THEIR OWN ID belong here.
    const ARCH_IDS: &[&str] = &["arch", "manjaro", "endeavouros"];

    if tokens.iter().any(|t| REDHAT_IDS.contains(&t.as_str())) {
        return Some(LinuxFamily::RedHat);
    }
    if tokens.iter().any(|t| ARCH_IDS.contains(&t.as_str())) {
        return Some(LinuxFamily::Arch);
    }
    None
}

/// Resolve the absolute filesystem path that the family's trust-anchor
/// scanner picks up. Returning `&'static str` (rather than `&Path`)
/// matches the existing `LINUX_DEBIAN_CERT_DEST` shape — the caller
/// wraps in `Path::new` at the use site.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_family_install_path(family: LinuxFamily) -> &'static str {
    match family {
        LinuxFamily::RedHat => LINUX_REDHAT_CERT_DEST,
        LinuxFamily::Arch => LINUX_ARCH_CERT_DEST,
    }
}

/// Build the per-family `sudo <refresh-tool>` command that consolidates
/// the anchors directory into the consumed trust bundles.
///
/// Pure builder so the argv shape can be unit-tested without invoking
/// `sudo` (which requires a TTY and has destructive side effects).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_family_refresh_command(family: LinuxFamily) -> Command {
    let mut cmd = Command::new("sudo");
    match family {
        LinuxFamily::RedHat => {
            // `update-ca-trust` (no arguments) is the standard refresh —
            // implicit `extract` runs when anchors/ or blacklist/ have
            // changed.
            cmd.arg("update-ca-trust");
        }
        LinuxFamily::Arch => {
            // `trust extract-compat` writes the legacy
            // `/etc/ssl/certs/ca-certificates.crt` bundle that
            // most TLS libs read on Arch.
            cmd.arg("trust").arg("extract-compat");
        }
    }
    cmd
}

/// Short human label for tracing — keeps the log messages tied to the
/// actual command without re-running the builder.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_family_refresh_label(family: LinuxFamily) -> &'static str {
    match family {
        LinuxFamily::RedHat => "update-ca-trust",
        LinuxFamily::Arch => "trust extract-compat",
    }
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
/// fails. Centralized so trust + untrust report errors the same way on
/// every platform where the live handler invokes a subprocess.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_or_bail(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("invoke `sudo` for {what}"))?;
    if !status.success() {
        // The subprocess (security(1), install(1), update-ca-certificates,
        // rm) inherits our stdio, so its own error has already printed to
        // the user's terminal above this bail message — point them there
        // rather than promising tracing detail we don't have.
        anyhow::bail!(
            "{what} failed (exit code {:?}); see subprocess output above for the cause",
            status.code()
        );
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// `aichu doctor` — read-only setup diagnostics.
// -----------------------------------------------------------------------------

/// Outcome of one diagnostic check. `Warn` and `Fail` differ on severity:
/// `Warn` is "something the user probably wants to know" (e.g. HTTPS_PROXY
/// not set in this shell), `Fail` is "doctor reports the binary cannot
/// function correctly until this is fixed" (e.g. CA not generated).
#[derive(Debug, PartialEq)]
enum CheckResult {
    Ok(String),
    Warn { message: String, hint: String },
    Fail { message: String, hint: String },
}

/// Check 1: does the CA cert file exist on disk? Without this, `aichu run`
/// will generate one on first invocation — but if the user already ran
/// `aichu trust`, *this* file is the one they trusted, and a regenerated
/// CA would orphan that install.
fn check_ca_present(ca_dir: &Path) -> CheckResult {
    let cert_path = ca_dir.join(proxy_mitm::ca::CERT_FILENAME);
    let key_path = ca_dir.join(proxy_mitm::ca::KEY_FILENAME);
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => CheckResult::Ok(format!("CA present at {}", cert_path.display())),
        (false, false) => CheckResult::Fail {
            message: format!("CA not found at {}", cert_path.display()),
            hint: "run `aichu run` once to generate the CA, then `aichu trust` to install it \
                   (if you previously trusted a now-deleted CA, run `aichu untrust` first to \
                   avoid an orphaned keychain entry)"
                .into(),
        },
        (true, false) => CheckResult::Fail {
            message: format!("CA cert exists but private key is missing at {}", key_path.display()),
            hint: "the CA is unusable — `rm` the cert and run `aichu run` to regenerate (you'll need to `aichu untrust` + `aichu trust` again)".into(),
        },
        (false, true) => CheckResult::Fail {
            message: format!("CA private key exists but cert is missing at {}", cert_path.display()),
            hint: "the CA is unusable — `rm` the key and run `aichu run` to regenerate".into(),
        },
    }
}

/// Check 2: is `HTTPS_PROXY` set in this shell? Without it, coding agents
/// won't route traffic through aichu — the proxy can be running and
/// trusted, and prompts will still flow unredacted to the model provider.
///
/// We don't try to parse or validate the URL — heuristic guessing about
/// "right" URLs would mask real misconfigurations behind opinions. A set
/// value reports Ok with the value displayed; the user reads it and
/// decides if it points where they meant.
fn check_https_proxy<F>(env: F) -> CheckResult
where
    F: Fn(&str) -> Option<OsString>,
{
    match env("HTTPS_PROXY").or_else(|| env("https_proxy")) {
        Some(value) => CheckResult::Ok(format!(
            "HTTPS_PROXY={}",
            value.to_string_lossy()
        )),
        None => CheckResult::Warn {
            message: "HTTPS_PROXY is not set in this shell".into(),
            hint: "export HTTPS_PROXY=http://127.0.0.1:8788 (the proxy still works for any process that DOES have it set)".into(),
        },
    }
}

/// Check 3: is anything listening on the proxy port? Uses a short
/// `TcpStream::connect_timeout` — if something accepts the connection,
/// the port is bound (which is what we want); ECONNREFUSED means
/// nothing's there (the proxy isn't running).
///
/// We can't tell from the outside whether the listener is actually
/// aichu vs. some other binding (`nc -l 8788` would also pass). That
/// ambiguity is acceptable — the user is asking "is my proxy up?",
/// not "prove this is aichu specifically".
fn check_proxy_port_listening(addr: SocketAddr) -> CheckResult {
    match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(_) => CheckResult::Ok(format!("something is listening on {addr}")),
        Err(_) => CheckResult::Warn {
            message: format!("nothing is listening on {addr}"),
            hint: "run `aichu` (or `aichu run`) in another shell to start the proxy".into(),
        },
    }
}

/// Check 4 (Linux only): does the CA cert exist at the destination
/// path that the distro's trust-update tool picks up? File existence
/// is a sufficient signal — if the file is there, the distro's
/// refresh command would have folded it into the consumed bundle.
/// Verifying the bundle directly would require parsing PEM
/// concatenations, which is more work than a check this proxy-y needs.
///
/// Pure file-existence check, no subprocess. Compiles on every target
/// so the unit test runs cross-OS.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_linux_anchor_file_present(cert_dest: &Path) -> CheckResult {
    if cert_dest.exists() {
        CheckResult::Ok(format!("CA present at {}", cert_dest.display()))
    } else {
        CheckResult::Fail {
            message: format!("CA not found at {}", cert_dest.display()),
            hint: "run `aichu trust` to install it (requires sudo)".into(),
        }
    }
}

/// Doctor's Linux trust-source check, with per-family path routing
/// done at runtime so a Fedora/Arch host doesn't get a misleading
/// "Debian-family path missing" failure.
///
/// Detection mirrors `handle_trust` exactly: Debian sentinel first
/// (cheapest check, also handles the most common Linux case), then
/// `/etc/os-release` for RH/Arch. If detection fails, doctor reports
/// `Fail` — `aichu trust` exits non-zero on this same host, so doctor
/// must match that signal (Rule 12 — fail loud; the user should know
/// trust automation won't work here without parsing log lines).
#[cfg(target_os = "linux")]
fn linux_doctor_trust_source_check() -> (&'static str, CheckResult) {
    if is_debian_family(|p| Path::new(p).exists()) {
        return (
            "CA in trust source (Debian-family)",
            check_linux_anchor_file_present(Path::new(LINUX_DEBIAN_CERT_DEST)),
        );
    }
    let family = read_os_release()
        .as_deref()
        .and_then(linux_family_from_os_release);
    match family {
        Some(LinuxFamily::RedHat) => (
            "CA in trust source (Red Hat-family)",
            check_linux_anchor_file_present(Path::new(LINUX_REDHAT_CERT_DEST)),
        ),
        Some(LinuxFamily::Arch) => (
            "CA in trust source (Arch-family)",
            check_linux_anchor_file_present(Path::new(LINUX_ARCH_CERT_DEST)),
        ),
        None => ("CA in trust source", linux_doctor_unknown_family_result()),
    }
}

/// The `Fail` result `linux_doctor_trust_source_check` returns when
/// the host's family can't be detected. Factored out so the unknown-
/// family branch is unit-testable cross-OS without needing a Linux
/// host whose `/etc/os-release` is missing or malformed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_doctor_unknown_family_result() -> CheckResult {
    CheckResult::Fail {
        message: "Cannot detect Linux family from /etc/os-release; \
                  manual cert install required"
            .into(),
        hint: "`aichu trust` cannot run on this host — install the CA \
               manually into your distro's trust-anchor directory and \
               run the appropriate update command"
            .into(),
    }
}

/// Check 5 (macOS only): does the CA appear in the System keychain?
/// Uses `security find-certificate -c <CN> <keychain>` which is
/// read-only and does not prompt for sudo. Exit 0 = found, non-zero
/// = not found.
#[cfg(target_os = "macos")]
fn check_keychain_has_ca(common_name: &str, keychain: &Path) -> CheckResult {
    let mut cmd = find_certificate_command(common_name, keychain);
    // Capture both streams so we can choose what to surface to the user.
    // `Output` gives us stderr; we only forward it on the *unexpected*
    // failure path (e.g. keychain file missing). The normal "not found"
    // case still maps to a clean Fail with a `aichu trust` hint.
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::Fail {
                message: format!("could not invoke `security find-certificate`: {e}"),
                hint: "is the macOS Security framework command-line available? (`which security`)"
                    .into(),
            };
        }
    };
    interpret_find_certificate_output(&output, common_name)
}

/// Build `security find-certificate -c <common_name> <keychain>`. Pure
/// so tests can pin the argv shape without spawning. (No `sudo`: this
/// is a read-only operation; the keychain itself allows lookups by
/// any local user.)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn find_certificate_command(common_name: &str, keychain: &Path) -> Command {
    let mut cmd = Command::new("security");
    cmd.arg("find-certificate")
        .arg("-c")
        .arg(common_name)
        .arg(keychain);
    cmd
}

/// Pure interpretation of `find-certificate`'s output. Three branches:
///   1. exit 0 → cert present.
///   2. exit non-zero with the standard "could not be found" stderr → cert
///      not installed; suggest `aichu trust`.
///   3. exit non-zero with any other stderr → surface that stderr in the
///      Fail message. Without this branch a broken keychain (missing file,
///      permissions issue) would be reported as "not installed" and the
///      user would chase the wrong fix.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn interpret_find_certificate_output(
    output: &std::process::Output,
    common_name: &str,
) -> CheckResult {
    if output.status.success() {
        return CheckResult::Ok(format!("CA \"{common_name}\" present in System keychain"));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `security find-certificate -c <CN>` emits this exact phrasing for
    // "no matching cert" — anything else is an environmental problem.
    if stderr.contains("could not be found") {
        CheckResult::Fail {
            message: format!("CA \"{common_name}\" is not installed in the System keychain"),
            hint: "run `aichu trust` to install it (will prompt for sudo)".into(),
        }
    } else {
        CheckResult::Fail {
            message: format!(
                "`security find-certificate` failed unexpectedly: {}",
                stderr.trim()
            ),
            hint: "check that /Library/Keychains/System.keychain is accessible".into(),
        }
    }
}

/// Run every diagnostic and surface results. Returns `Err` if any check
/// reports `Fail` so the process exit code is non-zero — `Warn`s alone
/// keep doctor exiting 0 (the user might intentionally have HTTPS_PROXY
/// unset in this particular shell while testing).
fn handle_doctor() -> Result<()> {
    println!("aichu doctor — checking your setup:\n");

    let ca_dir = ca_dir()?;
    let mut any_fail = false;
    let mut any_warn = false;

    let checks: Vec<(&str, CheckResult)> = vec![
        ("CA on disk", check_ca_present(&ca_dir)),
        (
            "HTTPS_PROXY in this shell",
            check_https_proxy(|k| std::env::var_os(k)),
        ),
        (
            "proxy port reachable",
            check_proxy_port_listening("127.0.0.1:8788".parse().expect("hardcoded addr parses")),
        ),
        #[cfg(target_os = "macos")]
        (
            "CA in System keychain (macOS)",
            check_keychain_has_ca(
                proxy_mitm::ca::COMMON_NAME,
                Path::new(MACOS_SYSTEM_KEYCHAIN),
            ),
        ),
        #[cfg(target_os = "linux")]
        linux_doctor_trust_source_check(),
    ];

    for (label, result) in &checks {
        match result {
            CheckResult::Ok(msg) => println!("  ✓ {label}: {msg}"),
            CheckResult::Warn { message, hint } => {
                println!("  ! {label}: {message}");
                println!("      hint: {hint}");
                any_warn = true;
            }
            CheckResult::Fail { message, hint } => {
                println!("  ✗ {label}: {message}");
                println!("      hint: {hint}");
                any_fail = true;
            }
        }
    }

    println!();
    if any_fail {
        anyhow::bail!("one or more checks failed — see above")
    } else if any_warn {
        println!("all critical checks passed; some warnings above.");
        Ok(())
    } else {
        println!("all checks passed ✓");
        Ok(())
    }
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
        match cli.command() {
            // Default to Run with default args (injection ON — the
            // default-OFF behavior is what the dedicated flag test
            // pins). Bare `aichu` MUST land here; if a future
            // refactor changes the default, the user-facing entry
            // point silently changes too.
            Commands::Run(args) => assert!(
                !args.no_system_prompt,
                "default Run should keep system-prompt injection ON",
            ),
            other => panic!("expected Commands::Run, got {other:?}"),
        }
    }

    #[test]
    fn explicit_run_subcommand_resolves_to_run() {
        let cli = Cli::parse_from(["aichu", "run"]);
        match cli.command() {
            Commands::Run(args) => assert!(!args.no_system_prompt),
            other => panic!("expected Commands::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_with_no_system_prompt_flag_sets_field_true() {
        // Pin: `aichu run --no-system-prompt` flips the field. Without
        // this test, a regression that renamed/dropped the flag (or
        // mis-wired the inversion in `run()`) would silently leave
        // injection ON for users who explicitly opted out — exactly
        // the kind of "fail silently" failure CLAUDE.md Rule 12
        // exists to prevent.
        let cli = Cli::parse_from(["aichu", "run", "--no-system-prompt"]);
        match cli.command() {
            Commands::Run(args) => assert!(
                args.no_system_prompt,
                "--no-system-prompt should set no_system_prompt to true",
            ),
            other => panic!("expected Commands::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_default_keeps_system_prompt_on() {
        // Pin the default-ON contract explicitly: `aichu run` with
        // no flags must NOT set `no_system_prompt`. Belt-and-
        // suspenders for the e03 result — users who don't pass the
        // flag get the e03-measured behavior by default.
        let cli = Cli::parse_from(["aichu", "run"]);
        match cli.command() {
            Commands::Run(args) => assert!(!args.no_system_prompt),
            other => panic!("expected Commands::Run, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        // Locks the contract: typos in subcommand names must fail loudly,
        // not silently fall through to the default. Surfaces a future
        // regression where `Option<Commands>` swallows clap's error.
        // `xyzzy` is a known-never-to-be-a-real-subcommand placeholder.
        let result = Cli::try_parse_from(["aichu", "xyzzy"]);
        assert!(result.is_err(), "expected `aichu xyzzy` to error");
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

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn handle_trust_returns_unsupported_on_unsupported_os() {
        // The unsupported-OS error must name the platform constraint so
        // users know it's deliberate, not a missing dependency. Compare-
        // by-substring is intentionally loose to allow message tweaks.
        // Currently fires only on Windows + BSDs + Solaris.
        let err = handle_trust().expect_err("unsupported-OS trust should error");
        let msg = err.to_string();
        assert!(
            msg.contains("macOS") && msg.contains("Linux"),
            "unsupported-OS trust error should mention macOS and Linux: {msg}"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn handle_untrust_returns_unsupported_on_unsupported_os() {
        let err = handle_untrust().expect_err("unsupported-OS untrust should error");
        let msg = err.to_string();
        assert!(
            msg.contains("macOS") && msg.contains("Linux"),
            "unsupported-OS untrust error should mention macOS and Linux: {msg}"
        );
    }

    // ---- Linux trust automation (Debian-family) -----------------------------

    #[test]
    fn is_debian_family_true_when_sentinel_file_exists() {
        // The sentinel is `/etc/debian_version`. The function takes an
        // `exists` closure precisely so this test doesn't depend on the
        // host filesystem.
        let r = is_debian_family(|p| p == LINUX_DEBIAN_SENTINEL);
        assert!(r, "should detect Debian family when sentinel exists");
    }

    #[test]
    fn is_debian_family_false_when_sentinel_file_absent() {
        let r = is_debian_family(|_| false);
        assert!(!r, "should NOT detect Debian family when sentinel is absent");
    }

    #[test]
    fn linux_trust_copy_command_uses_install_with_644_mode() {
        // Pin the exact argv. Using `install(1)` rather than `cp` is a
        // deliberate choice (explicit mode 644 instead of inheriting
        // ~/.aichu/ca/'s mode 600 which would brick parsing).
        let cmd = linux_trust_copy_command(
            Path::new("/home/me/.aichu/ca/aichu-ca.pem"),
            Path::new("/usr/local/share/ca-certificates/aichu-ca.crt"),
        );
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(
            args,
            vec![
                "install",
                "-m",
                "644",
                "/home/me/.aichu/ca/aichu-ca.pem",
                "/usr/local/share/ca-certificates/aichu-ca.crt",
            ]
        );
    }

    #[test]
    fn linux_trust_update_command_runs_update_ca_certificates() {
        let cmd = linux_trust_update_command();
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(args, vec!["update-ca-certificates"]);
    }

    #[test]
    fn check_linux_anchor_file_present_ok_when_cert_present() {
        // File existence at the destination path is the signal that
        // `aichu trust` ran successfully — `update-ca-certificates`
        // would have folded the cert into the bundle on its last run.
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("aichu-ca.crt");
        std::fs::write(&dest, "fake-cert-bytes").unwrap();
        assert!(matches!(
            check_linux_anchor_file_present(&dest),
            CheckResult::Ok(_)
        ));
    }

    #[test]
    fn check_linux_anchor_file_present_fails_when_cert_absent() {
        // Absence means `aichu trust` hasn't run (or `aichu untrust`
        // removed it). The hint must point at `aichu trust`.
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("aichu-ca.crt"); // intentionally not created
        match check_linux_anchor_file_present(&dest) {
            CheckResult::Fail { hint, .. } => {
                assert!(
                    hint.contains("aichu trust"),
                    "hint should point at `aichu trust`: {hint}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn doctor_fails_loud_on_unknown_distro() {
        // On a Linux host with no Debian sentinel AND an unparseable
        // `/etc/os-release`, `aichu trust` bails non-zero — so doctor
        // MUST report `Fail`, not `Warn`. Pinning `Fail` here prevents
        // a regression to a softer signal that would let users miss
        // that trust automation cannot work on their host (Rule 12 —
        // fail loud; Rule 9 — encodes WHY the signal matters: doctor
        // must mirror what `aichu trust` would do).
        match linux_doctor_unknown_family_result() {
            CheckResult::Fail { message, .. } => {
                assert!(
                    message.contains("Cannot detect Linux family"),
                    "message should name the detection failure: {message}"
                );
            }
            other => panic!("expected Fail (mirroring `aichu trust` bail), got {other:?}"),
        }
    }

    #[test]
    fn linux_untrust_remove_command_uses_rm_f_for_idempotency() {
        // The `-f` flag means rm succeeds even if the cert is already
        // gone — keeps `aichu untrust` idempotent against a partially-
        // cleaned-up state. Locking the flag here so a future "let's
        // be defensive and drop `-f`" reflex would surface as a test
        // failure.
        let cmd = linux_untrust_remove_command(Path::new(
            "/usr/local/share/ca-certificates/aichu-ca.crt",
        ));
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(
            args,
            vec!["rm", "-f", "/usr/local/share/ca-certificates/aichu-ca.crt"]
        );
    }

    // ---- Linux trust automation (Red Hat & Arch families) -------------------
    //
    // Detection here parses `/etc/os-release` (freedesktop.org's standard,
    // shipped by every modern systemd-using distro) rather than a single
    // sentinel file like `/etc/debian_version`. Two reasons: derivatives
    // (Rocky, AlmaLinux, Manjaro, EndeavourOS) don't all ship a uniquely-
    // named sentinel, and `ID_LIKE=` in `/etc/os-release` already
    // encodes the "compatible with" relationship the install path
    // depends on. The Debian path keeps its sentinel (Rule 3 — don't
    // refactor what isn't broken).

    /// A minimal `/etc/os-release` fixture for Fedora 40. The full file
    /// has many more keys, but only `ID=` and `ID_LIKE=` drive routing.
    fn fixture_os_release(id: &str, id_like: Option<&str>) -> String {
        let mut s = format!("NAME=\"Test Distro\"\nID={id}\n");
        if let Some(ilk) = id_like {
            s.push_str(&format!("ID_LIKE=\"{ilk}\"\n"));
        }
        s.push_str("VERSION_ID=\"1\"\n");
        s
    }

    #[test]
    fn parses_fedora_as_redhat_family() {
        // Fedora itself sets ID=fedora with no ID_LIKE — it IS the
        // reference, not a derivative. Routing must succeed on the ID
        // alone, without depending on ID_LIKE being present.
        let os_release = fixture_os_release("fedora", None);
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::RedHat));
    }

    #[test]
    fn parses_rhel_via_id_like_as_redhat_family() {
        // Real RHEL ships ID=rhel with ID_LIKE="fedora". The detector
        // must pick up RHEL on the ID alone — the ID_LIKE check is
        // about derivatives that DON'T set a known ID.
        let os_release = fixture_os_release("rhel", Some("fedora"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::RedHat));
    }

    #[test]
    fn parses_centos_as_redhat_family() {
        // CentOS Stream sets ID=centos with ID_LIKE="rhel fedora".
        // The space-separated ID_LIKE is the freedesktop.org spec —
        // parsing must tokenize it, not match the whole string.
        let os_release = fixture_os_release("centos", Some("rhel fedora"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::RedHat));
    }

    #[test]
    fn parses_rocky_as_redhat_family() {
        // Rocky Linux ships ID=rocky with ID_LIKE="\"rhel centos fedora\"".
        // Real-world ID_LIKE values are often quoted AND multi-token —
        // both must round-trip through the parser.
        let os_release = fixture_os_release("rocky", Some("rhel centos fedora"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::RedHat));
    }

    #[test]
    fn parses_almalinux_as_redhat_family() {
        // AlmaLinux uses ID=almalinux. Covering it explicitly because
        // it's the other major RHEL rebuild after Rocky — if either is
        // missed, a chunk of the production-RHEL user base gets no
        // trust automation.
        let os_release = fixture_os_release("almalinux", Some("rhel centos fedora"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::RedHat));
    }

    #[test]
    fn parses_arch_as_arch_family() {
        // Arch Linux ships ID=arch with no ID_LIKE — like Fedora, it's
        // the reference, not a derivative. Routing must succeed on ID
        // alone.
        let os_release = fixture_os_release("arch", None);
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::Arch));
    }

    #[test]
    fn parses_manjaro_as_arch_family() {
        // Manjaro ships ID=manjaro with ID_LIKE=arch. The detector
        // must accept either an exact-known ID or a known token in
        // ID_LIKE — Manjaro tests both halves of that.
        let os_release = fixture_os_release("manjaro", Some("arch"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::Arch));
    }

    #[test]
    fn parses_endeavouros_as_arch_family() {
        // EndeavourOS ships ID=endeavouros with ID_LIKE=arch. Same
        // "ID_LIKE-only matches a known family" pattern as Manjaro.
        let os_release = fixture_os_release("endeavouros", Some("arch"));
        assert_eq!(linux_family_from_os_release(&os_release), Some(LinuxFamily::Arch));
    }

    #[test]
    fn unknown_distro_returns_none() {
        // An ID we don't know AND an ID_LIKE we don't know must NOT
        // silently route to a wrong path (Rule 12 — fail loud). The
        // caller is expected to bail with a clear "manual install"
        // message when this returns None.
        let os_release = fixture_os_release("haiku", Some("beos"));
        assert_eq!(linux_family_from_os_release(&os_release), None);
    }

    #[test]
    fn malformed_os_release_returns_none() {
        // Garbage in must not crash and must not falsely identify a
        // family. A missing ID line means we can't tell, so we bail
        // out to the manual-install fallback.
        let os_release = "this is not a valid os-release file\n";
        assert_eq!(linux_family_from_os_release(os_release), None);
    }

    #[test]
    fn redhat_and_arch_families_route_to_different_install_paths() {
        // This is the actual invariant under test: a regression where
        // both families resolve to the SAME path would silently break
        // one of them on its real host (the file would be written to
        // the wrong directory, `update-ca-trust` / `trust extract-compat`
        // would not see it, and trust would silently fail). Pinning
        // the per-family install paths AND asserting they differ
        // catches that class of bug.
        let rh = linux_family_install_path(LinuxFamily::RedHat);
        let arch = linux_family_install_path(LinuxFamily::Arch);
        assert_eq!(rh, "/etc/pki/ca-trust/source/anchors/aichu-ca.crt");
        assert_eq!(arch, "/etc/ca-certificates/trust-source/anchors/aichu-ca.crt");
        assert_ne!(rh, arch, "families must route to distinct paths");
    }

    #[test]
    fn redhat_refresh_command_is_update_ca_trust() {
        // Pin the argv. `update-ca-trust` (no arguments) is the
        // canonical Fedora/RHEL refresh command — it processes both
        // the source/anchors dir and the source/blacklist dir and
        // rebuilds the consolidated bundle. Any drift here would
        // silently break the post-install trust rebuild on RHEL hosts.
        let cmd = linux_family_refresh_command(LinuxFamily::RedHat);
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(args, vec!["update-ca-trust"]);
    }

    #[test]
    fn arch_refresh_command_is_trust_extract_compat() {
        // `trust extract-compat` (from p11-kit, which Arch ships in
        // base) consolidates the trust-source/anchors dir into the
        // legacy `/etc/ssl/certs/ca-certificates.crt` bundle that
        // most TLS libraries read.
        let cmd = linux_family_refresh_command(LinuxFamily::Arch);
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(args, vec!["trust", "extract-compat"]);
    }

    #[test]
    fn install_then_remove_at_redhat_path_round_trips() {
        // Integration check: drive `install -m 644` + `rm -f` against
        // a tempdir-rooted RedHat-family path and confirm the file
        // appears then disappears. Sudo is omitted (the tempdir is
        // user-writable), so the test runs on any host including
        // macOS — what's exercised is the per-family path routing
        // plus the underlying utilities behaving as expected.
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("aichu-ca.pem");
        std::fs::write(&src, b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n").unwrap();

        // Mirror the RedHat anchors layout under the tempdir.
        let anchors = dir.path().join("etc/pki/ca-trust/source/anchors");
        std::fs::create_dir_all(&anchors).unwrap();
        let dest = anchors.join("aichu-ca.crt");

        // `install -m 644 <src> <dest>` — no sudo, tempdir is ours.
        let status = Command::new("install")
            .arg("-m").arg("644")
            .arg(&src).arg(&dest)
            .status().expect("install(1) available on POSIX hosts");
        assert!(status.success(), "install failed: {status:?}");
        assert!(dest.exists(), "cert should be at RedHat anchors path");

        // `rm -f <dest>` — no sudo, idempotent.
        let status = Command::new("rm").arg("-f").arg(&dest).status().unwrap();
        assert!(status.success());
        assert!(!dest.exists(), "cert should be gone after rm -f");
    }

    #[test]
    fn install_then_remove_at_arch_path_round_trips() {
        // Same shape as the RedHat round-trip but routed through the
        // Arch path. The reason both tests exist (rather than one
        // parameterized) is that a copy-paste regression where Arch
        // routes to the RedHat anchors dir would pass a single
        // parameterized test but fail this one — the duplication is
        // load-bearing.
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("aichu-ca.pem");
        std::fs::write(&src, b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n").unwrap();

        let anchors = dir.path().join("etc/ca-certificates/trust-source/anchors");
        std::fs::create_dir_all(&anchors).unwrap();
        let dest = anchors.join("aichu-ca.crt");

        let status = Command::new("install")
            .arg("-m").arg("644")
            .arg(&src).arg(&dest)
            .status().expect("install(1) available on POSIX hosts");
        assert!(status.success(), "install failed: {status:?}");
        assert!(dest.exists(), "cert should be at Arch anchors path");

        let status = Command::new("rm").arg("-f").arg(&dest).status().unwrap();
        assert!(status.success());
        assert!(!dest.exists(), "cert should be gone after rm -f");
    }

    // ---- `aichu doctor` checks ------------------------------------------------

    #[test]
    fn check_ca_present_ok_when_both_files_exist() {
        // Both cert and key on disk: the proxy can boot and the trust install
        // (if any) is consistent with what's there.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(proxy_mitm::ca::CERT_FILENAME), "fake-cert").unwrap();
        std::fs::write(dir.path().join(proxy_mitm::ca::KEY_FILENAME), "fake-key").unwrap();
        assert!(matches!(
            check_ca_present(dir.path()),
            CheckResult::Ok(_)
        ));
    }

    #[test]
    fn check_ca_present_fails_when_neither_file_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = check_ca_present(dir.path());
        match result {
            CheckResult::Fail { hint, .. } => {
                assert!(hint.contains("aichu run"), "hint should point at `aichu run`: {hint}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn check_ca_present_fails_loudly_when_only_one_file_exists() {
        // Partial state (cert without key, or vice versa) is unrecoverable
        // — the CA is unusable. Doctor surfaces this as a Fail rather than
        // letting `aichu run` silently regenerate (which would orphan any
        // trust install).
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(proxy_mitm::ca::CERT_FILENAME), "only-cert").unwrap();
        assert!(matches!(
            check_ca_present(dir.path()),
            CheckResult::Fail { .. }
        ));
    }

    #[test]
    fn check_https_proxy_ok_when_uppercase_var_set() {
        let r = check_https_proxy(|k| match k {
            "HTTPS_PROXY" => Some("http://127.0.0.1:8788".into()),
            _ => None,
        });
        assert!(matches!(r, CheckResult::Ok(_)));
    }

    #[test]
    fn check_https_proxy_falls_back_to_lowercase_var() {
        // Many shell environments only set `https_proxy` (lowercase, the
        // libcurl convention). Coding agents that use libcurl-derived
        // HTTP clients will read it; doctor must too, or it'd warn about
        // a setup that actually works.
        let r = check_https_proxy(|k| match k {
            "https_proxy" => Some("http://127.0.0.1:8788".into()),
            _ => None,
        });
        assert!(matches!(r, CheckResult::Ok(_)));
    }

    #[test]
    fn check_https_proxy_warns_when_unset() {
        // Unset is Warn, not Fail — the proxy might still be useful for
        // a different shell where the user did export it.
        let r = check_https_proxy(|_| None);
        assert!(matches!(r, CheckResult::Warn { .. }));
    }

    #[test]
    fn check_proxy_port_listening_ok_when_something_listens() {
        // Bind a sacrificial listener on a free port and verify the check
        // sees it. The kernel never re-binds the same ephemeral port
        // within a single process, so there's no race with the connect.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let r = check_proxy_port_listening(addr);
        assert!(matches!(r, CheckResult::Ok(_)), "got {r:?}");
    }

    #[test]
    fn check_proxy_port_listening_warns_when_nothing_listens() {
        // Bind, capture the address, drop the listener — within this test's
        // window no other process is racing for ephemeral ports, so the
        // connect refuses cleanly. (We can't promise the kernel won't ever
        // re-issue this port; we promise nothing in *this* test is asking
        // it to.)
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let r = check_proxy_port_listening(addr);
        assert!(matches!(r, CheckResult::Warn { .. }), "got {r:?}");
    }

    #[test]
    fn find_certificate_command_targets_named_keychain() {
        // Argv-pin the read-only lookup so any drift (e.g. adding `-Z`
        // flag or changing keychain path semantics) is caught here, not
        // by users on a real machine.
        let cmd = find_certificate_command(
            "aichu local proxy CA",
            Path::new("/Library/Keychains/System.keychain"),
        );
        assert_eq!(cmd.get_program(), "security");
        let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
        assert_eq!(
            args,
            vec![
                "find-certificate",
                "-c",
                "aichu local proxy CA",
                "/Library/Keychains/System.keychain",
            ]
        );
        // Crucially: no `sudo` prefix. Read operation, no privilege needed.
    }

    #[cfg(unix)]
    #[test]
    fn interpret_find_certificate_output_ok_on_zero_exit() {
        // Use a real subprocess to construct a known-success Output — `true`
        // exits 0 with empty stdout/stderr on every POSIX platform.
        let output = Command::new("true").output().unwrap();
        let r = interpret_find_certificate_output(&output, "aichu local proxy CA");
        assert!(matches!(r, CheckResult::Ok(_)));
    }

    #[cfg(unix)]
    #[test]
    fn interpret_find_certificate_output_reports_install_hint_on_normal_not_found() {
        // Construct an Output that mimics the *expected* failure: exit
        // non-zero, stderr contains the "could not be found" phrasing.
        // The hint must point at `aichu trust` so the user takes the
        // right next action.
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n".to_vec(),
        };
        let r = interpret_find_certificate_output(&output, "aichu local proxy CA");
        match r {
            CheckResult::Fail { hint, message } => {
                assert!(
                    hint.contains("aichu trust"),
                    "normal not-found hint should point at `aichu trust`: {hint}"
                );
                assert!(
                    message.contains("not installed"),
                    "message should describe the install gap: {message}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn interpret_find_certificate_output_surfaces_unexpected_stderr() {
        // The defensive branch: if stderr says something OTHER than the
        // canonical "could not be found" phrasing, doctor must NOT
        // misreport it as "not installed" — the user would chase the
        // wrong fix (`aichu trust` won't help if the keychain itself is
        // broken). Verifies the stderr is surfaced in the Fail message.
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"SecKeychainCopyDefault: keychain file does not exist".to_vec(),
        };
        let r = interpret_find_certificate_output(&output, "aichu local proxy CA");
        match r {
            CheckResult::Fail { message, .. } => {
                assert!(
                    message.contains("keychain file does not exist"),
                    "unexpected stderr should be surfaced: {message}"
                );
                assert!(
                    !message.contains("not installed"),
                    "unexpected stderr should NOT be reported as 'not installed': {message}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }
}
