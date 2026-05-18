// CA load-or-create.
//
// On first call: generate a fresh self-signed CA via rcgen, write cert + key
// PEMs to `dir/`, restrict the key file to mode 0o600 on Unix.
// On subsequent calls: parse the existing PEMs back into an Issuer.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use hudsucker::rustls::crypto::aws_lc_rs;

pub const CERT_FILENAME: &str = "aichu-ca.pem";
pub const KEY_FILENAME: &str = "aichu-ca.key";

/// X.509 Common Name baked into the self-signed CA. The `aichu untrust`
/// CLI uses this to locate the cert in the system keychain for removal,
/// so it must stay stable across versions — changing this string would
/// orphan installs by anyone who ran `aichu trust` on an earlier build.
pub const COMMON_NAME: &str = "aichu local proxy CA";

/// A loaded or freshly-generated local CA, ready to back a hudsucker proxy.
pub struct Ca {
    /// The hudsucker authority that signs leaf certs for intercepted hosts.
    pub authority: RcgenAuthority,
    /// PEM-encoded public CA certificate. Safe to share; trust-installable
    /// into the system root store.
    pub cert_pem: Vec<u8>,
}

/// Generate or load the local CA from `dir`. Creates `dir` if missing.
///
/// Files used:
///   - `<dir>/aichu-ca.pem`  — public CA certificate (PEM)
///   - `<dir>/aichu-ca.key`  — CA private key (PEM, mode 0o600 on Unix)
pub fn load_or_create_ca(dir: &Path) -> Result<Ca> {
    crate::ensure_rustls_provider();

    let cert_path = dir.join(CERT_FILENAME);
    let key_path = dir.join(KEY_FILENAME);

    let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
        let cert = fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key = fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        (cert, key)
    } else {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

        let (cert_pem, key_pem) = generate_ca()?;
        fs::write(&cert_path, &cert_pem)
            .with_context(|| format!("write {}", cert_path.display()))?;
        write_key(&key_path, &key_pem)?;
        (cert_pem, key_pem)
    };

    let key_pair = KeyPair::from_pem(&key_pem).context("parse CA private key")?;
    let issuer =
        Issuer::from_ca_cert_pem(&cert_pem, key_pair).context("parse CA certificate")?;
    let authority = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    Ok(Ca {
        authority,
        cert_pem: cert_pem.into_bytes(),
    })
}

fn generate_ca() -> Result<(String, String)> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("init CA certificate params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, COMMON_NAME);
    dn.push(DnType::OrganizationName, "aichu");
    params.distinguished_name = dn;
    // Constrained(0): this CA can sign leaf certificates but cannot mint
    // sub-CAs. The proxy only ever needs to issue leafs for intercepted
    // hosts, so forbidding sub-CAs is defense-in-depth if the key ever
    // leaks.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let key_pair = KeyPair::generate().context("generate CA key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign CA certificate")?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(unix)]
fn write_key(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn first_call_writes_cert_and_key_files() {
        let dir = TempDir::new().unwrap();
        let ca = load_or_create_ca(dir.path()).unwrap();

        assert!(dir.path().join(CERT_FILENAME).exists(), "cert file missing");
        assert!(dir.path().join(KEY_FILENAME).exists(), "key file missing");
        assert!(
            !ca.cert_pem.is_empty(),
            "Ca.cert_pem should expose the public cert bytes"
        );
    }

    #[test]
    fn cert_file_is_a_pem_certificate() {
        // We don't parse the cert here — the integration test already proves
        // it's a usable CA. This test pins the on-disk file format so a
        // future refactor that switches to DER would surface immediately.
        let dir = TempDir::new().unwrap();
        let _ = load_or_create_ca(dir.path()).unwrap();
        let cert = fs::read_to_string(dir.path().join(CERT_FILENAME)).unwrap();
        assert!(
            cert.starts_with("-----BEGIN CERTIFICATE-----"),
            "expected PEM CERTIFICATE block, got: {}",
            &cert[..cert.len().min(60)]
        );
        assert!(
            cert.trim_end().ends_with("-----END CERTIFICATE-----"),
            "expected PEM CERTIFICATE end-marker"
        );
    }

    #[test]
    fn second_call_reuses_existing_ca_without_regenerating() {
        // The user trusts the CA into their system store once. If we silently
        // regenerated on every startup, every restart would invalidate that
        // trust install — exactly the foot-gun §4 of the build plan warns
        // about.
        let dir = TempDir::new().unwrap();
        let _ = load_or_create_ca(dir.path()).unwrap();
        let cert_before = fs::read(dir.path().join(CERT_FILENAME)).unwrap();
        let key_before = fs::read(dir.path().join(KEY_FILENAME)).unwrap();

        let _ = load_or_create_ca(dir.path()).unwrap();
        let cert_after = fs::read(dir.path().join(CERT_FILENAME)).unwrap();
        let key_after = fs::read(dir.path().join(KEY_FILENAME)).unwrap();

        assert_eq!(cert_before, cert_after, "CA cert was regenerated");
        assert_eq!(key_before, key_after, "CA key was regenerated");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_owner_only_permissions() {
        // The CA private key is the thing that can sign certs for any host.
        // It must not be world-readable. This test pins 0o600 so a future
        // refactor that bypasses `write_key` is caught immediately.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let _ = load_or_create_ca(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(KEY_FILENAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key file mode is {mode:o}, expected 600");
    }
}
