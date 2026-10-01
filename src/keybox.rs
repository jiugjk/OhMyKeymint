use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock, RwLock,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::Encode;
use kmr_common::{
    crypto::{ec, rsa, KeyMaterial, Sha256},
    Error,
};
use kmr_crypto_boring::{ec::BoringEc, mldsa::BoringMlDsa, rsa::BoringRsa, sha256::BoringSha256};
use kmr_ta::device::{
    RetrieveCertSigningInfo, SigningAlgorithm, SigningInfoSnapshot, SigningKeyType,
};
use kmr_wire::keymint;
use log::{debug, error, info, warn};
use regex::Regex;
use x509_cert::der as x509_der;
use x509_cert::Certificate;

pub const KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";

const BUNDLED_KEYBOX_XML: &str = include_str!("../template/keybox.xml");

lazy_static::lazy_static! {
    pub static ref KEYBOX: RwLock<KeyBox> = RwLock::new(KeyBox::new());
    static ref KEYBOX_IO_LOCK: Mutex<()> = Mutex::new(());
    static ref KEY_BLOCK_RE: Regex =
        Regex::new(r#"(?s)<Key\s+algorithm="([^"]+)">\s*(.*?)\s*</Key>"#).unwrap();
    static ref PRIVATE_KEY_RE: Regex =
        Regex::new(r#"(?s)<PrivateKey[^>]*>\s*(.*?)\s*</PrivateKey>"#).unwrap();
    static ref CERT_COUNT_RE: Regex =
        Regex::new(r#"(?s)<NumberOfCertificates>\s*(\d+)\s*</NumberOfCertificates>"#).unwrap();
    static ref CERT_RE: Regex =
        Regex::new(r#"(?s)<Certificate(?:\s+[^>]*)?>\s*(.*?)\s*</Certificate>"#).unwrap();
}

static KEYBOX_WATCHER: OnceLock<()> = OnceLock::new();
static KEYBOX_DB_RETIRE_ALLOWED: AtomicBool = AtomicBool::new(false);
static KEYBOX_RUNTIME_LOADED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct CertSignAlgoInfo {
    key: KeyMaterial,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
}

#[derive(Clone)]
pub struct KeyBox {
    rsa_info: Option<CertSignAlgoInfo>,
    ec_info: Option<CertSignAlgoInfo>,
    identity_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum KeyAlgorithm {
    Ec,
    Rsa,
}

struct ParsedKeyEntry {
    key_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

impl KeyBox {
    pub fn new() -> Self {
        Self::from_xml_str(BUNDLED_KEYBOX_XML).expect("bundled keybox.xml must be valid")
    }

    pub fn from_xml_str(xml: &str) -> Result<Self> {
        let mut rsa_entry = None;
        let mut ec_entry = None;

        for captures in KEY_BLOCK_RE.captures_iter(xml) {
            let algorithm = match captures.get(1).map(|m| m.as_str().trim()) {
                Some("ecdsa") | Some("ec") => KeyAlgorithm::Ec,
                Some("rsa") => KeyAlgorithm::Rsa,
                Some(other) => bail!("unsupported key algorithm `{other}` in keybox.xml"),
                None => bail!("missing key algorithm in keybox.xml"),
            };
            let body = captures
                .get(2)
                .map(|m| m.as_str())
                .ok_or_else(|| anyhow!("missing key block body"))?;
            let entry = ParsedKeyEntry::from_xml_block(body).with_context(|| {
                format!("failed to parse {:?} key entry", algorithm_name(algorithm))
            })?;
            match algorithm {
                KeyAlgorithm::Ec => ec_entry = Some(entry),
                KeyAlgorithm::Rsa => rsa_entry = Some(entry),
            }
        }

        if rsa_entry.is_none() && ec_entry.is_none() {
            bail!("missing RSA or EC key entry in keybox.xml");
        }

        let rsa_info = rsa_entry.map(Self::build_rsa_info).transpose()?;
        let ec_info = ec_entry.map(Self::build_ec_info).transpose()?;
        let identity_digest = Self::compute_identity_digest(&rsa_info, &ec_info)?;

        Ok(Self {
            rsa_info,
            ec_info,
            identity_digest,
        })
    }

    fn build_rsa_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("RSA certificate chain is empty");
        }
        let key = rsa::import_pkcs1_key(&entry.key_der)
            .map(|(key, _, _)| key)
            .map_err(|e| anyhow!("failed to import RSA private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Rsa)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn build_ec_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("EC certificate chain is empty");
        }
        let key = ec::import_sec1_private_key(&entry.key_der)
            .map_err(|e| anyhow!("failed to import EC private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Ec)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn compute_identity_digest(
        rsa_info: &Option<CertSignAlgoInfo>,
        ec_info: &Option<CertSignAlgoInfo>,
    ) -> Result<[u8; 32]> {
        let mut material = Vec::new();
        // Keep the existing digest for dual-algorithm keyboxes. Algorithm labels also
        // distinguish single-algorithm identities without inventing missing entries.
        if let Some(info) = rsa_info {
            append_labeled_bytes(&mut material, b"rsa-key", &info.key_der);
            append_labeled_chain(&mut material, b"rsa-chain", &info.chain);
        }
        if let Some(info) = ec_info {
            append_labeled_bytes(&mut material, b"ec-key", &info.key_der);
            append_labeled_chain(&mut material, b"ec-chain", &info.chain);
        }

        BoringSha256 {}
            .hash(&material)
            .map_err(|e| anyhow!("failed to hash keybox identity: {e:?}"))
    }

    fn refresh_identity_digest(&mut self) -> Result<()> {
        self.identity_digest = Self::compute_identity_digest(&self.rsa_info, &self.ec_info)?;
        Ok(())
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        // The hint describes the subject key, not a required issuer algorithm.
        // Select the key and its chain together when the preferred issuer is absent.
        let info = match key_type.algo_hint {
            SigningAlgorithm::Rsa => self.rsa_info.as_ref().or(self.ec_info.as_ref()),
            SigningAlgorithm::Ec => self.ec_info.as_ref().or(self.rsa_info.as_ref()),
        }
        .ok_or_else(|| {
            kmr_common::km_err!(AttestationKeysNotProvisioned, "no attestation signing key")
        })?;

        Ok(SigningInfoSnapshot {
            signing_key: info.key.clone(),
            cert_chain: info.chain.clone(),
            identity_digest: self.identity_digest,
        })
    }

    pub fn update_rsa_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Rsa, key_der, chain)
    }

    pub fn update_ec_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Ec, key_der, chain)
    }

    fn update_keybox(
        &mut self,
        algorithm: KeyAlgorithm,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        let entry = ParsedKeyEntry {
            key_der,
            chain: chain
                .into_iter()
                .map(|certificate| certificate.encoded_certificate)
                .collect(),
        };
        match algorithm {
            KeyAlgorithm::Ec => self.ec_info = Some(Self::build_ec_info(entry)?),
            KeyAlgorithm::Rsa => self.rsa_info = Some(Self::build_rsa_info(entry)?),
        }
        self.refresh_identity_digest()
    }

    pub fn to_xml_string(&self) -> String {
        format!(
            concat!(
                "<?xml version=\"1.0\"?>\n",
                "<AndroidAttestation>\n",
                "<NumberOfKeyboxes>1</NumberOfKeyboxes>\n",
                "<Keybox DeviceID=\"sw\">\n",
                "{}\n",
                "{}\n",
                "</Keybox>\n",
                "</AndroidAttestation>\n"
            ),
            self.to_xml_block(KeyAlgorithm::Ec),
            self.to_xml_block(KeyAlgorithm::Rsa),
        )
    }

    fn to_xml_block(&self, algorithm: KeyAlgorithm) -> String {
        let (name, private_label, info) = match algorithm {
            KeyAlgorithm::Ec => ("ecdsa", "EC PRIVATE KEY", &self.ec_info),
            KeyAlgorithm::Rsa => ("rsa", "RSA PRIVATE KEY", &self.rsa_info),
        };
        let Some(info) = info else {
            return String::new();
        };
        let certificates = info
            .chain
            .iter()
            .map(|certificate| {
                format!(
                    "<Certificate format=\"pem\">\n{}\n</Certificate>",
                    encode_pem_block("CERTIFICATE", &certificate.encoded_certificate)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            concat!(
                "<Key algorithm=\"{name}\">\n",
                "<PrivateKey format=\"pem\">\n",
                "{private_key}\n",
                "</PrivateKey>\n",
                "<CertificateChain>\n",
                "<NumberOfCertificates>{cert_count}</NumberOfCertificates>\n",
                "{certificates}\n",
                "</CertificateChain>\n",
                "</Key>"
            ),
            name = name,
            private_key = encode_pem_block(private_label, &info.key_der),
            cert_count = info.chain.len(),
            certificates = certificates,
        )
    }
}

impl Default for KeyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ParsedKeyEntry {
    fn from_xml_block(block: &str) -> Result<Self> {
        let private_key_pem = PRIVATE_KEY_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <PrivateKey> block")?;
        let key_der = decode_pem(private_key_pem)?;

        let expected_cert_count = CERT_COUNT_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <NumberOfCertificates> in certificate chain")?
            .parse::<usize>()
            .context("invalid certificate count in keybox.xml")?;

        let chain = CERT_RE
            .captures_iter(block)
            .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
            .map(decode_pem)
            .collect::<Result<Vec<_>>>()?;

        if chain.len() != expected_cert_count {
            bail!(
                "certificate count mismatch: declared {}, parsed {}",
                expected_cert_count,
                chain.len()
            );
        }

        Ok(Self { key_der, chain })
    }
}

fn append_labeled_bytes(buffer: &mut Vec<u8>, label: &[u8], data: &[u8]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
}

fn append_labeled_chain(buffer: &mut Vec<u8>, label: &[u8], chain: &[keymint::Certificate]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(chain.len() as u32).to_be_bytes());
    for certificate in chain {
        buffer.extend_from_slice(&(certificate.encoded_certificate.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&certificate.encoded_certificate);
    }
}

fn algorithm_name(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ec => "EC",
        KeyAlgorithm::Rsa => "RSA",
    }
}

fn validate_chain_matches_key(
    key: &KeyMaterial,
    chain: &[keymint::Certificate],
    algorithm: KeyAlgorithm,
) -> Result<()> {
    let first_cert = chain
        .first()
        .context("certificate chain must contain a leaf certificate")?;
    let certificate = <Certificate as x509_der::Decode>::from_der(&first_cert.encoded_certificate)
        .with_context(|| {
            format!(
                "failed to parse {} leaf certificate from keybox chain",
                algorithm_name(algorithm)
            )
        })?;
    let mut spki_buf = Vec::new();
    let derived_spki = key
        .subject_public_key_info(
            &mut spki_buf,
            &BoringEc::default(),
            &BoringRsa::default(),
            &BoringMlDsa,
        )
        .map_err(|e| {
            anyhow!(
                "failed to derive {} public key info from private key: {e:?}",
                algorithm_name(algorithm)
            )
        })?
        .context("symmetric key cannot back an attestation certificate")?
        .to_der()
        .with_context(|| {
            format!(
                "failed to encode {} public key info from private key",
                algorithm_name(algorithm)
            )
        })?;
    let certificate_spki =
        x509_der::Encode::to_der(certificate.tbs_certificate().subject_public_key_info())
            .with_context(|| {
                format!(
                    "failed to encode {} public key info from certificate chain",
                    algorithm_name(algorithm)
                )
            })?;
    if derived_spki != certificate_spki {
        bail!(
            "{} certificate chain does not match the supplied private key",
            algorithm_name(algorithm)
        );
    }
    Ok(())
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();

    if base64_body.is_empty() {
        bail!("empty PEM payload");
    }

    STANDARD
        .decode(base64_body.as_bytes())
        .context("failed to decode PEM payload")
}

fn encode_pem_block(label: &str, der: &[u8]) -> String {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    let base64 = STANDARD.encode(der);
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

fn temp_keybox_path(path: &str) -> PathBuf {
    let target = Path::new(path);
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("keybox.xml");
    let temp_name = format!(".{file_name}.tmp-{}", std::process::id());
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

fn write_keybox_xml(path: &str, xml: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create keybox directory {}", parent.display()))?;
    }
    let temp_path = temp_keybox_path(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .with_context(|| {
                format!(
                    "failed to open temporary keybox.xml {}",
                    temp_path.display()
                )
            })?;
        file.write_all(xml.as_bytes()).with_context(|| {
            format!(
                "failed to write temporary keybox.xml {}",
                temp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temporary keybox.xml {}",
                temp_path.display()
            )
        })?;
    }

    #[cfg(windows)]
    if Path::new(path).exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace keybox.xml at {path} on Windows"))?;
    }

    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to atomically replace keybox.xml at {path}"))
}

fn write_bundled_keybox(path: &str) -> Result<()> {
    write_keybox_xml(path, BUNDLED_KEYBOX_XML)
}

pub fn ensure_keybox_file(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }
    info!("keybox.xml missing at {}; seeding bundled template", path);
    write_bundled_keybox(path)
}

fn is_bundled_keybox_xml(xml: &str) -> bool {
    xml.trim() == BUNDLED_KEYBOX_XML.trim()
}

fn retire_stale_keybox_bound_entries(current_identity: [u8; 32]) {
    if !db_retirement_allowed() {
        warn!("skipping stale keybox-bound DB retirement while active keybox came from fallback");
        return;
    }

    match crate::global::DB.with(|db| {
        db.borrow_mut()
            .retire_stale_keybox_bound_entries(current_identity)
    }) {
        Ok(0) => debug!("no stale keybox-bound key entries needed retirement"),
        Ok(retired) => info!("retired {retired} stale keybox-bound key entries"),
        Err(error) => error!("failed to retire stale keybox-bound key entries: {error:#}"),
    }
}

fn install_keybox(
    new_keybox: KeyBox,
    retire_db_entries: bool,
    db_retirement_allowed: bool,
) -> bool {
    let new_identity = new_keybox.identity_digest();
    let changed = {
        let mut keybox = KEYBOX.write().unwrap();
        let changed = keybox.identity_digest() != new_identity;
        *keybox = new_keybox;
        changed
    };
    KEYBOX_DB_RETIRE_ALLOWED.store(db_retirement_allowed, Ordering::Release);
    KEYBOX_RUNTIME_LOADED.store(true, Ordering::Release);

    if changed {
        crate::keymaster::keymint_device::clear_initialized_attestation_caches();
    }

    if retire_db_entries {
        retire_stale_keybox_bound_entries(new_identity);
    }

    changed
}

pub fn db_retirement_allowed() -> bool {
    KEYBOX_DB_RETIRE_ALLOWED.load(Ordering::Acquire)
}

fn is_fallback_continuation(keybox: &KeyBox, contents: &str) -> bool {
    let current_identity = KEYBOX
        .read()
        .map(|current| current.identity_digest())
        .unwrap_or([0u8; 32]);
    is_fallback_continuation_with_state(
        keybox,
        contents,
        KEYBOX_RUNTIME_LOADED.load(Ordering::Acquire),
        db_retirement_allowed(),
        current_identity,
    )
}

fn is_fallback_continuation_with_state(
    keybox: &KeyBox,
    contents: &str,
    runtime_loaded: bool,
    retirement_allowed: bool,
    current_identity: [u8; 32],
) -> bool {
    runtime_loaded
        && !retirement_allowed
        && is_bundled_keybox_xml(contents)
        && current_identity == keybox.identity_digest()
}

fn load_keybox_with_fallback(path: &str) -> Result<(KeyBox, bool)> {
    match fs::read_to_string(path) {
        Ok(contents) => match KeyBox::from_xml_str(&contents) {
            Ok(keybox) => {
                let fallback_origin = is_fallback_continuation(&keybox, &contents);
                Ok((keybox, fallback_origin))
            }
            Err(error) => {
                warn!(
                    "invalid keybox.xml at {}: {:#}; rewriting bundled template",
                    path, error
                );
                write_bundled_keybox(path)?;
                Ok((KeyBox::new(), true))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!("keybox.xml missing at {}; writing bundled template", path);
            write_bundled_keybox(path)?;
            Ok((KeyBox::new(), true))
        }
        Err(error) => Err(error).with_context(|| format!("failed to read keybox.xml from {path}")),
    }
}

pub fn reload_from_disk() -> Result<bool> {
    reload_from_disk_inner(true)
}

fn reload_from_disk_inner(retire_db_entries: bool) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, used_fallback) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let changed = install_keybox(keybox, retire_db_entries, !used_fallback);
    if changed {
        info!(
            "active keybox identity updated from {} (fallback={})",
            KEYBOX_PATH, used_fallback
        );
    } else {
        debug!(
            "keybox reload completed without identity change (fallback={})",
            used_fallback
        );
    }
    Ok(changed)
}

pub fn initialize() -> Result<()> {
    ensure_keybox_file(KEYBOX_PATH)?;
    reload_from_disk_inner(false)?;
    KEYBOX_WATCHER.get_or_init(|| {
        if let Err(error) = kmr_common::runtime::file_watch::spawn_path_watcher(
            "omk-keybox-watch",
            PathBuf::from(KEYBOX_PATH),
            |_trigger| {
                if let Err(reload_error) = reload_from_disk() {
                    error!("failed to reload keybox.xml after change: {reload_error:#}");
                }
            },
        ) {
            error!("failed to watch keybox.xml: {error:#}");
        }
    });
    Ok(())
}

pub fn update_rsa_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Rsa, key_der, chain)
}

pub fn update_ec_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Ec, key_der, chain)
}

fn update_keybox_file(
    algorithm: KeyAlgorithm,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let mut keybox = KEYBOX.read().unwrap().clone();
    keybox.update_keybox(algorithm, key_der, chain)?;
    write_keybox_xml(KEYBOX_PATH, &keybox.to_xml_string())?;
    Ok(install_keybox(keybox, true, true))
}

pub fn current_identity_digest() -> [u8; 32] {
    KEYBOX.read().unwrap().identity_digest()
}

pub(crate) fn signing_certificate_ders_from_disk() -> Result<Vec<Vec<u8>>> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, _) = load_keybox_with_fallback(KEYBOX_PATH)?;
    Ok([keybox.rsa_info, keybox.ec_info]
        .into_iter()
        .flatten()
        .map(|info| info.chain[0].encoded_certificate.clone())
        .collect())
}

pub struct KeyboxManager;

impl RetrieveCertSigningInfo for KeyboxManager {
    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        let keybox = KEYBOX
            .read()
            .map_err(|_| kmr_common::km_err!(UnknownError, "failed to lock KEYBOX"))?;
        keybox.signing_info(key_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::SigningKey;

    fn write_temp_keybox(name: &str, contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::Builder::new()
            .prefix(&format!("omk-keybox-{name}-"))
            .suffix(".xml")
            .tempfile()
            .unwrap();
        fs::write(file.path(), contents).unwrap();
        file
    }

    fn single_algorithm_xml(algorithm: &str) -> String {
        KEY_BLOCK_RE
            .replace_all(BUNDLED_KEYBOX_XML, |captures: &regex::Captures<'_>| {
                if &captures[1] == algorithm {
                    captures[0].to_owned()
                } else {
                    String::new()
                }
            })
            .into_owned()
    }

    #[test]
    fn parses_bundled_template() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        assert_eq!(keybox.ec_info.as_ref().unwrap().chain.len(), 2);
        assert_eq!(keybox.rsa_info.as_ref().unwrap().chain.len(), 2);
        // The original identity must survive this format extension so existing
        // keys bound to a dual-algorithm keybox are not retired on upgrade.
        assert_eq!(
            hex::encode(keybox.identity_digest()),
            "9c747f8d8b7d3f2b4e5e95b3e783b786f9bab233b642f9a5bf4d78b7bce2c7fe"
        );
    }

    #[test]
    fn rejects_invalid_xml() {
        assert!(KeyBox::from_xml_str("<AndroidAttestation/>").is_err());
    }

    #[test]
    fn identity_changes_when_chain_changes() {
        let original = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let mut changed = original.clone();
        let info = changed.ec_info.as_mut().unwrap();
        info.chain.push(info.chain[0].clone());
        changed.refresh_identity_digest().unwrap();

        let modified = KeyBox::from_xml_str(&changed.to_xml_string()).unwrap();
        assert_ne!(original.identity_digest(), modified.identity_digest());
    }

    #[test]
    fn rejects_mismatched_private_key_and_certificate_chain() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let rsa_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.rsa_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let ec_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.ec_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let modified_xml = BUNDLED_KEYBOX_XML.replacen(&rsa_cert, &ec_cert, 1);
        assert!(KeyBox::from_xml_str(&modified_xml).is_err());
    }

    #[test]
    fn signing_snapshot_keeps_key_chain_and_digest_in_sync() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        let rsa_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();
        assert_eq!(rsa_snapshot.identity_digest, keybox.identity_digest());
        assert!(matches!(rsa_snapshot.signing_key, KeyMaterial::Rsa(_)));
        validate_chain_matches_key(
            &rsa_snapshot.signing_key,
            &rsa_snapshot.cert_chain,
            KeyAlgorithm::Rsa,
        )
        .unwrap();

        let ec_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Ec,
            })
            .unwrap();
        assert_eq!(ec_snapshot.identity_digest, keybox.identity_digest());
        assert!(matches!(ec_snapshot.signing_key, KeyMaterial::Ec(_, _, _)));
        validate_chain_matches_key(
            &ec_snapshot.signing_key,
            &ec_snapshot.cert_chain,
            KeyAlgorithm::Ec,
        )
        .unwrap();
    }

    #[test]
    fn single_algorithm_files_are_loaded_without_rewriting() {
        for algorithm in ["ecdsa", "rsa"] {
            let xml = single_algorithm_xml(algorithm);
            let file = write_temp_keybox(algorithm, &xml);
            let (keybox, used_fallback) =
                load_keybox_with_fallback(file.path().to_str().unwrap()).unwrap();
            assert!(!used_fallback);
            assert_eq!(fs::read_to_string(file.path()).unwrap(), xml);
            assert_eq!(keybox.ec_info.is_some(), algorithm == "ecdsa");
            assert_eq!(keybox.rsa_info.is_some(), algorithm == "rsa");

            let written = keybox.to_xml_string();
            assert_eq!(KEY_BLOCK_RE.captures_iter(&written).count(), 1);
            assert!(written.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));
            let reloaded = KeyBox::from_xml_str(&written).unwrap();
            assert_eq!(reloaded.identity_digest(), keybox.identity_digest());
        }
    }

    #[test]
    fn single_algorithm_signing_keeps_the_available_key_and_chain_for_both_hints() {
        let bundled = KeyBox::new();
        for algorithm in ["ecdsa", "rsa"] {
            let keybox = KeyBox::from_xml_str(&single_algorithm_xml(algorithm)).unwrap();
            let expected_info = if algorithm == "ecdsa" {
                bundled.ec_info.as_ref().unwrap()
            } else {
                bundled.rsa_info.as_ref().unwrap()
            };
            for which in [SigningKey::Batch, SigningKey::DeviceUnique] {
                for algo_hint in [SigningAlgorithm::Rsa, SigningAlgorithm::Ec] {
                    let snapshot = keybox
                        .signing_info(SigningKeyType { which, algo_hint })
                        .unwrap();
                    assert_eq!(snapshot.cert_chain, expected_info.chain);
                    assert_eq!(snapshot.identity_digest, keybox.identity_digest());
                    let actual_algorithm = match &snapshot.signing_key {
                        KeyMaterial::Rsa(_) => {
                            assert_eq!(algorithm, "rsa");
                            KeyAlgorithm::Rsa
                        }
                        KeyMaterial::Ec(_, _, _) => {
                            assert_eq!(algorithm, "ecdsa");
                            KeyAlgorithm::Ec
                        }
                        _ => panic!("unexpected attestation key material"),
                    };
                    validate_chain_matches_key(
                        &snapshot.signing_key,
                        &snapshot.cert_chain,
                        actual_algorithm,
                    )
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn single_algorithm_keybox_updates_preserve_other_entries_and_identity() {
        let bundled = KeyBox::new();
        let ec_only = KeyBox::from_xml_str(&single_algorithm_xml("ecdsa")).unwrap();
        let rsa_only = KeyBox::from_xml_str(&single_algorithm_xml("rsa")).unwrap();
        assert_ne!(ec_only.identity_digest(), rsa_only.identity_digest());
        for mut keybox in [ec_only, rsa_only] {
            assert_ne!(keybox.identity_digest(), bundled.identity_digest());
            // Updating an existing algorithm must not populate the missing one.
            let (algorithm, info) = if let Some(info) = keybox.ec_info.as_ref() {
                (KeyAlgorithm::Ec, info)
            } else {
                (KeyAlgorithm::Rsa, keybox.rsa_info.as_ref().unwrap())
            };
            let identity = keybox.identity_digest();
            keybox
                .update_keybox(algorithm, info.key_der.clone(), info.chain.clone())
                .unwrap();
            assert_eq!(keybox.identity_digest(), identity);
            assert_eq!(
                KEY_BLOCK_RE.captures_iter(&keybox.to_xml_string()).count(),
                1
            );

            let (missing_algorithm, missing_info) = if keybox.ec_info.is_some() {
                (KeyAlgorithm::Rsa, bundled.rsa_info.as_ref().unwrap())
            } else {
                (KeyAlgorithm::Ec, bundled.ec_info.as_ref().unwrap())
            };
            keybox
                .update_keybox(
                    missing_algorithm,
                    missing_info.key_der.clone(),
                    missing_info.chain.clone(),
                )
                .unwrap();
            let reloaded = KeyBox::from_xml_str(&keybox.to_xml_string()).unwrap();
            assert_eq!(reloaded.identity_digest(), bundled.identity_digest());
            assert!(reloaded.ec_info.is_some());
            assert!(reloaded.rsa_info.is_some());
        }
    }

    #[test]
    fn malformed_supplied_entries_are_not_treated_as_missing() {
        for algorithm in ["ecdsa", "rsa"] {
            let xml = single_algorithm_xml(algorithm);
            let bad_count = xml.replacen("<NumberOfCertificates>2", "<NumberOfCertificates>3", 1);
            assert!(KeyBox::from_xml_str(&bad_count).is_err());
            let other_cert = if algorithm == "ecdsa" {
                KeyBox::new().rsa_info.unwrap().chain.remove(0)
            } else {
                KeyBox::new().ec_info.unwrap().chain.remove(0)
            };
            let mismatched = CERT_RE.replace(
                &xml,
                format!(
                    "<Certificate format=\"pem\">\n{}\n</Certificate>",
                    encode_pem_block("CERTIFICATE", &other_cert.encoded_certificate),
                ),
            );
            assert!(KeyBox::from_xml_str(&mismatched).is_err());
            let damaged_other_entry = xml.replace(
                "</Keybox>",
                &format!(
                    "<Key algorithm=\"{}\"><PrivateKey>invalid</PrivateKey></Key>\n</Keybox>",
                    if algorithm == "rsa" { "ecdsa" } else { "rsa" },
                ),
            );
            assert!(KeyBox::from_xml_str(&damaged_other_entry).is_err());
        }
    }

    #[test]
    fn invalid_file_falls_back_to_bundled_template() {
        let file = write_temp_keybox("invalid", "<not-xml>");
        let (keybox, used_fallback) =
            load_keybox_with_fallback(file.path().to_str().unwrap()).unwrap();
        assert!(used_fallback);
        assert_eq!(keybox.identity_digest(), KeyBox::new().identity_digest());
        let written = fs::read_to_string(file.path()).unwrap();
        assert!(written.contains("<AndroidAttestation>"));
    }

    #[test]
    fn explicit_bundled_template_is_retirement_eligible_before_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            false,
            false,
            keybox.identity_digest(),
        ));
    }

    #[test]
    fn non_bundled_keybox_is_retirement_eligible() {
        let modified_xml = format!("{BUNDLED_KEYBOX_XML}\n<!-- explicit local keybox -->\n");
        let file = write_temp_keybox("modified", &modified_xml);

        let (_, used_fallback) = load_keybox_with_fallback(file.path().to_str().unwrap()).unwrap();

        assert!(!used_fallback);
    }

    #[test]
    fn rewritten_bundled_template_can_continue_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            false,
            keybox.identity_digest(),
        ));
        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            true,
            keybox.identity_digest(),
        ));
    }
}
