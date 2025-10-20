use std::collections::HashMap;
use aes::{Aes128, Aes256};
use anyhow::{bail, Context, Result};
use cipher::{Block, BlockDecrypt, KeyInit};
use des::TdesEde3;
use hkdf::Hkdf;
use sha2::Sha256;
use spki::ObjectIdentifier;
use x509_parser::prelude::*;

/// The default administrator key for Nitrokey
pub const DEFAULT_ADMIN_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

#[allow(dead_code)]
pub(crate) const ALGO_RSA2048: u8 = 0x07;
pub(crate) const ALGO_NISTP256: u8 = 0x11;
pub(crate) const ALGO_NISTP384: u8 = 0x14;

/// PIV key slot identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PivSlot {
    /// 9A - PIV Authentication (signing, key management)
    Authentication = 0x9A,
    /// 9C - Digital Signature (signing only)
    Signature = 0x9C,
    /// 9D - Key Management (encryption/decryption)
    KeyManagement = 0x9D,
    /// 9E - Card Authentication (signing, key management)
    CardAuthentication = 0x9E,
    /// 82-95 - Retired Key Management slots
    Retired1 = 0x82,
    Retired2 = 0x83,
    Retired3 = 0x84,
    Retired4 = 0x85,
    Retired5 = 0x86,
    Retired6 = 0x87,
    Retired7 = 0x88,
    Retired8 = 0x89,
    Retired9 = 0x8A,
    Retired10 = 0x8B,
    Retired11 = 0x8C,
    Retired12 = 0x8D,
    Retired13 = 0x8E,
    Retired14 = 0x8F,
    Retired15 = 0x90,
    Retired16 = 0x91,
    Retired17 = 0x92,
    Retired18 = 0x93,
    Retired19 = 0x94,
    Retired20 = 0x95,
}

impl PivSlot {
    /// Get the certificate object ID for this slot
    pub fn cert_object_id(&self) -> &'static [u8] {
        match self {
            Self::Authentication => &[0x5F, 0xC1, 0x05],
            Self::Signature => &[0x5F, 0xC1, 0x0A],
            Self::KeyManagement => &[0x5F, 0xC1, 0x0B],
            Self::CardAuthentication => &[0x5F, 0xC1, 0x01],
            Self::Retired1 => &[0x5F, 0xC1, 0x0D],
            Self::Retired2 => &[0x5F, 0xC1, 0x0E],
            Self::Retired3 => &[0x5F, 0xC1, 0x0F],
            Self::Retired4 => &[0x5F, 0xC1, 0x10],
            Self::Retired5 => &[0x5F, 0xC1, 0x11],
            Self::Retired6 => &[0x5F, 0xC1, 0x12],
            Self::Retired7 => &[0x5F, 0xC1, 0x13],
            Self::Retired8 => &[0x5F, 0xC1, 0x14],
            Self::Retired9 => &[0x5F, 0xC1, 0x15],
            Self::Retired10 => &[0x5F, 0xC1, 0x16],
            Self::Retired11 => &[0x5F, 0xC1, 0x17],
            Self::Retired12 => &[0x5F, 0xC1, 0x18],
            Self::Retired13 => &[0x5F, 0xC1, 0x19],
            Self::Retired14 => &[0x5F, 0xC1, 0x1A],
            Self::Retired15 => &[0x5F, 0xC1, 0x1B],
            Self::Retired16 => &[0x5F, 0xC1, 0x1C],
            Self::Retired17 => &[0x5F, 0xC1, 0x1D],
            Self::Retired18 => &[0x5F, 0xC1, 0x1E],
            Self::Retired19 => &[0x5F, 0xC1, 0x1F],
            Self::Retired20 => &[0x5F, 0xC1, 0x20],
        }
    }

    /// Get slot ID as u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Return the **expected** PIN policy for a given PIV slot.
    /// This is the **factory-default** behavior on YubiKey 5 / Nitrokey 3
    /// until we query the real policy with the vendor-specific GET-METADATA command.
    pub fn pin_policy(&self) -> PinPolicy {
        use PivSlot::*;
        match &self {
            // NIST-mandated: 9C must prompt **every time** (legal intent)
            Signature => PinPolicy::Always,

            // 9E is **never** protected – physical tap only
            CardAuthentication => PinPolicy::Never,

            // Everything else is **unlocked once** after PIN verify
            Authentication | KeyManagement  => PinPolicy::Once,
            _ => PinPolicy::Once,
        }
    }
}

impl TryFrom<u8> for PivSlot {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self> {
        use PivSlot::*;
        Ok(match byte {
            0x9A => Authentication,
            0x9C => Signature,
            0x9D => KeyManagement,
            0x9E => CardAuthentication,
            0x82..=0x95 => {
                // Map 0x82 → Retired1, 0x83 → Retired2, …, 0x95 → Retired20
                let idx = byte.saturating_sub(0x82);
                if idx > 19 {
                    bail!("Retired slot index {} out of range 0-19", idx);
                }
                // SAFETY: idx is 0..=19
                unsafe { std::mem::transmute(Retired1.as_u8() + idx) }
            }
            _ => bail!("Unknown PIV slot byte 0x{:02X}", byte),
        })
    }
}

/// Default PIN policy per slot (NIST + vendor conventions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    /// Never ask for PIN (slot 9E, some retired keys)
    Never,
    /// Ask once per session (most slots)
    Once,
    /// Ask before **every** private-key operation (slot 9C)
    Always,
}

impl PinPolicy {
    /// Human-readable short name
    pub fn as_str(&self) -> &'static str {
        match self {
            PinPolicy::Never => "never",
            PinPolicy::Once  => "once",
            PinPolicy::Always=> "always",
        }
    }
}

/// Supported elliptic curves for PIV
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    /// NIST P-256 (secp256r1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
}

impl EccCurve {
    /// Get the PIV algorithm identifier byte
    pub fn algorithm_id(&self) -> u8 {
        match self {
            Self::P256 => 0x11,
            Self::P384 => 0x14,
        }
    }

    /// Get the expected public key length in bytes
    pub fn public_key_len(&self) -> usize {
        match self {
            Self::P256 => 65, // 0x04 || x (32 bytes) || y (32 bytes)
            Self::P384 => 97, // 0x04 || x (48 bytes) || y (48 bytes)
        }
    }
}

/// Certificate subject information
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct CertificateSubject {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
}

/// Parse a DN-style string into a CertificateSubject structure.
///
/// Example accepted formats:
/// - "CN=Alice, O=Acme Corp, OU=Dev, C=US"
/// - "C=US, O=Acme Corp, CN=Alice"
/// - "CN=Alice"
///
/// Whitespace around commas and equal signs is ignored.
/// Unknown fields are ignored.
pub fn parse_certificate_subject(input: &str) -> Result<CertificateSubject, String> {
    if input.trim().is_empty() {
        return Err("Empty subject string".into());
    }

    let mut map = HashMap::new();

    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut kv = trimmed.splitn(2, '=');
        let key = kv.next().ok_or("Malformed key=value pair")?.trim().to_uppercase();
        let value = kv
            .next()
            .ok_or_else(|| format!("Missing value for key '{}'", key))?
            .trim()
            .to_string();

        if value.is_empty() {
            return Err(format!("Empty value for key '{}'", key));
        }

        map.insert(key, value);
    }

    let common_name = map
        .remove("CN")
        .ok_or_else(|| "Missing required field: CN".to_string())?;

    Ok(CertificateSubject {
        common_name,
        organization: map.remove("O"),
        organizational_unit: map.remove("OU"),
        country: map.remove("C"),
    })
}

/// Public key returned from key generation
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// A kind of Curve
    pub curve: EccCurve,
    /// Curve's point X
    pub x: Vec<u8>,
    /// Curve's point Y
    pub y: Vec<u8>,
}

impl PublicKey {
    /// Get the uncompressed point format (0x04 || x || y)
    pub fn to_uncompressed_point(&self) -> Vec<u8> {
        let mut point = vec![0x04];
        point.extend_from_slice(&self.x);
        point.extend_from_slice(&self.y);
        point
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = anyhow::Error;

    /// Parse an uncompressed EC point: 0x04 || x || y
    fn try_from(point: &[u8]) -> Result<Self> {
        // minimal length check
        if point.len() < 65 {
            bail!("Uncompressed point too short: {} bytes", point.len());
        }
        // format byte
        if point[0] != 0x04 {
            bail!("Point is not uncompressed (first byte {:02X})", point[0]);
        }

        // coordinate lengths (P-256 or P-384)
        let coord_len = (point.len() - 1) / 2; // 32 or 48
        // map coordinate length → curve
        let curve = match coord_len {
            32 => EccCurve::P256,
            48 => EccCurve::P384,
            _  => bail!("Unknown curve (coordinate length {})", coord_len),
        };

        // split coordinates
        let x = point[1..1 + coord_len].to_vec();
        let y = point[1 + coord_len..].to_vec();

        Ok(PublicKey { curve, x, y })
    }
}

/// Convert bytes array to HEX format
pub fn to_hex(buf: &[u8]) -> String {
    let mut result = String::new();
    for x in buf.iter() {
        result.push_str(&format!("{:01$X}", x, 2));
    }
    result
}

/// Parse hex literal
pub fn from_hex(string: &str) -> Result<Vec<u8>, anyhow::Error> {
    match split_n(string.trim(), 2) {
        Ok(s) => {
            let results: Vec<_> = s.iter()
                .map(|b| u8::from_str_radix(b, 16))
                .collect();
            if results.iter().any(|r| r.is_err()) {
                bail!("Malformed hex string");
            }
            let result = results
                .into_iter()
                .filter(|r| r.is_ok())
                .map(|r| r.unwrap())
                .collect();
            Ok(result)
        }
        Err(e) => {
            bail!(e.to_string());
        }
    }
}

fn split_n(s: &str, n: usize) -> Result<Vec<&str>> {
    if s.len() % n != 0 {
        bail!("Invalid number of digits in string");
    }
    Ok((0..=(s.len() - n + 1) / 2)
        .map(|i| &s[2 * i..2 * i + n])
        .collect())
}

/// Low-level encryption helper: ECB encrypt (one block) with the chosen key
pub(crate) fn encrypt_challenge(key: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut block = plaintext.to_vec();

    // PIV specification (SP-800-73-4, part 2, §3.2.2) defines the admin-key operation as:
    // "The decrypt primitive of the block cipher is applied to the challenge."
    match key.len() {
        24 => {
            let cipher = TdesEde3::new_from_slice(key)?; // key len checked above
            let block_ref = Block::<TdesEde3>::from_mut_slice(&mut block);
            cipher.decrypt_block(block_ref);
        }
        16 => {
            let cipher = Aes128::new_from_slice(key)?;
            let mut block_ref = Block::<Aes128>::from_mut_slice(&mut block);
            cipher.decrypt_block(&mut block_ref);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)?;
            let block_ref = Block::<Aes256>::from_mut_slice(&mut block);
            cipher.decrypt_block(block_ref);
        }
        _ => unreachable!(),
    }

    Ok(block)
}

/// Parses certificate in DER format, and gets public key from it
pub fn read_pubkey_from_certificate(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Parse X.509
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .context("failed to parse certificate DER")?;

    // Extract subjectPublicKeyInfo
    let spki: &SubjectPublicKeyInfo = &cert.tbs_certificate.subject_pki;

    // For EC keys, the public key is the BIT STRING (uncompressed point usually prefixed by 0x04).
    // For RSA, you might want the whole SPKI DER instead (or the modulus/exponent).
    // Here we'll return:
    // - For EC: the raw BIT STRING bytes as stored (leading 0x04 + x + y)
    // - For RSA: the SPKI DER (pkcs#1 or SubjectPublicKeyInfo DER)
    match &spki.algorithm.algorithm {
        oid if *oid == oid_registry::OID_PKCS1_RSAENCRYPTION => {
            // return SPKI DER (encoded)
            let spki_der = cert.tbs_certificate.subject_pki.raw.to_owned();
            Ok(spki_der)
        }
        _ => {
            // For other curves (e.g. prime256v1), return the raw BIT STRING bytes
            let bitstring = spki.subject_public_key.data.to_vec();
            Ok(bitstring)
        }
    }
}

/// Parses certificate in DER format, and gets public key from it
pub fn read_subject_from_certificate(cert_der: &[u8]) -> Result<String, String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    // Get the subject
    let subject = cert.subject();

    // Build a formatted string
    let mut parts = Vec::new();

    for rdn in subject.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type();
            let value = attr.attr_value().as_str()
                .map_err(|e| format!("Failed to parse attribute value: {}", e))?;

            // Map common OIDs to their abbreviations
            let name = match oid.to_id_string().as_str() {
                "2.5.4.3" => "CN",    // Common Name
                "2.5.4.10" => "O",    // Organization
                "2.5.4.11" => "OU",   // Organizational Unit
                "2.5.4.6" => "C",     // Country
                "2.5.4.7" => "L",     // Locality
                "2.5.4.8" => "ST",    // State/Province
                _ => continue,         // Skip unknown attributes
            };

            parts.push(format!("{}={}", name, value));
        }
    }

    Ok(parts.join(", "))
}

/// Wraps shared secret using HKDF and given salt (can be empty)
pub fn wrap_key(shared_secret: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand");

    okm
}

/* ----------  OIDs we need ---------- */
pub(crate) const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");          // id-ecPublicKey

pub(crate) const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");        // ecdsa-with-SHA256
#[allow(dead_code)]
pub(crate) const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");        // ecdsa-with-SHA384

#[allow(dead_code)]
pub(crate) const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");        // secp256r1 / P-256
#[allow(dead_code)]
pub(crate) const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");               // secp384r1 / P-384

/* ----------  X.501 / RFC 5280 name-attribute OIDs ---------- */
pub(crate) const OID_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");          // id-at-commonName
pub(crate) const OID_AT_COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");          // id-at-countryName
pub(crate) const OID_AT_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");         // id-at-organizationName
pub(crate) const OID_AT_ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");         // id-at-organizationalUnitName

#[allow(dead_code)]
pub(crate) const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");