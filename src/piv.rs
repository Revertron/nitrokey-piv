use crate::apdu::{build_apdu, build_tlv, find_tlv_tag, parse_tlv, send_receive, transmit_apdu};
use crate::utils::encrypt_challenge;
use crate::{read_pubkey_from_certificate, utils, wrap_key, CertificateSubject, EccCurve, PivSlot, PublicKey};
use anyhow::{bail, Context, Result};
use der::asn1::{BitString, ObjectIdentifier, OctetString, Utf8StringRef};
use der::{Any, Encode, Tagged};
use pcsc::{Attribute, Card, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::ext::{AsExtension, Extensions};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};

/// Nitrokey Card wrapper that provides methods to work with PIV applet on the card.
pub struct Nitrokey3PIV {
    // Nitrokey card to work with
    card: Card,
    // Cached card serial
    serial: u32,
    // Name of the Nitrokey reader
    name: String
}

impl Nitrokey3PIV {
    /// Opens a connection to a Nitrokey 3 device with PIV application
    ///
    /// # Arguments
    /// * `serial` - Optional serial number to connect to a specific device.
    ///              If None and multiple devices are found, returns an error.
    ///
    /// # Returns
    /// * `Ok(Nitrokey3PIV)` - Successfully connected device
    /// * `Err` - If no device found, multiple devices found without serial specified,
    ///           or connection failed
    pub fn open(serial: Option<u32>) -> Result<Self> {
        // Expected ATR for Nitrokey 3
        const EXPECTED_ATR: &[u8] = &[
            0x3b, 0x8f, 0x01, 0x80, 0x5d, 0x4e, 0x69, 0x74,
            0x72, 0x6f, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x6a
        ];

        // PIV application AID
        const PIV_AID: &[u8] = &[
            0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
            0x00, 0x01, 0x00, 0x00
        ];

        // Establish PC/SC context
        let ctx = pcsc::Context::establish(Scope::System)
            .context("Failed to establish PC/SC context")?;

        // Get list of available readers
        let mut readers_buf = [0; 2048];
        let readers = ctx.list_readers(&mut readers_buf)
            .context("Failed to list card readers")?;

        let mut matching_cards = Vec::new();

        // Find all Nitrokey 3 devices
        for reader in readers {
            println!("Found {:?} reader", reader);
            // Try to connect to the card
            let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => card,
                Err(_) => continue, // No card in this reader, skip
            };
            println!("Got the card, reading attributes...");

            // Check ATR
            let atr = card.get_attribute_owned(Attribute::AtrString)
                .context("Failed to get ATR")?;

            if atr != EXPECTED_ATR {
                println!("Card {:?} is not Nitrokey 3", reader);
                continue; // Not a Nitrokey 3
            }

            // Try to select PIV application
            let select_apdu = [
                vec![0x00, 0xA4, 0x04, 0x00, PIV_AID.len() as u8],
                PIV_AID.to_vec(),
            ].concat();

            match transmit_apdu(&card, &select_apdu) {
                Ok(_) => {
                    println!("PIV application selected successfully!");
                }
                Err(e) => {
                    println!("Failed to select PIV application: {:?}", e);
                    continue;
                }
            }

            // Get serial number
            let card_serial = get_serial_number(&card)?;
            println!("Got serial number: {:04X}", card_serial);

            matching_cards.push((card, card_serial, reader.to_string_lossy()));
        }

        // Handle matching results
        match matching_cards.len() {
            0 => bail!("No Nitrokey 3 PIV device found"),
            1 => {
                let (card, found_serial, reader_name) = matching_cards.into_iter().next().unwrap();

                // If user specified a serial, verify it matches
                if let Some(requested_serial) = serial {
                    if requested_serial != found_serial {
                        bail!("Found Nitrokey 3 (serial: {:04X}) but requested serial {} was not found", found_serial, requested_serial);
                    }
                }

                println!("Connected to Nitrokey 3 (serial: {:04X}) on reader: {}", found_serial, reader_name);

                Ok(Self { card, serial: found_serial, name: reader_name.to_string() })
            }
            _ => {
                if let Some(requested_serial) = serial {
                    // Find the card with matching serial
                    for (card, found_serial, reader_name) in matching_cards {
                        if found_serial == requested_serial {
                            println!("Connected to Nitrokey 3 (serial: {:04X}) on reader: {}", found_serial, reader_name);
                            return Ok(Self { card, serial: found_serial, name: reader_name.to_string() });
                        }
                    }

                    bail!("No Nitrokey 3 with serial {:04X} found", requested_serial);
                } else {
                    // Multiple devices found, no serial specified
                    let serials: Vec<u32> = matching_cards.iter()
                        .map(|(_, serial, _)| *serial)
                        .collect();

                    bail!("Multiple Nitrokey 3 devices found. Please specify serial number. Available serials: {:?}", serials);
                }
            }
        }
    }

    /// Authenticates on PIV card using given admin key
    pub fn auth_admin(&self, admin_key: &[u8]) -> Result<()> {
        authenticate_admin(&self.card, admin_key)
    }

    /// Change the PIV management key (admin key).
    /// `new_key` must be 24 (3-DES), 16 (AES-128) or 32 (AES-256) bytes.
    pub fn set_admin_key(&self, admin_key: &[u8]) -> Result<()> {
        set_admin_key(&self.card, admin_key)
    }

    /// Authenticate user PIN
    pub fn verify_pin(&self, pin: &str) -> Result<()> {
        verify_pin(&self.card, pin)
    }

    /// Change user PIN
    pub fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<()> {
        change_pin(&self.card, old_pin, new_pin)
    }

    /// Change PUK (knowing the old one).
    /// PUK is **exactly** 8 bytes, **no padding**.
    pub fn change_puk(&self, old_puk: &str, new_puk: &str) -> Result<()> {
        change_puk(&self.card, old_puk, new_puk)
    }

    /// Unlock PIN with PUK and set a new PIN.
    pub fn reset_retry_counter(&self, puk: &str, new_pin: &str) -> Result<()> {
        reset_retry_counter(&self.card, puk, new_pin)
    }

    /// Factory-reset the PIV applet (card must be **PIN-blocked** first).
    pub fn factory_reset(&self) -> Result<()> {
        factory_reset(&self.card)
    }

    /// Sign data with given slot and ECC algo
    pub fn sign_data(&self, slot: PivSlot, ecc_curve: EccCurve, data: &[u8]) -> Result<Vec<u8>> {
        sign_data(&self.card, slot, ecc_curve, data)
    }

    /// Read the **raw public key** from any slot (no certificate needed).
    /// Returns the uncompressed EC point (65 bytes for P-256) or RSA pubkey DER.
    /// If the slot is empty returns Ok(None).
    pub fn read_public_key(&self, slot: PivSlot) -> Result<Option<Vec<u8>>> {
        read_public_key(&self.card, slot)
    }

    /// Generates a key in the given slot, builds **minimal** certificate,
    /// signs it with the **fresh** key, and stores it in given PIV slot.
    /// Returns public key from the fresh key-pair.
    pub fn generate_key_and_cert(&self, slot: PivSlot, subject: &CertificateSubject, curve: EccCurve, validity_days: u32) -> Result<PublicKey> {
        generate_key_and_cert(&self.card, slot, subject, curve, validity_days)
    }

    /// Perform ECDH with other party's public key. Returns wrapped key of the shared secret.
    pub fn ecdh(&self, slot: PivSlot, peer_point: &[u8], salt: Option<&[u8]>) -> Result<Vec<u8>> {
        let shared_point = ecdh(&self.card, slot, peer_point)?;
        Ok(wrap_key(&shared_point, salt).to_vec())
    }

    /// Perform ECDH with other party's public key. Returns unwrapped shared secret.
    pub fn ecdh_unwrapped(&self, slot: PivSlot, peer_point: &[u8]) -> Result<Vec<u8>> {
        ecdh(&self.card, slot, peer_point)
    }

    /// Write certificate into given PIV slot
    pub fn write_certificate(&self, slot: PivSlot, data: &[u8]) -> Result<()> {
        write_certificate(&self.card, slot, data)
    }

    /// Read the raw DER certificate from a PIV slot.
    /// Returns `None` if the slot is empty (status 6A82).
    pub fn read_certificate(&self, slot: PivSlot) -> Result<Option<Vec<u8>>> {
        read_certificate_from_slot(&self.card, slot)
    }

    /// Get serial number of PIV application on this card
    pub fn get_serial(&self) -> u32 {
        self.serial
    }

    /// Get name of this card
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get card GUID
    pub fn guid(&self) -> Result<[u8; 16]> {
        guid(&self.card)
    }
}

/// Pad a user PIN to exactly 8 bytes (0xFF padding) – same as Python.
fn encode_pin(pin: &str) -> Result<[u8; 8]> {
    let mut body = pin.as_bytes().to_vec();
    if body.len() > 8 {
        bail!("PIN can only be up to 8 bytes long");
    }
    body.resize(8, 0xFF); // right-pad with 0xFF
    Ok(body.try_into().unwrap()) // always 8 bytes
}

/// Verify user PIN (unlock private-key ops).
pub fn verify_pin(card: &Card, pin: &str) -> Result<()> {
    let body = encode_pin(pin)?;
    send_receive(card, 0x20, 0x00, 0x80, &body)?; // VERIFY
    Ok(())
}

/// Change user PIN (knowing the old one).
pub fn change_pin(card: &Card, old_pin: &str, new_pin: &str) -> Result<()> {
    let old = encode_pin(old_pin)?;
    let new = encode_pin(new_pin)?;
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&old);
    body.extend_from_slice(&new);
    send_receive(card, 0x24, 0x00, 0x80, &body)?; // CHANGE REFERENCE DATA (PIN)
    Ok(())
}

/// Change PUK (knowing the old one).
/// PUK is **exactly** 8 bytes, **no padding**.
pub fn change_puk(card: &Card, old_puk: &str, new_puk: &str) -> Result<()> {
    let old = old_puk.as_bytes();
    let new = new_puk.as_bytes();
    if old.len() != 8 || new.len() != 8 {
        bail!("PUK must be exactly 8 bytes long");
    }
    let body = [old, new].concat(); // 16 bytes total
    send_receive(card, 0x24, 0x00, 0x81, &body)?; // CHANGE REFERENCE DATA (PUK)
    Ok(())
}

/// Unlock PIN with PUK and set a new PIN.
pub fn reset_retry_counter(card: &Card, puk: &str, new_pin: &str) -> Result<()> {
    let puk_bytes = puk.as_bytes();
    if puk_bytes.len() != 8 {
        bail!("PUK must be exactly 8 bytes long");
    }
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(puk_bytes); // 8 bytes
    body.extend_from_slice(&encode_pin(new_pin)?); // 8 bytes (padded)
    send_receive(card, 0x2C, 0x00, 0x80, &body)?; // RESET RETRY COUNTER
    Ok(())
}

/// Factory-reset the PIV applet (card must be **PIN-blocked** first).
pub fn factory_reset(card: &Card) -> Result<()> {
    send_receive(card, 0xFB, 0x00, 0x00, &[])?; // no data, no Le
    Ok(())
}

/// Get card GUID
pub fn guid(card: &Card) -> Result<[u8; 16]> {
    let payload = build_tlv(&[(0x5C, b"\x5F\xC1\x02")]);
    let chuid = send_receive(card, 0xCB, 0x3F, 0xFF, &payload)?;

    let chuid_tlvs = parse_tlv(&chuid);
    let chuid_val = find_tlv_tag(&chuid_tlvs, 0x53).context("no CHUID wrapper")?;
    let tlv = parse_tlv(chuid_val);
    let guid_tlv = find_tlv_tag(&tlv, 0x34).context("no GUID inside CHUID")?;

    if guid_tlv.len() != 16 {
        bail!("GUID must be 16 bytes, got {}", guid_tlv.len());
    }
    Ok(guid_tlv.try_into().unwrap())
}


/// Helper function to get the serial number from a connected card
fn get_serial_number(card: &Card) -> Result<u32> {
    // Send GET DATA command for serial number
    // INS: 0x01, P1: 0x00, P2: 0x00
    let get_serial_apdu = [0x00, 0x01, 0x00, 0x00, 0x00];

    let mut response_buf = [0; MAX_BUFFER_SIZE];
    let response = card.transmit(&get_serial_apdu, &mut response_buf)
        .context("Failed to get serial number")?;

    // Check status bytes
    if response.len() < 2 {
        bail!("Invalid response when getting serial number");
    }

    let status = &response[response.len() - 2..];
    if status != [0x90, 0x00] {
        bail!("Failed to get serial number: status {:02X}{:02X}", status[0], status[1]);
    }

    // Serial number is in the response data (before status bytes)
    let data = &response[..response.len() - 2];
    if data.len() != 4 {
        bail!("Unexpected serial number length: {}", data.len());
    }

    // Convert bytes to u32 (big-endian)
    let serial = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    Ok(serial)
}

/// Sign data using the key in the specified slot
pub fn sign_data(card: &Card, slot: PivSlot, curve: EccCurve, data: &[u8]) -> Result<Vec<u8>> {
    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Build GENERAL AUTHENTICATE command for signing
    let body = build_tlv(&[
        (0x7C, &build_tlv(&[
            (0x81, hash.as_slice()),
            (0x82, &[]), // Empty - we want the signature back
        ]))
    ]);

    // INS: 0x87 (GENERAL AUTHENTICATE)
    // P1: algorithm
    // P2: key reference
    let response = send_receive(card, 0x87, curve.algorithm_id(), slot.as_u8(), &body)?;

    // Parse response
    let data = parse_tlv(&response);
    let auth_data = find_tlv_tag(&data, 0x7C)
        .context("Failed to get response to GENERAL AUTHENTICATE")?;

    let auth_data_parsed = parse_tlv(auth_data);
    let signature = find_tlv_tag(&auth_data_parsed, 0x82)
        .context("Failed to get signature from device")?;

    Ok(signature.to_vec())
}

/// Raw ECDH cofactor primitive. Returns the X-coordinate of the shared secret.
pub fn ecdh(card: &Card, slot: PivSlot, peer_point: &[u8]) -> Result<Vec<u8>> {
    // peer_point must be 0x04 || X || Y, 65 bytes for P-256 or 97 for P-384
    let body = build_tlv(&[
        (0x7C, &build_tlv(&[
            (0x82, &[]),        // empty (request)
            (0x85, peer_point), // peer public key
        ]))
    ]);

    // P1 = curve, P2 = key slot
    let algo = match peer_point.len() {
        65 => utils::ALGO_NISTP256,   // 0x11
        97 => utils::ALGO_NISTP384,   // 0x14
        _  => bail!("Bad peer-point length"),
    };
    let rsp = send_receive(card, 0x87, algo, slot.as_u8(), &body)?;

    let tlvs = parse_tlv(&rsp);
    let outer = find_tlv_tag(&tlvs, 0x7C).context("no 0x7C container")?;
    let inner = parse_tlv(outer);
    let z = find_tlv_tag(&inner, 0x82).context("no shared secret Z")?;
    Ok(z.to_vec())
}

/// Write a certificate to the device
pub fn write_certificate(card: &Card, slot: PivSlot, cert_der: &[u8]) -> Result<()> {
    let payload = build_tlv(&[
        (0x5C, slot.cert_object_id()),
        (0x53, &build_tlv(&[
            (0x70, cert_der),
            (0x71, &[0]), // CertInfo - uncompressed
        ]))
    ]);

    // INS: 0xDB (PUT DATA)
    // P1: 0x3F, P2: 0xFF
    send_receive(card, 0xDB, 0x3F, 0xFF, &payload)?;
    Ok(())
}

/// Read the raw DER certificate from a PIV slot.
/// Returns `None` if the slot is empty (status 6A82).
pub fn read_certificate_from_slot(card: &Card, slot: PivSlot) -> Result<Option<Vec<u8>>> {
    let container = slot.cert_object_id();
    read_certificate_from_container(card, container)
}

/// Read the raw DER certificate from a container slot.
/// `container_id` is the 3-byte object identifier (e.g. 5F C1 0A for slot 9C).
/// Returns `None` if the slot is empty (status 6A82).
pub fn read_certificate_from_container(card: &Card, container_id: &[u8]) -> Result<Option<Vec<u8>>> {
    let payload = build_tlv(&[(0x5C, container_id)]);
    let resp = match send_receive(card, 0xCB, 0x3F, 0xFF, &payload) {
        Ok(r) => r,
        Err(e) if e.to_string().contains("6A 82") => return Ok(None),
        Err(e) => return Err(e),
    };

    let outer = parse_tlv(&resp);
    if outer.len() != 1 || outer[0].0 != 0x53 {
        bail!("Bad outer TLV (expected single 0x53)");
    }
    let inner = parse_tlv(&outer[0].1);
    if inner.is_empty() || inner[0].0 != 0x70 {
        bail!("Bad inner TLV (expected 0x70 certificate)");
    }
    Ok(Some(inner[0].1.clone()))
}

/// Authenticate to the PIV card with the management key.
/// `admin_key` must be 24, 16 or 32 bytes (3-DES, AES-128, AES-256).
pub fn authenticate_admin(card: &Card, admin_key: &[u8]) -> Result<()> {
    let (algo_byte, key_len) = match admin_key.len() {
        24 => (0x03, 8),   // 3-DES (EDE3) -> 8-byte challenge
        16 => (0x08, 16),  // AES-128      -> 16-byte challenge
        32 => (0x0C, 16),  // AES-256      -> 16-byte challenge
        _  => bail!("Admin key must be 24, 16 or 32 bytes"),
    };

    // Request challenge from the card
    let inner = build_tlv(&[(0x80, &[])]);
    let challenge_body = build_tlv(&[(0x7C, &inner)]);
    let resp1 = transmit_apdu(
        card,
        &build_apdu(0x87, algo_byte, 0x9B, &challenge_body),
    )?;
    let tlvs1 = parse_tlv(&resp1);
    let container = find_tlv_tag(&tlvs1, 0x7C)
        .context("Card did not return 0x7C container")?;
    let tlv = parse_tlv(container);
    let challenge = find_tlv_tag(&tlv, 0x80)
        .context("Card did not return challenge (0x80)")?;

    if challenge.len() != key_len {
        bail!("Bad challenge length: got {}, expected {}", challenge.len(), key_len);
    }

    // Encrypt the challenge and build our own random challenge
    let our_challenge: Vec<u8> = (0..key_len).map(|_| rand::random()).collect();

    let encrypted_resp = encrypt_challenge(admin_key, challenge)?;
    let encrypted_ours = encrypt_challenge(admin_key, &our_challenge)?;

    let inner = build_tlv(&[
        (0x80, &encrypted_resp),
        (0x81, &encrypted_ours),
    ]);
    let response_body = build_tlv(&[(0x7C, &inner)]);

    // Send response and verify card echoed our challenge
    let resp2 = transmit_apdu(
        card,
        &build_apdu(0x87, algo_byte, 0x9B, &response_body),
    )?;
    let tlvs2 = parse_tlv(&resp2);
    let container2 = find_tlv_tag(&tlvs2, 0x7C)
        .context("Second 0x7C container missing")?;
    let tlv = parse_tlv(container2);
    let echoed = find_tlv_tag(&tlv, 0x82)
        .context("Card did not echo our challenge (0x82)")?;

    if echoed != our_challenge.as_slice() {
        bail!("Admin authentication failed – challenge echo mismatch");
    }

    Ok(())
}

/// Change the PIV management key (admin key).
/// `new_key` must be 24 (3-DES), 16 (AES-128) or 32 (AES-256) bytes.
pub fn set_admin_key(card: &Card, new_key: &[u8]) -> Result<()> {
    let (algo_byte, expected_len) = match new_key.len() {
        24 => (0x03, 24), // 3-DES
        16 => (0x08, 16), // AES-128
        32 => (0x0C, 32), // AES-256
        _ => bail!("Unsupported admin-key length: must be 16, 24 or 32 bytes"),
    };

    // Build payload: [algo, 0x9B, key_len, key...]
    let mut payload = Vec::with_capacity(3 + expected_len);
    payload.push(algo_byte);
    payload.push(0x9B); // slot 9B (management key)
    payload.push(expected_len as u8);
    payload.extend_from_slice(new_key);

    // INS = 0xFF, P1 = 0xFF, P2 = 0xFE  (vendor-specific for "set admin key")
    send_receive(card, 0xFF, 0xFF, 0xFE, &payload)?;

    Ok(())
}

/// Read public key from slot (from certificate in that slot)
pub fn read_public_key(card: &Card, slot: PivSlot) -> Result<Option<Vec<u8>>> {
    let cert = read_certificate_from_slot(card, slot)?;
    match cert {
        None => Ok(None),
        Some(cert) => {
            let pub_key = read_pubkey_from_certificate(&cert)?;
            Ok(Some(pub_key))
        }
    }
}

/// Generates a key in the given slot, builds **minimal** certificate,
/// signs it with the **fresh** key, and stores it in given PIV slot.
/// Returns public key from the fresh key-pair.
pub fn generate_key_and_cert(card: &Card, slot: PivSlot, subject: &CertificateSubject, curve: EccCurve, validity_days: u32) -> Result<PublicKey> {
    // Generate ECC key-pair on device
    let algo_id = match curve {
        EccCurve::P256 => utils::ALGO_NISTP256,
        EccCurve::P384 => utils::ALGO_NISTP384,
    };

    let gen_body = build_tlv(&[(0xAC, &build_tlv(&[(0x80, &[algo_id])]))]);
    let resp = send_receive(card, 0x47, 0x00, slot.as_u8(), &gen_body)?;

    let tlvs = parse_tlv(&resp);
    let key_wrapper = find_tlv_tag(&tlvs, 0x7F49).context("no 7F49")?;
    let tlv = parse_tlv(key_wrapper);
    let point = find_tlv_tag(&tlv, 0x86).context("no 0x86")?;

    if point.is_empty() || point[0] != 0x04 {
        bail!("Bad point format");
    }
    let coord_len = match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
    };
    let point_bytes = &point[1..]; // drop 0x04
    if point_bytes.len() != 2 * coord_len {
        bail!("Bad point length");
    }
    let public_key = PublicKey {
        curve,
        x: point_bytes[..coord_len].to_vec(),
        y: point_bytes[coord_len..].to_vec(),
    };

    // Build certificate
    let cert_der = build_self_signed_cert(&public_key, subject, validity_days, |tbs_der| {
        // sign on-device with the **fresh** key
        sign_data(card, slot, public_key.curve, tbs_der)
    })?;

    // Store certificate
    write_certificate(card, slot, &cert_der)?;
    Ok(public_key)
}

/// Signs `tbs_der` with the **device** (ECDSA-P256) and returns **complete** DER certificate.
fn build_self_signed_cert(public_key: &PublicKey, subject: &CertificateSubject, validity_days: u32, sign_call: impl FnOnce(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    use x509_cert::ext::Extension;
    use x509_cert::spki::AlgorithmIdentifier;

    // serial
    let serial = rand::random::<u64>();
    // validity
    let duration = std::time::Duration::from_secs(validity_days as u64 * 24 * 60 * 60);
    let validity = Validity::from_now(duration).context(format!("Failed to create validity for {:?}", duration))?;

    // issuer = subject  (self-signed)
    /*let issuer_rdn = vec![
        rel_distinguished_name(&utils::OID_AT_COMMON_NAME, &subject.common_name)?,
        rel_distinguished_name(&utils::OID_AT_ORGANIZATION_NAME, "Test Organization")?,
        rel_distinguished_name(&utils::OID_AT_COUNTRY_NAME, "US")?,
    ];*/

    let mut subject_rdn = vec![
        rel_distinguished_name(&utils::OID_AT_COMMON_NAME, &subject.common_name)?,
    ];
    if let Some(org) = &subject.organization {
        subject_rdn.push(rel_distinguished_name(&utils::OID_AT_ORGANIZATION_NAME, org)?);
    }
    if let Some(ou) = &subject.organizational_unit {
        subject_rdn.push(rel_distinguished_name(&utils::OID_AT_ORGANIZATIONAL_UNIT_NAME, ou)?);
    }
    if let Some(c) = &subject.country {
        subject_rdn.push(rel_distinguished_name(&utils::OID_AT_COUNTRY_NAME, c)?);
    }
    let issuer = Name::from(subject_rdn.clone());
    let subject_name = Name::from(subject_rdn);

    // SPKI
    let spki = build_spki(public_key)?;

    // Build TBS
    let mut tbs = TbsCertificate {
        version:          Version::V3,
        serial_number:    SerialNumber::from(serial),
        signature:        AlgorithmIdentifier {
            oid:  utils::OID_ECDSA_WITH_SHA256, // ecdsa-with-SHA256
            parameters: None,
        },
        issuer:           issuer.clone(),
        validity,
        subject:          subject_name.clone(),
        subject_public_key_info: spki,
        issuer_unique_id:  None,
        subject_unique_id: None,
        extensions:       None,
    };

    // Adding extensions
    let mut ext = Extensions::default();
    let constraints = BasicConstraints { ca: false, path_len_constraint: None }
        .to_extension(&subject_name, &ext)?;
    ext.push(constraints);
    let usages = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation);
    ext.push(usages.to_extension(&subject_name, &ext)?);
    ext.push(ExtendedKeyUsage(vec![
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"), // clientAuth
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.2"), // smartcard-logon
    ]).to_extension(&subject_name, &ext)?);
    // SMIMECapabilities blob (exact bytes from Python)
    let smime_blob = hex_literal::hex!("308183300B060960864801650304012A300B060960864801650304012D300B0609608648016503040116300B0609608648016503040119300B0609608648016503040102300B0609608648016503040105300A06082A864886F70D0307300706052B0E030207300E06082A864886F70D030202020080300E06082A864886F70D030402020200");
    ext.push(Extension{
        extn_id: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.15"),
        critical: false,
        extn_value: OctetString::new(smime_blob.to_vec())?,
    });
    tbs.extensions = Some(ext);

    // serialize TBS
    let tbs_der = tbs.to_der()?;

    // sign on-device
    let sig_der = sign_call(&tbs_der)?; // raw r||s
    let sig_bit = BitString::from_bytes(&sig_der)?;
    //println!("Public key: {}", to_hex(&public_key.to_uncompressed_point()[1..]));

    // assemble final certificate
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier{
            oid: utils::OID_ECDSA_WITH_SHA256,
            parameters: None,
        },
        signature: sig_bit,
    };
    Ok(cert.to_der()?)
}

/// helper: build a single RelativeDistinguishedName with one AVA
fn rel_distinguished_name(oid: &ObjectIdentifier, value: &str) -> Result<RelativeDistinguishedName> {
    Ok(RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue {
        oid: *oid,
        value: Any::from(Utf8StringRef::new(value)?),
    }])?)
}

/// Build SubjectPublicKeyInfo structure
fn build_spki(public_key: &PublicKey) -> Result<SubjectPublicKeyInfo<Any, BitString>, anyhow::Error> {
    let (curve_oid, key_der) = match public_key.curve {
        EccCurve::P256 => (
            ObjectIdentifier::from_bytes(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])?, // 1.2.840.10045.3.1.7
            public_key.to_uncompressed_point(),
        ),
        EccCurve::P384 => (
            ObjectIdentifier::from_bytes(&[0x2B, 0x81, 0x04, 0x00, 0x22])?, // 1.3.132.0.34
            public_key.to_uncompressed_point(),
        ),
    };

    let curve_params = Any::new(curve_oid.tag(), curve_oid.as_bytes())
        .context(format!("Failed to parse curve oid {:?}", &public_key))?;
    let alg_id = AlgorithmIdentifier {
        oid:  utils::OID_EC_PUBLIC_KEY,
        parameters: Some(curve_params),
    };

    let key_bits = BitString::from_bytes(&key_der)?;

    Ok(SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: key_bits,
    })
}