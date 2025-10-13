use anyhow::{bail, Context};
use pcsc::{Card, MAX_BUFFER_SIZE};

/// Helper function to build TLV structure
pub(crate) fn build_tlv(tags: &[(u16, &[u8])]) -> Vec<u8> {
    let mut result = Vec::new();

    for (tag, value) in tags {
        // Tag
        if *tag <= 0xFF {
            result.push(*tag as u8);
        } else {
            result.push((*tag >> 8) as u8);
            result.push(*tag as u8);
        }

        // Length
        let len = value.len();
        if len < 0x80 {
            result.push(len as u8);
        } else if len < 0x100 {
            result.push(0x81);
            result.push(len as u8);
        } else if len < 0x10000 {
            result.push(0x82);
            result.push((len >> 8) as u8);
            result.push(len as u8);
        } else {
            panic!("TLV value too long");
        }

        // Value
        result.extend_from_slice(value);
    }

    result
}

/// Helper function to parse TLV structure
pub(crate) fn parse_tlv(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < data.len() {
        // Parse tag
        let tag = if data[i] & 0x1F == 0x1F {
            // Two-byte tag
            if i + 1 >= data.len() {
                break;
            }
            let t = ((data[i] as u16) << 8) | (data[i + 1] as u16);
            i += 2;
            t
        } else {
            let t = data[i] as u16;
            i += 1;
            t
        };

        if i >= data.len() {
            break;
        }

        // Parse length
        let len = if data[i] & 0x80 == 0 {
            let l = data[i] as usize;
            i += 1;
            l
        } else {
            let num_bytes = (data[i] & 0x7F) as usize;
            i += 1;

            if i + num_bytes > data.len() {
                break;
            }

            let mut l = 0usize;
            for _ in 0..num_bytes {
                l = (l << 8) | (data[i] as usize);
                i += 1;
            }
            l
        };

        if i + len > data.len() {
            break;
        }

        // Parse value
        let value = data[i..i + len].to_vec();
        i += len;

        result.push((tag, value));
    }

    result
}

/// Helper function to find TLV tag
pub(crate) fn find_tlv_tag(tlv_data: &[(u16, Vec<u8>)], tag: u16) -> Option<&[u8]> {
    tlv_data.iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, v)| v.as_slice())
}

/// Send APDU command with automatic response handling
pub(crate) fn send_receive(card: &Card, ins: u8, p1: u8, p2: u8, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let apdu = build_apdu(ins, p1, p2, data);
    transmit_apdu(&card, &apdu)
}

/// Build APDU command (ISO 7816-4 compliant)
pub(crate) fn build_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, ins, p1, p2];

    match data.len() {
        0 => {
            // Case 1: no data, no Le
            // -> caller decides whether to append Le separately if needed
        }
        1..=255 => {
            // Case 2: short APDU with data
            apdu.push(data.len() as u8); // Lc (1 byte)
            apdu.extend_from_slice(data);
            // No automatic Le (Python iso7816_compose does not force it)
        }
        256..=65535 => {
            // Case 3: extended APDU with data
            apdu.push(0x00); // Extended Lc marker
            apdu.push(((data.len() >> 8) & 0xFF) as u8);
            apdu.push((data.len() & 0xFF) as u8);
            apdu.extend_from_slice(data);
            // No automatic Le
        }
        _ => panic!("APDU data too long"),
    }

    apdu
}

/// Send APDU and handle multi-packet responses (0x61 status)
pub(crate) fn transmit_apdu(card: &Card, apdu: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut response_buf = [0; MAX_BUFFER_SIZE];
    let mut response = card.transmit(apdu, &mut response_buf)
        .context("Failed to transmit APDU")?;

    if response.len() < 2 {
        bail!("Response too short: {} bytes", response.len());
    }

    let mut data = response[..response.len() - 2].to_vec();
    let mut sw1 = response[response.len() - 2];
    let mut sw2 = response[response.len() - 1];

    const MORE_DATA_STATUS: u8 = 0x61;

    // Handle 0x61 XX - more data available
    while sw1 == MORE_DATA_STATUS {
        // ISO 7816-4: if SW2 == 0, request 0xFF (255) bytes
        let le = if sw2 != 0 { sw2 } else { 0xFF };

        let get_response = [0x00, 0xC0, 0x00, 0x00, le];

        response = card.transmit(&get_response, &mut response_buf)
            .context("Failed to get response")?;

        if response.len() < 2 {
            bail!("GET RESPONSE returned data too short");
        }

        let chunk = &response[..response.len() - 2];
        data.extend_from_slice(chunk);

        sw1 = response[response.len() - 2];
        sw2 = response[response.len() - 1];
    }

    // Accept final status = 0x9000
    if sw1 != 0x90 || sw2 != 0x00 {
        bail!("APDU failed with status: {:02X} {:02X}", sw1, sw2);
    }

    Ok(data)
}