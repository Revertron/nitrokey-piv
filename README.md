# nitrokey-piv

A Rust library for working with the **PIV (Personal Identity Verification) applet** on **Nitrokey 3** devices.  
This crate provides a clean and efficient interface to communicate with and manage PIV keys, certificates, and authentication operations over PC/SC.

---

## ✨ Features

- 🧩 **PIV Applet Support** — Interact with the PIV applet on Nitrokey 3.
- 🔐 **Key Management** — Generate keys & certificates in PIV slots.
- 🧾 **Certificate Handling** — Parse and create X.509 certificates.
- ⚙️ **Cryptographic Operations** — Perform signing, encryption, and key derivation using keys in PIV slots.
- 🖧 **PC/SC Backend** — Uses the [`pcsc`](https://crates.io/crates/pcsc) crate for direct communication with the Nitrokey device.

---

## 📦 Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
nitrokey-piv = "1.0.0"
```

Or install directly from the GitHub repository:

```bash
cargo add --git https://github.com/Revertron/nitrokey-piv
```

---

## 🔧 Requirements

* **Rust 1.74+**
* **Nitrokey 3** with PIV applet installed and enabled
* **PC/SC runtime**

    * Linux: `pcscd` and `libpcsclite`
    * macOS: built-in support
    * Windows: native Smart Card subsystem

---

## 🧠 Example

Below is a minimal example that connects to the first Nitrokey device with the PIV applet:

```rust
use nitrokey_piv::Nitrokey3PIV;
use anyhow::Result;

fn main() -> Result<()> {
    // Initialize the PIV context and connect to the Nitrokey reader
    let mut piv = Nitrokey3PIV::open(None)?;

    // Read the PIV applet version
    let name = piv.get_name();
    let serial = piv.get_version();
    println!("Connected to Nitrokey {} with serial {}", name, serial);

    Ok(())
}
```
---

## 🔐 Dependencies

This crate relies on well-tested cryptographic and certificate libraries:

| Crate                                                 | Purpose                                        |
| ----------------------------------------------------- | ---------------------------------------------- |
| [`pcsc`](https://crates.io/crates/pcsc)               | Smart card interface                           |
| [`der`](https://crates.io/crates/der)                 | DER and PEM encoding/decoding                  |
| [`spki`](https://crates.io/crates/spki)               | SubjectPublicKeyInfo parsing                   |
| [`sha2`](https://crates.io/crates/sha2)               | SHA-256 and SHA-512 hashing                    |
| [`x509-cert`](https://crates.io/crates/x509-cert)     | X.509 certificate creation                     |
| [`x509-parser`](https://crates.io/crates/x509-parser) | Certificate parsing                            |
| [`hkdf`](https://crates.io/crates/hkdf)               | Key derivation                                 |
| [`aes`, `des`, `cipher`]                              | Symmetric encryption and decryption primitives |

---

## 🧰 Development

### Build

```bash
cargo build
```

---

## ⚖️ License

This project is licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Revertron**
Rust and Android Developer
[https://github.com/Revertron](https://github.com/Revertron)

---

## 💬 Contributing

Contributions are welcome!
Please open an issue or pull request on GitHub if you have improvements, bug reports, or additional PIV functionality to propose.

---

## 🧾 Notes

* This crate is not affiliated with Nitrokey GmbH.
* Use at your own risk — always verify cryptographic operations before deploying in security-sensitive environments.

---

**Made with ❤️ in Rust**