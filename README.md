# FritzBox-Backup-Decoder

A Python CLI tool to decode and decrypt AVM FRITZ!Box `.export` backup files.
Extracts VoIP/SIP credentials, WLAN passwords, phonebook contacts, user accounts,
internet connection settings, VPN configuration, and more — all in one command.

---

## Features

- 🔐 **Decrypts `$$$$`-encrypted values** using the export password (AES-256-CBC)
- 📞 **VoIP / SIP accounts** — phone numbers, SIP username, SIP password, registrar, provider
- 🌐 **Internet connection** — connection mode, PPPoE credentials, WAN interfaces
- 📶 **WLAN / WiFi** — SSIDs and passwords for 2.4 GHz, 5 GHz and guest networks
- 📖 **Phonebook** — external contacts and internal extensions
- 🖨️ **Fax settings** — MSN, sender name
- 👤 **User accounts** — FritzBox login users with rights and passwords
- 🔒 **VPN configuration** — WireGuard port, connections
- ⚙️ **TR-069 remote management** — ACS URL and credentials
- 📄 **Dual output** — human-readable `.txt` summary and machine-readable `.json`

---

## Requirements

- Python 3.7+
- [pycryptodome](https://pypi.org/project/pycryptodome/)

```bash
pip install pycryptodome
```

---

## Usage

```bash
python3 FritzBox-Backup-Decoder.py <backup.export> <password>
```

**With custom output directory:**

```bash
python3 FritzBox-Backup-Decoder.py backup.export mypassword -o /path/to/output
```

**Output files generated:**

| File | Description |
|------|-------------|
| `<name>_decoded.txt` | Human-readable summary (German labels) |
| `<name>_decoded.json` | Full structured data as JSON |

### Example

```bash
python3 FritzBox-Backup-Decoder.py FRITZ.Box_7590_backup.export "mySecretPassword"
```

```
FritzBox Backup Decoder
  Input:  FRITZ.Box_7590_backup.export
  Output: ./

Extracting data...
  JSON: FRITZ.Box_7590_backup_decoded.json
  TXT:  FRITZ.Box_7590_backup_decoded.txt

======================================================================
  FRITZBOX BACKUP - DECODED CONFIGURATION
======================================================================
  Modell:    FRITZ!Box 7590
  Firmware:  07.57
  LAN-IP:    192.168.178.1
...
```

---

## How It Works

AVM FRITZ!Box export files store sensitive values (passwords, SIP credentials, etc.)
encrypted with a two-step AES-256-CBC scheme:

1. **Bootstrap key**: `MD5(export_password) + 16 zero bytes`
2. **Decrypt the `Password=` header field** using the bootstrap key → yields the actual session key
3. **All `$$$$`-prefixed values** are decrypted using the session key

Encrypted values are encoded in AVM's custom Base32 alphabet
(`A–Z` + `1–6` instead of the standard RFC 4648 `A–Z` + `2–7`).

The decrypted payload format is:
```
[4 bytes: MD5 checksum] [4 bytes: data length (BE)] [data bytes]
```

---

## Tested Devices

| Model | Firmware |
|-------|----------|
| FRITZ!Box 6591 Cable (Vodafone) | 161.08.03 |
| FRITZ!Box 4050 | 287.08.02 |

Likely compatible with most FRITZ!Box models running firmware 6.x–8.x.

---

## Acknowledgements & Inspiration

This tool was developed with reference to prior community research on the FRITZ!Box
export encryption format. Special thanks to:

- **Tobias Quathamer** – early documentation of the AVM two-step key derivation algorithm
- **Philip Huppert** ([`fritzbox-password-decoder`](https://github.com/PhilippHuppert/fritzbox-backup-password-decoder)) – research into the `$$$$` encryption scheme and AVM's custom Base32 alphabet
- **AVM / FRITZ!Box community forums** ([ip-phone-forum.de](https://www.ip-phone-forum.de)) – long-running community threads reverse-engineering the export file format
- The broader open-source community maintaining tools like `fritzinflux`, `fritzconnection`, and similar FritzBox automation projects

---

## Web Version

A browser-based version of this tool is available at **[www.fb-decoder.com](https://www.fb-decoder.com)** —
no installation required, runs entirely in your browser.

---

## Disclaimer

> This tool is intended for legitimate use only — e.g. recovering your own credentials
> from your own backup files. Do not use it to access devices or data you do not own
> or have explicit permission to inspect.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Generated with [Claude](https://claude.ai)*
