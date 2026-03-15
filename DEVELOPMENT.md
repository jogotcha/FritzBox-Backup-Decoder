# FritzBox-Backup-Decoder — Development Notes

A behind-the-scenes account of how this tool came to be: the research, the dead ends,
the community knowledge it builds on, and the technical decisions that shaped it.

---

## Origin

The project started with a single `.export` file from a FRITZ!Box 6591 Cable (Vodafone)
and a simple goal: extract the VoIP account credentials. What followed was a gradual reverse-engineering 
of an undocumented proprietary file format.

---

## The File Format

The `.export` file is a plain-text container with a small header block followed by named
sections, each opened by a `**** CFGFILE:` or `**** B64FILE:` marker and closed by
`**** END OF FILE ****`.

    **** FRITZ!Box 6591 Cable (Vodafone) CONFIGURATION EXPORT
    Password=$$$$6OOMGZQ...
    FirmwareVersion=161.08.03
    ...
    **** CFGFILE:voip.cfg
    voipcfg {
        ua1 {
            name = "02215699495";
            passwd = "$$$$HPMBHA2HX1FT...";
            ...
        }
    }
    **** END OF FILE ****
    **** B64FILE:phonebook
    PD94bWwKdmVyc2lvbj0i...
    **** END OF FILE ****

**CFG sections** are AVM's own config language — a loose C-struct notation with `key = value;`
pairs and nested `{ }` blocks. **B64FILE sections** are Base64-encoded binary blobs, mostly XML.

The format itself is not publicly documented by AVM. Everything here was derived from
reading the file directly and cross-referencing community research.

---

## The Encryption Problem

Every sensitive value in the file is replaced by a `$$$$`-prefixed ciphertext string, for example:

    passwd = "$$$$HPMBHA2HX1FTCZMEUZVZZIYZILOMMXGDUIPSZRHJT6NFYZ3EQL63Q11IGO1HRDWCT41XVA6OQU6VSA2P";

The first challenge was simply identifying what encoding was used. Standard Base32 (RFC 4648)
uses the alphabet `A–Z` + `2–7`. These strings failed to decode with any standard library call.

**The finding:** As far as community research indicates, AVM appears to use a custom Base32
alphabet — `A–Z` + `1–6` (shifting the digit range down by one). This is not publicly
documented by AVM. The alphabet was identified through trial and error, and the same
observation appears in Philip Huppert's
[`fritzbox-backup-password-decoder`](https://github.com/PhilippHuppert/fritzbox-backup-password-decoder)
among other community projects.

The decoder for this had to be written from scratch:

```python
AVM_B32_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

def avm_b32_decode(data: str) -> bytes:
    result = bytearray()
    buffer = 0
    bits = 0
    for char in data:
        idx = AVM_B32_CHARSET.find(char)
        if idx < 0:
            continue
        buffer = (buffer << 5) | idx
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((buffer >> bits) & 0xFF)
    return bytes(result)
```

---

## Key Derivation — The Two-Step Process

Once the Base32 encoding was solved, the next problem was the AES key. Several naive
approaches were tried first and failed:

- `MD5(password)` doubled to 32 bytes → wrong results
- `SHA-256(password)` → wrong results
- Zero IV with various key constructions → padding errors or garbage output

**The currently best-supported reconstruction**, corroborated by community threads on
[ip-phone-forum.de](https://www.ip-phone-forum.de) and related open-source decoder projects,
is a two-step derivation:

**Step 1 — Bootstrap key**

    bootstrap_key = MD5(export_password) + b'\x00' * 16   # 32 bytes

**Step 2 — Per-export key**

The `Password=` field in the file header is itself an encrypted value. Decrypting it
with the bootstrap key yields the actual key used for all other values in that export.
More precisely: the export password is used to unwrap a per-export key stored in the
`Password=` header field; that unwrapped key is then used for all remaining encrypted values.

    per_export_key = decrypt(Password= field, key=bootstrap_key)[:16] + b'\x00' * 16

The `Password=` field also functions as a password-check: if decryption produces a payload
with a matching MD5 prefix, the supplied password is correct.

**Decrypted payload format**

After AES-256-CBC decryption, every payload appears to follow this structure on the files tested:

    [ 4 bytes: MD5(remaining bytes)[:4] ]  ← integrity check
    [ 4 bytes: data length, big-endian  ]
    [ N bytes: actual plaintext data    ]

The MD5 prefix is used to verify correct decryption before trusting the result.

---

## The B64FILE Sections

The Base64-encoded sections decode to XML, but not well-formed XML. AVM's firmware
produces specific quirks that break standard parsers:

**Quirk 1 — Malformed XML declaration**

Standard XML:   `<?xml version="1.0" encoding="utf-8"?>`
AVM output:     `<?xml version="1.0" encoding="utf-8">`   ← missing `?` before `>`

The declaration must be stripped before parsing.

**Quirk 2 — Newlines inside opening tags**

```xml
<telephony
nid="1"><number type="home">...</number></telephony>
```

The newline inside the tag is technically invalid in strict parsers. All newlines must
be replaced with spaces before parsing.

**Quirk 3 — Multiple root elements**

The `phonebook` B64 section contains both a main `<phonebook>` element for external
contacts and a nested `<phonebook owner="255">` for internal extensions, followed by
additional loose elements — making it not a valid single-root XML document.
The fix is to wrap the entire decoded content in a synthetic `<root>` element.

---

## Character Encoding Issues

Not all B64FILE sections use the same encoding. On the files tested, some sections
(including phonebook and fonctrl) contained ISO-8859-1 encoded characters — German
umlauts among them — despite the XML declaration stating `encoding="utf-8"`. Decoding
as UTF-8 with `errors="replace"` silently produced replacement characters (`?`) instead
of the correct glyphs.

The fix is an encoding probe: try UTF-8 first, then ISO-8859-1, then CP1252, and
accept the first encoding that produces no replacement characters:

```python
for encoding in ("utf-8", "iso-8859-1", "cp1252"):
    try:
        candidate = raw.decode(encoding)
        if "\ufffd" not in candidate:
            decoded = candidate
            break
    except (UnicodeDecodeError, ValueError):
        continue
```

---

## Community Acknowledgements

This tool builds on prior work by others. The following contributions were particularly
relevant:

**Philip Huppert** — [`fritzbox-backup-password-decoder`](https://github.com/PhilippHuppert/fritzbox-backup-password-decoder)
documents the AVM custom Base32 alphabet and the two-step key derivation scheme, and was
among the most useful reference points during development.

**Tobias Quathamer** — provided documentation of the bootstrap key construction and the
MD5-prefix integrity check in the decrypted payload.

**ip-phone-forum.de community** — years of reverse-engineering threads that collectively
mapped out the `.export` file structure, the B64FILE encoding quirks, and the character
encoding inconsistencies. Much of this knowledge exists only in forum posts, not in any
formal documentation.

**AVM / FRITZ!Box open-source ecosystem** — projects like `fritzconnection` and
`fritzinflux` provided context for how the router exposes its data and helped validate
assumptions about the config file structure.

---

## What Was Not Solved

**SIP credential decryption on some firmware versions**

On one older firmware build tested, the key derivation produced a result that passed the
MD5 integrity check but yielded unexpected plaintext for SIP usernames. The root cause
remains unclear — one hypothesis is that certain builds mix device-specific values into
the key derivation, but this is not confirmed.

**DECT device pairing data**

The `dect_eeprom` B64FILE section contains binary EEPROM data in a proprietary format.
Its structure was not reverse-engineered and is not extracted by this tool.

---

## Technical Summary

| Aspect | Detail |
|---|---|
| Encryption | AES-256-CBC |
| Key size | 32 bytes (16-byte MD5 + 16 zero bytes) |
| IV | First 16 bytes of decoded ciphertext |
| Encoding | AVM custom Base32 (`A–Z` + `1–6`) |
| Integrity check | MD5[:4] of plaintext prepended to payload |
| Config format | AVM C-struct notation (`key = value;` / `{ }` blocks) |
| Binary sections | Base64 → XML (with encoding and parser quirks) |
| Character encoding | Mixed UTF-8 / ISO-8859-1 depending on section |

---

*Written with [Claude](https://claude.ai)*
