#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FritzBox Backup Decoder
=======================
Decodes and exports all configuration data from a FritzBox .export backup file,
including VoIP/SIP credentials, WLAN passwords, phonebook, user accounts, etc.

Requirements:
    - Python 3.7+
    - pycryptodome

Installation:
    Linux / macOS:
        pip3 install pycryptodome
        python3 fritzbox_decoder.py <backup.export> <password>

    Windows:
        pip install pycryptodome
        python fritzbox_decoder.py <backup.export> <password>

    Optional: virtual environment (recommended):
        python3 -m venv venv
        source venv/bin/activate        # Linux/macOS
        venv\\Scripts\\activate           # Windows
        pip install pycryptodome

Usage:
    python3 fritzbox_decoder.py <backup.export> <password> [-o OUTPUT_DIR]

    Output:
        <basename>_decoded.txt   - Human-readable summary
        <basename>_decoded.json  - Machine-readable JSON

Author: Generated with Claude
License: MIT
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome is required.")
    print("Install with: pip3 install pycryptodome")
    sys.exit(1)


# =============================================================================
# AVM Base32 Encoding (charset: A-Z, 1-6 instead of standard 2-7)
# =============================================================================

AVM_B32_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"


def avm_b32_decode(data: str) -> bytes:
    """Decode AVM's custom Base32 encoding."""
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


# =============================================================================
# FritzBox Decoder
# =============================================================================

class FritzBoxDecoder:
    """Decodes a FritzBox .export backup file."""

    def __init__(self, filepath: str, password: str):
        self.filepath = filepath
        self.password = password
        self.raw_lines = []
        self.header = {}
        self.cfg_sections = {}   # name -> raw text
        self.b64_sections = {}   # name -> raw bytes
        self.encryption_key = None

        self._read_file()
        self._derive_keys()

    # -------------------------------------------------------------------------
    # File parsing
    # -------------------------------------------------------------------------

    def _read_file(self):
        """Parse the export file into header, CFGFILE and B64FILE sections."""
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            self.raw_lines = f.readlines()

        current_section = None
        current_type = None
        section_lines = []

        for line in self.raw_lines:
            stripped = line.rstrip("\n")

            # Header lines (before first section)
            if current_section is None and not stripped.startswith("**** CFGFILE:") and not stripped.startswith("**** B64FILE:"):
                if "=" in stripped and not stripped.startswith("/*") and not stripped.startswith(" *"):
                    key, _, val = stripped.partition("=")
                    self.header[key.strip()] = val.strip()
                continue

            # Section start
            if stripped.startswith("**** CFGFILE:"):
                if current_section and section_lines:
                    self._store_section(current_type, current_section, section_lines)
                current_section = stripped.replace("**** CFGFILE:", "").strip()
                current_type = "cfg"
                section_lines = []
                continue

            if stripped.startswith("**** B64FILE:"):
                if current_section and section_lines:
                    self._store_section(current_type, current_section, section_lines)
                current_section = stripped.replace("**** B64FILE:", "").strip()
                current_type = "b64"
                section_lines = []
                continue

            if stripped.startswith("**** END OF FILE ****"):
                if current_section and section_lines:
                    self._store_section(current_type, current_section, section_lines)
                current_section = None
                current_type = None
                section_lines = []
                continue

            if stripped.startswith("**** END OF EXPORT"):
                break

            section_lines.append(stripped)

    def _store_section(self, stype, name, lines):
        if stype == "cfg":
            self.cfg_sections[name] = "\n".join(lines)
        elif stype == "b64":
            try:
                raw = base64.b64decode("".join(lines))
                self.b64_sections[name] = raw
            except Exception:
                self.b64_sections[name] = b""

    # -------------------------------------------------------------------------
    # Key derivation & decryption
    # -------------------------------------------------------------------------

    def _derive_keys(self):
        """Derive encryption key from export password.

        Algorithm:
        1. bootstrap_key = MD5(password) + 16 zero bytes (32 bytes)
        2. Decrypt Password= header field with bootstrap_key
        3. encryption_key = first 16 bytes of result + 16 zero bytes
        """
        md5 = hashlib.md5(self.password.encode("utf-8")).digest()
        bootstrap_key = md5 + b"\x00" * 16

        password_field = self.header.get("Password", "")
        if password_field.startswith("$$$$"):
            password_field = password_field[4:]

        try:
            key_data = self._decrypt_raw(password_field, bootstrap_key, is_string=False)
            if isinstance(key_data, bytes) and len(key_data) >= 16:
                self.encryption_key = key_data[:16] + b"\x00" * 16
            else:
                print(f"WARNING: Could not derive encryption key. Decryption will fail.")
                self.encryption_key = bootstrap_key
        except Exception as e:
            print(f"WARNING: Key derivation failed: {e}")
            print("         Encrypted values cannot be decrypted. Check your password.")
            self.encryption_key = bootstrap_key

    def _decrypt_raw(self, b32_data: str, key: bytes, is_string: bool = True):
        """Decrypt a base32-encoded encrypted value.

        Format: IV (16 bytes) + ciphertext
        Decrypted: MD5-check (4 bytes) + length (4 bytes BE) + data
        """
        raw = avm_b32_decode(b32_data)
        if len(raw) < 16:
            return None

        iv = raw[:16]
        ct = raw[16:]
        if len(ct) == 0:
            return None
        # Truncate to 16-byte boundary (AES block size); excess bytes are base32 artifacts
        if len(ct) % 16 != 0:
            ct = ct[:len(ct) - (len(ct) % 16)]
        if len(ct) == 0:
            return None

        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(ct)

        if len(dec) < 8:
            return None

        # Verify MD5 hash
        stored_hash = dec[:4]
        calc_hash = hashlib.md5(dec[4:]).digest()[:4]
        if stored_hash != calc_hash:
            return f"[HASH_MISMATCH]"

        data_length = struct.unpack(">I", dec[4:8])[0]
        data = dec[8:]

        if data_length > len(data):
            return f"[LENGTH_ERROR: {data_length} > {len(data)}]"

        result = data[:data_length]
        if is_string:
            return result.rstrip(b"\x00").decode("utf-8", errors="replace")
        return result

    def decrypt_value(self, encrypted: str) -> str:
        """Decrypt a $$$$-prefixed encrypted value from the config."""
        if not encrypted or not encrypted.startswith("$$$$"):
            return encrypted
        b32_data = encrypted[4:]
        try:
            result = self._decrypt_raw(b32_data, self.encryption_key)
            return result if result else encrypted
        except Exception:
            return encrypted

    # -------------------------------------------------------------------------
    # CFG parsing helpers
    # -------------------------------------------------------------------------

    def _get_cfg_value(self, text: str, key: str) -> str:
        """Extract a simple key = value; from cfg text."""
        pattern = rf'^\s*{re.escape(key)}\s*=\s*"?([^";]*)"?\s*;?\s*$'
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            val = match.group(1).strip().strip('"')
            if val.startswith("$$$$"):
                return self.decrypt_value(val)
            return val
        return ""

    def _get_cfg_encrypted(self, text: str, key: str) -> str:
        """Extract and decrypt a $$$$-prefixed value."""
        pattern = rf'^\s*{re.escape(key)}\s*=\s*"?(\$\$\$\$[^";]*)"?\s*;?\s*$'
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            return self.decrypt_value(match.group(1))
        return ""

    def _extract_blocks(self, text: str, block_name: str) -> list:
        """Extract repeated { } blocks for a given name, e.g. 'ua1', 'ua2', etc."""
        results = []
        # Pattern: block_name { ... }
        pattern = rf'{re.escape(block_name)}\s*\{{([^{{}}]*(?:\{{[^{{}}]*\}}[^{{}}]*)*)\}}'
        for match in re.finditer(pattern, text, re.DOTALL):
            results.append(match.group(1))
        return results

    def _decode_b64_xml(self, section_name: str) -> ET.Element:
        """Decode a B64FILE section as XML, handling FritzBox quirks."""
        raw = self.b64_sections.get(section_name, b"")
        if not raw:
            return None

        # Detect encoding from XML declaration or try UTF-8 first, then Latin-1
        decoded = None
        for encoding in ("utf-8", "iso-8859-1", "cp1252"):
            try:
                candidate = raw.decode(encoding)
                # Verify no replacement characters were needed
                if "\ufffd" not in candidate:
                    decoded = candidate
                    break
            except (UnicodeDecodeError, ValueError):
                continue
        if decoded is None:
            decoded = raw.decode("utf-8", errors="replace")

        # Fix: FritzBox uses newlines inside XML tags; also fix malformed <?xml> declaration
        fixed = decoded.replace("\n", " ")
        fixed = re.sub(r"<\?xml[^>]*>", "", fixed)
        try:
            return ET.fromstring("<root>" + fixed + "</root>")
        except ET.ParseError:
            try:
                return ET.fromstring(fixed)
            except ET.ParseError:
                return None

    # -------------------------------------------------------------------------
    # Data extraction methods
    # -------------------------------------------------------------------------

    def get_general_info(self) -> dict:
        """Extract general box information from header."""
        info = {
            "model": self.header.get("**** FRITZ!Box", "").split("CONFIGURATION")[0].strip(),
            "firmware": self.header.get("FirmwareVersion", ""),
            "oem": self.header.get("OEM", ""),
            "country": self.header.get("Country", ""),
            "language": self.header.get("Language", ""),
        }
        # Get model from first line
        if self.raw_lines:
            first = self.raw_lines[0].strip()
            if "FRITZ!Box" in first:
                info["model"] = first.replace("****", "").replace("CONFIGURATION EXPORT", "").strip()

        # LAN IP from ar7.cfg
        ar7 = self.cfg_sections.get("ar7.cfg", "")
        info["lan_ip"] = self._get_cfg_value(ar7, "ipaddr") or "192.168.178.1"
        info["lan_netmask"] = self._get_cfg_value(ar7, "netmask") or "255.255.255.0"

        return info

    def get_voip_accounts(self) -> list:
        """Extract VoIP/SIP account data."""
        voip_cfg = self.cfg_sections.get("voip.cfg", "")
        if not voip_cfg:
            return []

        accounts = []
        # Find ua1 through ua10
        for i in range(1, 11):
            pattern = rf'ua{i}\s*\{{(.*?)\n\s*\}}'
            match = re.search(pattern, voip_cfg, re.DOTALL)
            if not match:
                continue

            block = match.group(1)
            enabled = self._get_cfg_value(block, "enabled")
            if enabled != "yes":
                continue

            account = {
                "account": f"ua{i}",
                "enabled": True,
                "phone_number": self._get_cfg_value(block, "name"),
                "sip_username": self._get_cfg_encrypted(block, "username") or self._get_cfg_value(block, "username"),
                "sip_password": self._get_cfg_encrypted(block, "passwd") or self._get_cfg_value(block, "passwd"),
                "registrar": self._get_cfg_value(block, "registrar"),
                "provider": self._get_cfg_value(block, "voip_providerlist_id"),
                "protocol_preference": self._get_cfg_value(block, "protocolprefer"),
            }
            # Only include if has meaningful data
            if account["phone_number"] or account["registrar"]:
                accounts.append(account)

        # Also extract global SIP settings
        sip_port = self._get_cfg_value(voip_cfg, "sip_srcport")
        rtp_start = self._get_cfg_value(voip_cfg, "rtpport_start")

        return accounts

    def get_voip_settings(self) -> dict:
        """Extract global VoIP settings."""
        voip_cfg = self.cfg_sections.get("voip.cfg", "")
        return {
            "sip_port": self._get_cfg_value(voip_cfg, "sip_srcport") or "5060",
            "rtp_port_start": self._get_cfg_value(voip_cfg, "rtpport_start"),
            "dns_port": self._get_cfg_value(voip_cfg, "dnsport"),
        }

    def get_internet_config(self) -> dict:
        """Extract internet connection configuration."""
        ar7 = self.cfg_sections.get("ar7.cfg", "")
        if not ar7:
            return {}

        config = {
            "mode": self._get_cfg_value(ar7, "mode"),
            "ipv4_mode": self._get_cfg_value(ar7, "ipv4mode"),
            "ipv6_mode": self._get_cfg_value(ar7, "ipv6mode"),
            "mtu": self._get_cfg_value(ar7, "mtu_cutback"),
        }

        # PPPoE credentials (if present)
        pppoe_user = self._get_cfg_encrypted(ar7, "pppoeuser") or self._get_cfg_value(ar7, "pppoeuser")
        pppoe_pass = self._get_cfg_encrypted(ar7, "pppoepwd") or self._get_cfg_encrypted(ar7, "ppppasswd")
        if pppoe_user:
            config["pppoe_username"] = pppoe_user
        if pppoe_pass:
            config["pppoe_password"] = pppoe_pass

        # Serial/mobile config
        serial_user = self._get_cfg_encrypted(ar7, "username") or self._get_cfg_value(ar7, "username")
        serial_pass = self._get_cfg_encrypted(ar7, "passwd")
        if serial_user and serial_user != "[HASH_MISMATCH]":
            config["serial_username"] = serial_user
        if serial_pass and serial_pass != "[HASH_MISMATCH]":
            config["serial_password"] = serial_pass

        # WAN interfaces
        interfaces = []
        for match in re.finditer(r'interfaces\s*\{(.*?)\}', ar7, re.DOTALL):
            block = match.group(1)
            name = self._get_cfg_value(block, "name")
            if name:
                iface = {"name": name}
                ppptarget = self._get_cfg_value(block, "ppptarget")
                if ppptarget:
                    iface["ppptarget"] = ppptarget
                interfaces.append(iface)
        if interfaces:
            config["wan_interfaces"] = interfaces

        return config

    def get_wlan_config(self) -> list:
        """Extract WLAN/WiFi configuration."""
        wlan_cfg = self.cfg_sections.get("wlan.cfg", "")
        if not wlan_cfg:
            return []

        networks = []

        # Main WLAN
        ssid = self._get_cfg_value(wlan_cfg, "ssid")
        psk = self._get_cfg_encrypted(wlan_cfg, "pskvalue") or self._get_cfg_value(wlan_cfg, "pskvalue")
        enabled = self._get_cfg_value(wlan_cfg, "ap_enabled")
        if ssid:
            networks.append({
                "name": "Main WiFi (2.4 GHz)",
                "ssid": ssid,
                "password": psk,
                "enabled": enabled == "1",
                "hidden": self._get_cfg_value(wlan_cfg, "hidden_ssid") == "1",
                "channel": self._get_cfg_value(wlan_cfg, "channel") or "auto",
            })

        # 5 GHz
        ssid_scnd = self._get_cfg_value(wlan_cfg, "ssid_scnd")
        enabled_scnd = self._get_cfg_value(wlan_cfg, "ap_enabled_scnd")
        if ssid_scnd:
            networks.append({
                "name": "WiFi (5 GHz)",
                "ssid": ssid_scnd,
                "password": psk,  # Same PSK typically
                "enabled": enabled_scnd == "1",
                "channel": self._get_cfg_value(wlan_cfg, "channel_scnd") or "auto",
            })

        # Guest WLAN
        guest_enabled = self._get_cfg_value(wlan_cfg, "guest_ap_enabled")
        guest_ssid = self._get_cfg_value(wlan_cfg, "guest_ssid")
        guest_psk = self._get_cfg_encrypted(wlan_cfg, "guest_pskvalue") or self._get_cfg_value(wlan_cfg, "guest_pskvalue")
        if guest_ssid or guest_enabled == "yes":
            networks.append({
                "name": "Guest WiFi",
                "ssid": guest_ssid or "(not set)",
                "password": guest_psk or "",
                "enabled": guest_enabled in ("1", "yes"),
            })

        return networks

    def get_phonebook(self) -> list:
        """Extract phonebook contacts."""
        root = self._decode_b64_xml("phonebook")
        if root is None:
            return []

        contacts = []
        for phonebook in list(root.iter("phonebook")) + ([root] if root.tag == "phonebook" else []):
            owner = phonebook.get("owner", "")
            category = "Internal" if owner else "External"

            for contact in phonebook.findall("contact"):
                person = contact.find("person")
                name = ""
                if person is not None:
                    rn = person.find("realName")
                    if rn is not None and rn.text:
                        name = rn.text.strip()

                telephony = contact.find("telephony")
                numbers = []
                if telephony is not None:
                    for num_elem in telephony.findall("number"):
                        num_type = num_elem.get("type", "")
                        num_val = num_elem.text or ""
                        quickdial = num_elem.get("quickdial", "")
                        entry = {"number": num_val, "type": num_type}
                        if quickdial:
                            entry["quickdial"] = quickdial
                        numbers.append(entry)

                if name or numbers:
                    contacts.append({
                        "name": name,
                        "category": category,
                        "numbers": numbers,
                    })

        return contacts

    def get_devices(self) -> list:
        """Extract internal phone/DECT devices from fonctrl."""
        root = self._decode_b64_xml("fonctrl")
        if root is None:
            return []

        devices = []
        for person in root.iter("person"):
            dev_id = ""
            name = ""
            intern = ""
            dev_type = ""

            id_el = person.find("id")
            fname_el = person.find("fname")
            intern_el = person.find("intern")
            dtype_el = person.find("devicetype")

            if id_el is not None and id_el.text:
                dev_id = id_el.text
            if fname_el is not None and fname_el.text:
                name = fname_el.text.strip()
            if intern_el is not None and intern_el.text:
                intern = intern_el.text
            if dtype_el is not None and dtype_el.text:
                dev_type = dtype_el.text

            if name:
                devices.append({
                    "id": dev_id,
                    "name": name,
                    "intern_number": intern,
                    "device_type": dev_type,
                })

        return devices

    def get_fax_settings(self) -> dict:
        """Extract fax configuration."""
        root = self._decode_b64_xml("telefon_misc")
        if root is None:
            return {}

        fax_settings = {}
        fax = root.find(".//fax")
        if fax is not None:
            fid = fax.find("id")
            ss = fax.find("sender_short")
            sl = fax.find("sender_long")
            if fid is not None and fid.text:
                fax_settings["msn"] = fid.text
            if ss is not None and ss.text:
                fax_settings["sender_short"] = ss.text
            if sl is not None and sl.text:
                fax_settings["sender_long"] = sl.text

        return fax_settings

    def get_users(self) -> list:
        """Extract FritzBox user accounts."""
        ar7 = self.cfg_sections.get("ar7.cfg", "")
        if not ar7:
            return []

        users = []
        # Find boxusers section
        boxusers_match = re.search(r'boxusers\s*\{(.*?)^\}', ar7, re.DOTALL | re.MULTILINE)
        if not boxusers_match:
            return []

        boxusers_text = boxusers_match.group(1)

        # Find each users { } block
        # The format uses repeated { } blocks after "users"
        user_blocks = re.findall(
            r'(?:users\s*)?\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            boxusers_text,
            re.DOTALL
        )

        for block in user_blocks:
            if "enabled" not in block:
                continue

            user = {}
            enabled = self._get_cfg_value(block, "enabled")
            user["enabled"] = enabled == "yes"

            uid = self._get_cfg_value(block, "id")
            if uid:
                user["id"] = uid

            name = self._get_cfg_encrypted(block, "name") or self._get_cfg_value(block, "name")
            if name:
                user["name"] = name

            email = self._get_cfg_encrypted(block, "email") or self._get_cfg_value(block, "email")
            if email:
                user["email"] = email

            password = self._get_cfg_encrypted(block, "password") or self._get_cfg_value(block, "password")
            if password:
                user["password"] = password

            vpn = self._get_cfg_value(block, "vpn_access")
            if vpn:
                user["vpn_access"] = vpn == "yes"

            admin = self._get_cfg_value(block, "box_admin_rights")
            if admin:
                user["admin_rights"] = admin

            nas = self._get_cfg_value(block, "nas_rights")
            if nas:
                user["nas_rights"] = nas

            if user.get("name") or user.get("id"):
                users.append(user)

        return users

    def get_vpn_config(self) -> dict:
        """Extract VPN configuration."""
        vpn_cfg = self.cfg_sections.get("vpn.cfg", "")
        if not vpn_cfg:
            return {}

        config = {
            "version": self._get_cfg_value(vpn_cfg, "vpncfg_version"),
            "wireguard_port": self._get_cfg_value(vpn_cfg, "wg_listen_port"),
        }

        # Check for actual VPN connections
        connections = []
        for match in re.finditer(r'connection\s*\{(.*?)\}', vpn_cfg, re.DOTALL):
            block = match.group(1)
            conn = {
                "name": self._get_cfg_value(block, "name"),
                "enabled": self._get_cfg_value(block, "enabled") == "yes",
            }
            # Decrypt any keys
            key = self._get_cfg_encrypted(block, "key") or self._get_cfg_value(block, "key")
            if key:
                conn["key"] = key
            connections.append(conn)

        if connections:
            config["connections"] = connections

        return config

    def get_tr069_config(self) -> dict:
        """Extract TR-069 remote management config."""
        tr069 = self.cfg_sections.get("tr069.cfg", "")
        if not tr069:
            return {}

        config = {}

        def _get_any(*keys):
            for key in keys:
                val = self._get_cfg_encrypted(tr069, key) or self._get_cfg_value(tr069, key)
                if val:
                    return val
            return ""

        # Support both legacy keys (acs_*) and newer managementserver keys.
        url = _get_any("acs_url", "url")
        if url:
            config["acs_url"] = url
        user = _get_any("acs_user", "username")
        if user:
            config["acs_username"] = user
        pwd = _get_any("acs_passwd", "password")
        if pwd:
            config["acs_password"] = pwd

        cr_user = _get_any("ConnectionRequestUsername")
        if cr_user:
            config["connection_request_username"] = cr_user

        cr_pwd = _get_any("ConnectionRequestPassword")
        if cr_pwd:
            config["connection_request_password"] = cr_pwd

        return config

    # -------------------------------------------------------------------------
    # Export
    # -------------------------------------------------------------------------

    def export_all(self) -> dict:
        """Export all decoded data as a dictionary."""
        return {
            "general": self.get_general_info(),
            "voip_accounts": self.get_voip_accounts(),
            "voip_settings": self.get_voip_settings(),
            "internet": self.get_internet_config(),
            "wlan": self.get_wlan_config(),
            "phonebook": self.get_phonebook(),
            "devices": self.get_devices(),
            "fax": self.get_fax_settings(),
            "users": self.get_users(),
            "vpn": self.get_vpn_config(),
            "tr069": self.get_tr069_config(),
            "available_sections": {
                "cfg_files": list(self.cfg_sections.keys()),
                "b64_files": list(self.b64_sections.keys()),
            },
        }


# =============================================================================
# Text Formatter
# =============================================================================

def format_txt(data: dict) -> str:
    """Format decoded data as human-readable text."""
    lines = []
    sep = "=" * 70

    def add_section(title):
        lines.append("")
        lines.append(sep)
        lines.append(f"  {title}")
        lines.append(sep)

    # General
    gen = data.get("general", {})
    lines.append(sep)
    lines.append("  FritzBox Backup - Decoded Configuration")
    lines.append(sep)
    lines.append(f"  Model:     {gen.get('model', 'N/A')}")
    lines.append(f"  Firmware:  {gen.get('firmware', 'N/A')}")
    lines.append(f"  Country:   {gen.get('country', 'N/A')}")
    lines.append(f"  Language:  {gen.get('language', 'N/A')}")
    lines.append(f"  LAN IP:    {gen.get('lan_ip', 'N/A')}")
    lines.append(f"  Decoded:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # VoIP Accounts
    voip = data.get("voip_accounts", [])
    if voip:
        add_section("VoIP / SIP Accounts")
        voip_settings = data.get("voip_settings", {})
        lines.append(f"  SIP Port: {voip_settings.get('sip_port', 'N/A')}  |  "
                     f"RTP Start: {voip_settings.get('rtp_port_start', 'N/A')}")
        lines.append("")
        for acc in voip:
            lines.append(f"  [{acc['account']}]")
            lines.append(f"    Phone Number:    {acc.get('phone_number', '')}")
            lines.append(f"    SIP Username:    {acc.get('sip_username', '')}")
            lines.append(f"    SIP Password:    {acc.get('sip_password', '')}")
            lines.append(f"    Registrar:       {acc.get('registrar', '')}")
            lines.append(f"    Provider:        {acc.get('provider', '')}")
            lines.append("")

    # Internet
    inet = data.get("internet", {})
    if inet:
        add_section("Internet Connection")
        for key, val in inet.items():
            if key == "wan_interfaces":
                lines.append(f"  WAN Interfaces:")
                for iface in val:
                    lines.append(f"    - {iface}")
            else:
                label = key.replace("_", " ").title()
                lines.append(f"  {label:20s} {val}")

    # WLAN
    wlan = data.get("wlan", [])
    if wlan:
        add_section("WiFi")
        for net in wlan:
            status = "ON" if net.get("enabled") else "OFF"
            lines.append(f"  [{net.get('name', '')}] ({status})")
            lines.append(f"    SSID:     {net.get('ssid', '')}")
            lines.append(f"    Password: {net.get('password', '')}")
            if net.get("channel"):
                lines.append(f"    Channel:  {net.get('channel', '')}")
            lines.append("")

    # Phonebook
    pb = data.get("phonebook", [])
    if pb:
        add_section("Phonebook")
        extern = [c for c in pb if c.get("category") == "External"]
        intern = [c for c in pb if c.get("category") == "Internal"]

        if extern:
            lines.append("  --- External Contacts ---")
            for contact in extern:
                nums = ", ".join(
                    f"{n['number']} ({n['type']})" for n in contact.get("numbers", [])
                )
                lines.append(f"  {contact.get('name', 'N/A'):30s} {nums}")
            lines.append("")

        if intern:
            lines.append("  --- Internal Extensions ---")
            for contact in intern:
                nums = ", ".join(
                    f"{n['number']} ({n['type']})" for n in contact.get("numbers", [])
                )
                lines.append(f"  {contact.get('name', 'N/A'):30s} {nums}")
            lines.append("")

    # Devices
    devs = data.get("devices", [])
    if devs:
        add_section("Phones / DECT Devices")
        for dev in devs:
            lines.append(f"  {dev.get('name', 'N/A'):20s} Extension: {dev.get('intern_number', 'N/A')}")

    # Fax
    fax = data.get("fax", {})
    if fax:
        add_section("Fax Settings")
        for key, val in fax.items():
            label = key.replace("_", " ").title()
            lines.append(f"  {label:20s} {val}")

    # Users
    users = data.get("users", [])
    if users:
        add_section("User Accounts")
        for user in users:
            lines.append(f"  [{user.get('name', 'N/A')}] (ID: {user.get('id', '?')})")
            if user.get("email"):
                lines.append(f"    Email:         {user['email']}")
            if user.get("password"):
                lines.append(f"    Password:      {user['password']}")
            lines.append(f"    Active:        {'Yes' if user.get('enabled') else 'No'}")
            if user.get("admin_rights"):
                lines.append(f"    Admin Rights:  {user['admin_rights']}")
            if user.get("nas_rights"):
                lines.append(f"    NAS Rights:    {user['nas_rights']}")
            lines.append("")

    # VPN
    vpn = data.get("vpn", {})
    if vpn and (vpn.get("connections") or vpn.get("wireguard_port", "0") != "0"):
        add_section("VPN Configuration")
        lines.append(f"  Version:         {vpn.get('version', '')}")
        lines.append(f"  WireGuard Port:  {vpn.get('wireguard_port', '')}")
        for conn in vpn.get("connections", []):
            lines.append(f"  Connection: {conn.get('name', '')} "
                         f"({'active' if conn.get('enabled') else 'inactive'})")

    # TR-069
    tr069 = data.get("tr069", {})
    if tr069:
        add_section("TR-069 Remote Management")
        for key, val in tr069.items():
            label = key.replace("_", " ").title()
            lines.append(f"  {label:20s} {val}")

    # Available sections
    sections = data.get("available_sections", {})
    add_section("Available Sections in Backup")
    lines.append(f"  CFG Files: {', '.join(sections.get('cfg_files', []))}")
    lines.append(f"  B64 Files: {', '.join(sections.get('b64_files', []))}")

    lines.append("")
    lines.append(sep)
    lines.append("  End of Export")
    lines.append(sep)
    lines.append("")

    return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="FritzBox Backup Decoder - Extracts and decrypts configuration data from .export files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fritzbox_decoder.py backup.export mypassword
  python3 fritzbox_decoder.py backup.export mypassword -o /tmp/output
        """,
    )
    parser.add_argument("backup", help="Path to the FritzBox .export backup file")
    parser.add_argument("password", help="Export password used when creating the backup")
    parser.add_argument("-o", "--output", help="Output directory (default: same as input file)", default=None)

    args = parser.parse_args()

    if not os.path.isfile(args.backup):
        print(f"ERROR: File not found: {args.backup}")
        sys.exit(1)

    # Determine output paths
    basename = os.path.splitext(os.path.basename(args.backup))[0]
    output_dir = args.output or os.path.dirname(os.path.abspath(args.backup))
    os.makedirs(output_dir, exist_ok=True)

    txt_path = os.path.join(output_dir, f"{basename}_decoded.txt")
    json_path = os.path.join(output_dir, f"{basename}_decoded.json")

    print(f"FritzBox Backup Decoder")
    print(f"  Input:  {args.backup}")
    print(f"  Output: {output_dir}")
    print()

    # Decode
    try:
        decoder = FritzBoxDecoder(args.backup, args.password)
    except Exception as e:
        print(f"ERROR: Failed to decode backup: {e}")
        sys.exit(1)

    print("Extracting data...")
    data = decoder.export_all()

    # Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  JSON: {json_path}")

    # Write TXT
    txt = format_txt(data)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"  TXT:  {txt_path}")

    # Also print summary to console
    print()
    print(txt)


if __name__ == "__main__":
    main()
