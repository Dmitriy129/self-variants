"""Portable, strictly validated instance manifests.

Restore never invents credentials or changes URL paths. ``total_gb`` retains the
3x-ui API spelling but stores a traffic limit in bytes; zero means unlimited.
REALITY key generation and key-pair verification use the system OpenSSL binary.
"""

from __future__ import annotations

import base64
import copy
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Any
import uuid


SCHEMA_VERSION = 1
HTTPS_PORT = 8443
_MAX_INTEGER = 2**63 - 1
_MAX_MANIFEST_BYTES = 1024 * 1024
_PATH = re.compile(r"/(?:[A-Za-z0-9_-]+/)+\Z", re.ASCII)
_TOKEN = re.compile(r"[A-Za-z0-9_-]{8,128}\Z", re.ASCII)
_USERNAME = re.compile(r"[A-Za-z0-9_.@-]{1,64}\Z", re.ASCII)
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
_PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b656e032100")


class ConfigError(ValueError):
    """The manifest is unsafe, incomplete, or unsupported."""


def _fields(value: Any, required: set[str], field: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{field} must be an object")
    if set(value) != required:
        raise ConfigError(f"{field} has missing or unsupported fields")
    return value


def _text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ConfigError(f"{field} must be a nonempty string of at most {maximum} characters")
    return value


def _domain(value: Any, field: str) -> str:
    value = _text(value, field, 253)
    if value != value.lower():
        raise ConfigError(f"{field} must use lowercase DNS letters")
    labels = value.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise ConfigError(f"{field} must be an ASCII DNS domain without a port or trailing dot")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ConfigError(f"{field} must be a DNS domain, not an IP address")
    if not re.fullmatch(r"[a-z](?:[a-z0-9-]*[a-z0-9])?", labels[-1]):
        raise ConfigError(f"{field} must end in a DNS label starting with a letter")
    return value


def _email(value: Any, field: str) -> str:
    value = _text(value, field, 254)
    if value.count("@") != 1:
        raise ConfigError(f"{field} must be an email address")
    local, domain = value.split("@")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local, re.ASCII):
        raise ConfigError(f"{field} has an invalid email local part")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ConfigError(f"{field} has an invalid email local part")
    _domain(domain, field)
    return value


def _integer(value: Any, field: str, maximum: int = _MAX_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ConfigError(f"{field} must be an integer between 0 and {maximum}")
    return value


def _password(value: Any, field: str) -> str:
    value = _text(value, field)
    if len(value) < 12 or any(not 33 <= ord(char) <= 126 for char in value):
        raise ConfigError(f"{field} must contain 12 to 256 printable ASCII characters without spaces")
    return value


def _key(value: Any, field: str) -> bytes:
    value = _text(value, field, 43)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value, re.ASCII):
        raise ConfigError(f"{field} must be an unpadded URL-safe base64 X25519 key")
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError as error:
        raise ConfigError(f"{field} is not a valid X25519 key") from error
    if len(raw) != 32 or not any(raw) or _encode_key(raw) != value:
        raise ConfigError(f"{field} is not a canonical, nonzero 32-byte X25519 key")
    return raw


def _encode_key(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _openssl(*arguments: str, data: bytes | None = None) -> bytes:
    executable = shutil.which("openssl")
    if executable is None:
        raise ConfigError("OpenSSL with X25519 support is required for REALITY keys")
    try:
        result = subprocess.run(
            [executable, *arguments], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        # OpenSSL output and input can contain key material: never expose them.
        raise ConfigError("OpenSSL could not process the X25519 key") from None
    return result.stdout


def _raw_der(value: bytes, prefix: bytes) -> bytes:
    if not value.startswith(prefix) or len(value) != len(prefix) + 32:
        raise ConfigError("OpenSSL returned an unsupported X25519 DER encoding")
    return value[len(prefix):]


def _public_from_private(private: bytes) -> bytes:
    result = _openssl("pkey", "-inform", "DER", "-pubout", "-outform", "DER",
                      data=_PRIVATE_DER_PREFIX + private)
    return _raw_der(result, _PUBLIC_DER_PREFIX)


def _target(value: Any) -> tuple[str, int]:
    value = _text(value, "reality.target", 260)
    host, separator, port = value.rpartition(":")
    if not separator or not re.fullmatch(r"[1-9][0-9]{0,4}", port, re.ASCII):
        raise ConfigError("reality.target must be a DNS domain and port, for example www.example.com:443")
    _domain(host, "reality.target")
    if int(port) > 65535:
        raise ConfigError("reality.target port must be between 1 and 65535")
    return host, int(port)


def validate_instance(data: Any) -> dict:
    """Return a detached copy, rejecting rather than repairing any invalid data."""
    if not isinstance(data, dict):
        raise ConfigError("instance must be an object")
    if type(data.get("schema_version")) is not int or data["schema_version"] != SCHEMA_VERSION:
        raise ConfigError("schema_version must be the integer 1")
    profile = data.get("profile")
    if profile not in ("reality", "hysteria2"):
        raise ConfigError("profile must be reality or hysteria2")
    fields = {"schema_version", "profile", "domain", "email", "https_port", "panel", "subscription", "users"}
    if profile == "reality":
        fields.add("reality")
    _fields(data, fields, "instance")
    _domain(data["domain"], "domain")
    _email(data["email"], "email")
    if type(data["https_port"]) is not int or data["https_port"] != HTTPS_PORT:
        raise ConfigError("https_port must be the integer 8443")

    panel = _fields(data["panel"], {"path", "username", "password"}, "panel")
    subscription = _fields(data["subscription"], {"path"}, "subscription")
    for field, value in (("panel.path", panel["path"]), ("subscription.path", subscription["path"])):
        if not isinstance(value, str) or len(value) > 256 or not _PATH.fullmatch(value):
            raise ConfigError(f"{field} must begin and end with / and contain nonempty ASCII letters, digits, _ or - segments")
    if panel["path"].startswith(subscription["path"]) or subscription["path"].startswith(panel["path"]):
        raise ConfigError("panel.path and subscription.path must not overlap")
    if not isinstance(panel["username"], str) or not _USERNAME.fullmatch(panel["username"]):
        raise ConfigError("panel.username must contain 1 to 64 ASCII letters, digits, _, ., @ or -")
    _password(panel["password"], "panel.password")

    users = data["users"]
    if not isinstance(users, list) or len(users) > 10000:
        raise ConfigError("users must be an array with at most 10000 entries")
    emails: set[str] = set()
    sub_ids: set[str] = set()
    credentials: set[str] = set()
    credential = "uuid" if profile == "reality" else "password"
    for index, user in enumerate(users):
        field = f"users[{index}]"
        _fields(user, {"email", "sub_id", "enable", "expiry_time", "total_gb", "limit_ip", credential}, field)
        # 3x-ui calls this field email, but it is a user identifier and the
        # panel normally generates names without an @ or a mailbox domain.
        name = _text(user["email"], f"{field}.email", 254)
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in name):
            raise ConfigError(f"{field}.email must not contain whitespace or control characters")
        if not isinstance(user["sub_id"], str) or not _TOKEN.fullmatch(user["sub_id"]):
            raise ConfigError(f"{field}.sub_id must contain 8 to 128 ASCII letters, digits, _ or -")
        if type(user["enable"]) is not bool:
            raise ConfigError(f"{field}.enable must be a boolean")
        for name in ("expiry_time", "total_gb", "limit_ip"):
            _integer(user[name], f"{field}.{name}")
        if credential == "uuid":
            try:
                parsed = uuid.UUID(user["uuid"]) if isinstance(user["uuid"], str) else None
            except ValueError:
                parsed = None
            if parsed is None or parsed.int == 0 or str(parsed) != user["uuid"]:
                raise ConfigError(f"{field}.uuid must be a canonical nonzero lowercase UUID")
        else:
            _password(user["password"], f"{field}.password")
        if user["email"].casefold() in emails or user["sub_id"] in sub_ids or user[credential] in credentials:
            raise ConfigError("users must have unique emails, subscription IDs and credentials")
        emails.add(user["email"].casefold())
        sub_ids.add(user["sub_id"])
        credentials.add(user[credential])

    if profile == "reality":
        reality = _fields(data["reality"], {"target", "server_name", "private_key", "public_key", "short_id"}, "reality")
        _target(reality["target"])
        _domain(reality["server_name"], "reality.server_name")
        private = _key(reality["private_key"], "reality.private_key")
        public = _key(reality["public_key"], "reality.public_key")
        if not isinstance(reality["short_id"], str) or not re.fullmatch(r"(?:[0-9a-f]{2}){1,8}", reality["short_id"], re.ASCII):
            raise ConfigError("reality.short_id must contain 2 to 16 lowercase hexadecimal characters in byte pairs")
        if not hmac.compare_digest(_public_from_private(private), public):
            raise ConfigError("reality.public_key does not match reality.private_key")
    return copy.deepcopy(data)


def new_instance(profile: str, domain: str, email: str, reality_target: str | None = None,
                 admin_password: str | None = None) -> dict:
    """Create fresh credentials; this is the only manifest generation entry point."""
    if profile not in ("reality", "hysteria2"):
        raise ConfigError("profile must be reality or hysteria2")
    _domain(domain, "domain")
    _email(email, "email")
    if profile != "reality" and reality_target is not None:
        raise ConfigError("reality_target is only supported for the reality profile")
    if admin_password is not None:
        _password(admin_password, "panel.password")
    data = {
        "schema_version": SCHEMA_VERSION, "profile": profile, "domain": domain,
        "email": email, "https_port": HTTPS_PORT,
        "panel": {"path": f"/{secrets.token_urlsafe(18)}/", "username": "admin",
                  "password": admin_password if admin_password is not None else secrets.token_urlsafe(24)},
        "subscription": {"path": "/sub/"},
        "users": [{"email": f"personal@{domain}", "sub_id": secrets.token_urlsafe(18),
                   "enable": True, "expiry_time": 0, "total_gb": 0, "limit_ip": 0}],
    }
    if profile == "reality":
        target = reality_target if reality_target is not None else "www.microsoft.com:443"
        server_name, _ = _target(target)
        private_der = _openssl("genpkey", "-algorithm", "X25519", "-outform", "DER")
        private = _raw_der(private_der, _PRIVATE_DER_PREFIX)
        data["reality"] = {"target": target, "server_name": server_name,
                           "private_key": _encode_key(private),
                           "public_key": _encode_key(_public_from_private(private)),
                           "short_id": secrets.token_hex(8)}
        data["users"][0]["uuid"] = str(uuid.uuid4())
    else:
        data["users"][0]["password"] = secrets.token_urlsafe(24)
    return validate_instance(data)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("manifest contains duplicate JSON object keys")
        result[key] = value
    return result


def load_instance(path: str | os.PathLike[str]) -> dict:
    """Read and validate an existing manifest, without filling missing fields."""
    with open(path, "rb") as source:
        raw = source.read(_MAX_MANIFEST_BYTES + 1)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ConfigError("manifest exceeds the 1 MiB size limit")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ConfigError("manifest is not valid UTF-8 JSON") from None
    return validate_instance(data)


def save_instance(path: str | os.PathLike[str], data: Any) -> None:
    """Atomically replace a manifest with a validated, owner-only 0600 file."""
    instance = validate_instance(data)
    serialized = json.dumps(instance, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if len(serialized.encode("utf-8")) > _MAX_MANIFEST_BYTES:
        raise ConfigError("manifest exceeds the 1 MiB size limit")
    target = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = -1
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def subscription_urls(instance: Any) -> dict[str, str]:
    """Return each user's stable native subscription URL, including disabled users."""
    data = validate_instance(instance)
    base = f"https://{data['domain']}:{data['https_port']}{data['subscription']['path']}"
    return {user["email"]: base + user["sub_id"] for user in data["users"]}


def panel_url(instance: Any) -> str:
    data = validate_instance(instance)
    return f"https://{data['domain']}:{data['https_port']}{data['panel']['path']}"
