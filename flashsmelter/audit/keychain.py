"""核验签名密钥的保管与指纹。

信任边界：私钥只应存在于**线上导出主机**（建议放在受控目录、权限 600、能放进
HSM 更好）；车间离线机只需要 ``*.pub`` 公钥。公钥指纹（SHA-256 前 16 位）写进
每个核验包，事后可凭指纹指认「当时是哪把签的」。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ..errors import ConfigurationError, NotFoundError, ValidationError
from . import ed25519
from .chain import sha256_hex

SECRET_SUFFIX = ".secret"
PUBLIC_SUFFIX = ".pub"
KEY_ALGORITHM = "ed25519"
KEY_VERSION = 1


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    key_id: str
    secret_path: Path
    public_path: Path

    def secret(self) -> bytes:
        try:
            return bytes.fromhex(self.secret_path.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise ConfigurationError("私钥无法读取或不是十六进制", details={"path": str(self.secret_path)}) from exc

    def public(self) -> bytes:
        return load_public_key(self.public_path)


def fingerprint(public_key: bytes) -> str:
    return sha256_hex(public_key)[:16]


def init_keychain(keys_dir: Path | str, key_id: str = "line1") -> SigningIdentity:
    """在 ``keys_dir`` 下生成一对密钥；已存在则报错，绝不静默覆盖。"""

    directory = Path(keys_dir)
    secret_path = directory / (key_id + SECRET_SUFFIX)
    public_path = directory / (key_id + PUBLIC_SUFFIX)
    if secret_path.exists() or public_path.exists():
        raise ConfigurationError("密钥已存在，拒绝覆盖", details={"key_id": key_id, "dir": str(directory)})
    directory.mkdir(parents=True, exist_ok=True)
    seed, public = ed25519.generate_key()
    secret_path.write_text(seed.hex() + "\n", encoding="ascii")
    os.chmod(secret_path, 0o600)
    public_path.write_text(_public_file(public), encoding="ascii")
    os.chmod(public_path, 0o644)
    return SigningIdentity(key_id=key_id, secret_path=secret_path, public_path=public_path)


def load_identity(keys_dir: Path | str, key_id: str = "line1") -> SigningIdentity:
    directory = Path(keys_dir)
    secret_path = directory / (key_id + SECRET_SUFFIX)
    public_path = directory / (key_id + PUBLIC_SUFFIX)
    if not secret_path.exists() or not public_path.exists():
        raise NotFoundError("签名密钥不存在，请先 keychain-init", details={"key_id": key_id, "dir": str(directory)})
    return SigningIdentity(key_id=key_id, secret_path=secret_path, public_path=public_path)


def load_public_key(path: Path | str) -> bytes:
    """读取公钥文件（支持本工具 JSON 封装与裸 hex/base64 两种形态）。"""

    text = Path(path).read_text(encoding="ascii").strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _decode_key_material(text)
    if not isinstance(parsed, dict) or parsed.get("algorithm") != KEY_ALGORITHM:
        raise ValidationError("公钥文件算法标识不正确", details={"path": str(path)})
    return _decode_key_material(str(parsed.get("public_key", "")))


def public_key_text(public_key: bytes, *, key_id: str = "line1") -> str:
    return _public_file(public_key, key_id=key_id)


def _public_file(public_key: bytes, *, key_id: str = "line1") -> str:
    envelope = {
        "algorithm": KEY_ALGORITHM,
        "version": KEY_VERSION,
        "key_id": key_id,
        "fingerprint_sha256_16": fingerprint(public_key),
        "public_key": public_key.hex(),
    }
    return json.dumps(envelope, sort_keys=True, indent=2) + "\n"


def _decode_key_material(text: str) -> bytes:
    cleaned = "".join(text.split())
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        raise ValidationError("公钥必须是 32 字节的十六进制文本") from None
    if len(raw) != 32:
        raise ValidationError("Ed25519 公钥必须是 32 字节", details={"length": len(raw)})
    return raw


__all__ = ["SigningIdentity", "fingerprint", "init_keychain", "load_identity", "load_public_key", "public_key_text"]
