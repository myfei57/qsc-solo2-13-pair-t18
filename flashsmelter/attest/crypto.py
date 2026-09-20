"""离线核验包的信任根：Ed25519 签名。

设计原则是「私钥永不进车间」：生成密钥对之后，私钥锁在线上服务器（或 HSM 里），
核验包只携带公钥与签名。车间机器上即使把整个包拆开改，也没有私钥重新签名，
验包一定失败。

平台依赖为零（``requires-python`` 环境里没有第三方密码学库），因此这里通过
``openssl pkeyutl`` 调用系统 OpenSSL 3 完成 Ed25519 运算；OpenSSL 不可用时
只有签名/验签两个入口会报错，哈希链等其余功能照常可用。
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..errors import ConfigurationError, PersistenceError
from .chain import digest_bytes

ED25519_ALGORITHM = "Ed25519"
PEM_HEADER_PUBLIC = "-----BEGIN PUBLIC KEY-----"
PEM_HEADER_PRIVATE = "-----BEGIN PRIVATE KEY-----"


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _run_openssl(args: list[str], stdin: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["openssl", *args],
            input=stdin,
            capture_output=True,
            check=False,
        )
    except OSError as exc:  # pragma: no cover - openssl_available 已先行检查
        raise ConfigurationError("无法调用 OpenSSL", details={"reason": str(exc)}) from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace").strip()
        raise PersistenceError("OpenSSL 运算失败", details={"reason": reason})
    return completed.stdout


@dataclass(frozen=True, slots=True)
class KeyPair:
    public_pem: bytes
    private_pem: bytes

    @property
    def key_id(self) -> str:
        return digest_bytes(self.public_pem)[:16]


def generate_keypair() -> KeyPair:
    """生成一对 Ed25519 密钥。"""

    if not openssl_available():
        raise ConfigurationError("未找到 openssl 可执行文件，无法生成签名密钥")
    private_pem = _run_openssl(["genpkey", "-algorithm", ED25519_ALGORITHM])
    public_pem = _run_openssl(["pkey", "-pubout"], stdin=private_pem)
    return KeyPair(public_pem=public_pem, private_pem=private_pem)


def save_keypair(pair: KeyPair, private_path: Path, public_path: Path) -> None:
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(pair.private_pem)
    try:
        private_path.chmod(0o600)
    except OSError:  # Windows 等平台不支持权限位时忽略
        pass
    public_path.write_bytes(pair.public_pem)


def load_private_key(path: Path) -> bytes:
    path = Path(path)
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError("私钥不可读", details={"path": str(path)}) from exc
    if PEM_HEADER_PRIVATE not in pem.decode("utf-8", errors="replace"):
        raise ConfigurationError("私钥文件不是 PEM 格式", details={"path": str(path)})
    return pem


def load_public_key(path: Path) -> bytes:
    path = Path(path)
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError("公钥不可读", details={"path": str(path)}) from exc
    if PEM_HEADER_PUBLIC not in pem.decode("utf-8", errors="replace"):
        raise ConfigurationError("公钥文件不是 PEM 格式", details={"path": str(path)})
    return pem


def sign(message: bytes, private_pem: bytes) -> bytes:
    if not openssl_available():
        raise ConfigurationError("未找到 openssl 可执行文件，无法签名")
    # 私钥与消息分别走文件，避免 /dev/stdin 在不同平台行为不一致。
    import tempfile

    with tempfile.TemporaryDirectory(prefix="flashsmelter-sign-") as temp_dir:
        key_path = Path(temp_dir) / "key.pem"
        msg_path = Path(temp_dir) / "msg"
        key_path.write_bytes(private_pem)
        msg_path.write_bytes(message)
        try:
            return _run_openssl(
                ["pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(msg_path)]
            )
        finally:
            key_path.unlink(missing_ok=True)
            msg_path.unlink(missing_ok=True)


def verify_signature(message: bytes, signature: bytes, public_pem: bytes) -> bool:
    """签名合法返回 True；密钥不可用或签名不合法返回 False（不抛错）。"""

    if not openssl_available():
        raise ConfigurationError("未找到 openssl 可执行文件，无法验签")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="flashsmelter-verify-") as temp_dir:
        key_path = Path(temp_dir) / "pub.pem"
        msg_path = Path(temp_dir) / "msg"
        sig_path = Path(temp_dir) / "sig"
        key_path.write_bytes(public_pem)
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        try:
            completed = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-pubin",
                    "-inkey", str(key_path),
                    "-rawin", "-in", str(msg_path),
                    "-sigfile", str(sig_path),
                ],
                capture_output=True,
                check=False,
            )
        except OSError as exc:  # pragma: no cover
            raise ConfigurationError("无法调用 OpenSSL", details={"reason": str(exc)}) from exc
        return completed.returncode == 0


__all__ = [
    "KeyPair",
    "openssl_available",
    "generate_keypair",
    "save_keypair",
    "load_private_key",
    "load_public_key",
    "sign",
    "verify_signature",
]
