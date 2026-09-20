"""纯 Python Ed25519（RFC 8032），零第三方依赖。

离线核验包必须能在断网、不能 pip 安装的车间机器上验签，因此不依赖
``cryptography``；实现采用 RFC 8032 的扩展坐标参考算法，公开 API 只有
:func:`generate_key`、:func:`sign` 与 :func:`verify`。
"""

from __future__ import annotations

import hashlib
import os
from typing import Tuple

q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def _H(message: bytes) -> bytes:
    return hashlib.sha512(message).digest()


def _expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _inv(x: int) -> int:
    return _expmod(x, q - 2, q)


d = -121665 * _inv(121666)
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5)
Bx = _xrecover(By)
B = (Bx, By, 1, (Bx * By) % q)


def _edwards(P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """RFC 8032 参考实现的扩展坐标统一加法（不消 z）。

    之前用的 affine 分式在 z≠1 的点上虽仍落在曲线上，但参与 cofactor 验证的
    多基点组合时与标准结果不同，导致外部（OpenSSL/浏览器）签名验不过。
    """

    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % q
    Bb = ((y1 + x1) * (y2 + x2)) % q
    C = (t1 * 2 * d * t2) % q
    Dd = (z1 * 2 * z2) % q
    E = (Bb - A) % q
    F = (Dd - C) % q
    G = (Dd + C) % q
    H = (Bb + A) % q
    return ((E * F) % q, (G * H) % q, (F * G) % q, (E * H) % q)


def _scalarmult(P: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodepoint(P: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    result = bytearray(32)
    for i, bit in enumerate(bits):
        result[i // 8] |= bit << (i % 8)
    return bytes(result)


def _decodepoint(s: bytes) -> Tuple[int, int, int, int]:
    y = 0
    for i in range(255):
        y |= _bit(s, i) << i
    x = _xrecover(y)
    if (x & 1) != _bit(s, 255):
        x = q - x
    P = (x, y, 1, (x * y) % q)
    if not _isoncurve(P):
        raise ValueError("点不在曲线上")
    return P


def _isoncurve(P: Tuple[int, int, int, int]) -> bool:
    x, y, z, t = P
    # 扩展坐标一致性：XY = ZT；曲线：Y²−X² = Z² + d·T²（均在 mod q 下）。
    if (x * y - z * t) % q != 0:
        return False
    return (y * y - x * x - z * z - d * t * t) % q == 0


def _hint(m: bytes) -> int:
    """SHA-512 摘要按小端序当作整数（RFC 8032 的 Hint 读法）。"""

    return int.from_bytes(_H(m), "little")


def generate_key() -> Tuple[bytes, bytes]:
    """返回 ``(私钥 32B, 公钥 32B)``；私钥请离线保管。"""

    seed = os.urandom(32)
    return seed, public_key(seed)


def _clamped_scalar(h: bytes) -> int:
    """RFC 8032 标量夹紧：低 32 字节清 bit0-2、清 bit255、置 bit254。"""

    clamped = bytearray(h[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(bytes(clamped), "little")


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("私钥种子必须是 32 字节")
    a = _clamped_scalar(_H(seed))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def sign(seed: bytes, message: bytes) -> bytes:
    """对 ``message`` 返回 64 字节签名。"""

    if len(seed) != 32:
        raise ValueError("私钥种子必须是 32 字节")
    h = _H(seed)
    a = _clamped_scalar(h)
    A = _encodepoint(_scalarmult(B, a))
    r = _hint(h[32:64] + message)
    R = _encodepoint(_scalarmult(B, r))
    S = (r + _hint(R + A + message) * a) % l
    return R + _encodeint(S)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """校验签名；任何畸形输入都返回 ``False``，不抛异常。"""

    try:
        if len(public_key_bytes) != 32 or len(signature) != 64:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key_bytes)
        S = _decodeint(signature[32:])
        if S >= l:
            return False
        h = _hint(_encodepoint(R) + public_key_bytes + message)
        # 扩展坐标下同一射影点有多种 (X,Y,Z,T) 表示，必须比较编码后的压缩点，
        # 不能直接比较元组。
        return _encodepoint(_scalarmult(B, S)) == _encodepoint(_edwards(R, _scalarmult(A, h)))
    except (ValueError, ZeroDivisionError):
        return False


__all__ = ["generate_key", "public_key", "sign", "verify"]
