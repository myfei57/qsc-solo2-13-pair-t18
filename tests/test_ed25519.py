"""Ed25519 纯 Python 实现的标准向量与互通性测试。

向量来源：

* RFC 8032 第 7.1 节 TEST 2（消息 0x72，逐字节核对）；
* 一组用 **OpenSSL 3 现场生成/签名**的固定夹具，覆盖短消息、中文 UTF-8 与
  200 字节长消息，确保本实现与浏览器 Web Crypto、OpenSSL 等外部实现互通
  （公钥推导、签名、验签三项逐字节一致）。
"""

from __future__ import annotations

import unittest

from flashsmelter.audit import ed25519

# OpenSSL 3 对固定种子 0123...cdef 的权威输出（见测试夹具生成过程）。
OPENSSL_FIXTURE = {
    "seed_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "pub_hex": "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
    "vectors": [
        {
            "msg_hex": "72",
            "sig_hex": "d8c5d1d4ab9a08e870594658387d583983cf0e2949b6da9904e4dd831b63202f"
            "fc1ad16ed5db2bb051edc423a3d159981ed62cfe2b1157584056eda97a668802",
        },
        {
            "msg_hex": "e694bee9939ce68c87e4bba42338383432206175646974",
            "sig_hex": "401e8eb46b374fd3e4434306f0bd5c7807fb6232012578cbeb956fa9324ac6e2"
            "d5b93d2fb4c8965a9f1633d26703d0edc2b357e43aac26f27ea5126b9d0b6002",
        },
        {
            "msg_hex": "78" * 200,
            "sig_hex": "271d5206a41fd282a1359059d0dad5cec1a6e82439c73700302c0dff36873b00"
            "8ed6c1368457c5fb94e8db9a67eab7c5cf78bf490f7f68b98d8f99bee57a1702",
        },
    ],
}


class Ed25519VectorTest(unittest.TestCase):
    def test_rfc8032_test_vector_2(self) -> None:
        secret = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        public = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        message = bytes.fromhex("72")
        signature = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertEqual(ed25519.public_key(secret), public)
        self.assertEqual(ed25519.sign(secret, message), signature)
        self.assertTrue(ed25519.verify(public, message, signature))
        # 负向：改消息 / 改签名一个字节
        self.assertFalse(ed25519.verify(public, b"x", signature))
        flipped = signature[:-1] + bytes([signature[-1] ^ 1])
        self.assertFalse(ed25519.verify(public, message, flipped))

    def test_openssl_fixture_roundtrip(self) -> None:
        secret = bytes.fromhex(OPENSSL_FIXTURE["seed_hex"])
        public = bytes.fromhex(OPENSSL_FIXTURE["pub_hex"])
        # 公钥推导与 OpenSSL 逐字节一致
        self.assertEqual(ed25519.public_key(secret), public)
        for item in OPENSSL_FIXTURE["vectors"]:
            message = bytes.fromhex(item["msg_hex"])
            signature = bytes.fromhex(item["sig_hex"])
            # 签名与 OpenSSL 确定性签名逐字节一致，并能被本实现验过
            self.assertEqual(ed25519.sign(secret, message), signature)
            self.assertTrue(ed25519.verify(public, message, signature))

    def test_generated_keypair_roundtrip(self) -> None:
        secret, public = ed25519.generate_key()
        message = "放铜指令 audit#1024".encode("utf-8")
        signature = ed25519.sign(secret, message)
        self.assertTrue(ed25519.verify(public, message, signature))
        self.assertFalse(ed25519.verify(public, message + b"!", signature))
        # 畸形输入一律安全返回 False，不抛异常
        self.assertFalse(ed25519.verify(b"\x00" * 32, message, signature))
        self.assertFalse(ed25519.verify(public, message, b"\x00" * 64))
        self.assertFalse(ed25519.verify(b"short", message, signature))

    def test_rejects_malformed_secret(self) -> None:
        with self.assertRaises(ValueError):
            ed25519.public_key(b"\x00" * 31)
        with self.assertRaises(ValueError):
            ed25519.sign(b"\x00" * 33, b"m")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
