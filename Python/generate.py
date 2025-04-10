#!/usr/bin/env python3

"""
Script was made by @alula on GitHub

I made some improvements and modified it to be more user-friendly.
"""

import json
import hashlib
from datetime import datetime


TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'


def license_structure(name: str, email: str, license_key: str) -> dict:
    now = datetime.now()
    ten_years_later = now.replace(year=now.year + 10)

    ts_start = now.strftime(TIMESTAMP_FORMAT)
    ts_end = ten_years_later.strftime(TIMESTAMP_FORMAT)

    base = {
        "header": {"version": 1},
        "payload": {
            "name": name,
            "email": email,
            "licenses": [
                {
                    "id": license_key,
                    "license_type": "named",
                    "product": "IDA",
                    "seats": 1,
                    "start_date": ts_start,
                    "end_date": ts_end,  # This can't be more than 10 years!
                    "issued_on": ts_start,
                    "owner": name,
                    "add_ons": [],
                    "features": [],
                }
            ],
        },
    }

    addons = [
        "HEXX86",
        "HEXX64",
        "HEXARM",
        "HEXARM64",
        "HEXMIPS",
        "HEXMIPS64",
        "HEXPPC",
        "HEXPPC64",
        "HEXRV64",
        "HEXARC",
        "HEXARC64",
        # Probably cloud?
        # "HEXCX86",
        # "HEXCX64",
        # "HEXCARM",
        # "HEXCARM64",
        # "HEXCMIPS",
        # "HEXCMIPS64",
        # "HEXCPPC",
        # "HEXCPPC64",
        # "HEXCRV",
        # "HEXCRV64",
        # "HEXCARC",
        # "HEXCARC64",
    ]

    for i, addon in enumerate(addons):
        base["payload"]["licenses"][0]["add_ons"].append(
            {
                "id": f"48-1337-DEAD-{i:02}",
                "code": addon,
                "owner": base["payload"]["licenses"][0]["id"],
                "start_date": ts_start,
                "end_date": ts_end,
            }
        )

    return base


def json_stringify_alphabetical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def buf_to_bigint(buf: bytes) -> int:
    return int.from_bytes(buf, byteorder="little")


def bigint_to_buf(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="little")


# Yup, you only have to patch 5c -> cb in libida64.so
pub_modulus_hexrays: int = buf_to_bigint(
    bytes.fromhex(
        "edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
    )
)
pub_modulus_patched: int = buf_to_bigint(
    bytes.fromhex(
        "edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
    )
)

private_key: int = buf_to_bigint(
    bytes.fromhex(
        "77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874"
    )
)

example_real_sig_bytes: bytes = bytes.fromhex("8C601843D20AF0997C175723F49D6C6CE77A039F3FFCEC95B89FD99611C0EDDE0B9762A977C408D25662C06B2424B83EDDFBE30177C1A99A881ED1B695F2AD38E4119058463B0CA1BEA651CFCAFBD60E68A407FD76D519063CFB6EF35FFE7C1A375388BC5EB5565C29AFAB06BF0031A7A2AA7433CBD929FD8D12E160981D0812")
example_real_sig_bigint: int = buf_to_bigint(example_real_sig_bytes)


def decrypt(message: bytes, use_patched: bool = True) -> bytes:
    mod: int = pub_modulus_patched if use_patched else pub_modulus_hexrays
    decrypted_bigint: int = pow(buf_to_bigint(message), exponent, mod)
    decrypted_bytes: bytes = bigint_to_buf(decrypted_bigint)
    rev_decrypted_bytes = decrypted_bytes[::-1]
    print(f"decrypt: msg: {message.hex().upper()} decryped_bytes: {decrypted_bytes.hex().upper()} rev_decrypted_bytes: {rev_decrypted_bytes.hex().upper()}")
    return rev_decrypted_bytes


def encrypt(message: bytes, use_patched: bool = True) -> bytes:
    mod: int = pub_modulus_patched if use_patched else pub_modulus_hexrays
    encrypted_bigint: int = pow(buf_to_bigint(message[::-1]), private_key, mod)
    encrypted: bytes = bigint_to_buf(encrypted_bigint)
    print(f"encrypt: msg: {message.hex().upper()} encrypted: {encrypted.hex().upper()}")
    return encrypted


exponent = 0x13


def sign_hexlic(payload: dict) -> str:
    data = {"payload": payload}
    data_str = json_stringify_alphabetical(data)

    buffer = bytearray(128)
    # first 33 bytes are random
    for i in range(33):
        buffer[i] = 0x42

    # compute sha256 of the data
    sha256 = hashlib.sha256()
    sha256.update(data_str.encode())
    digest = sha256.digest()
    print(f"sha-256 digest: {digest.hex().upper()}")

    # copy the sha256 digest to the buffer
    for i in range(len(digest)):
        buffer[33 + i] = digest[i]

    print(f"pre-encrypted buffer: {buffer.hex().upper()}")
    # encrypt the buffer
    encrypted = encrypt(buffer)
    print(f"post-encrypted buffer: {encrypted.hex().upper()}")
    decrypted_sanity = decrypt(encrypted)
    print(f"decrypted encrypted buffer: {decrypted_sanity.hex().upper()}")

    return encrypted.hex().upper()


def main():
    print("IDA Pro 9.0 BETA Keygen")
    print("(!) DISCLAIMER: This is for educational purposes only. (!)")
    print("(!) Please note that you must patch the public modulus inside of the ida and ida64 dynamic libraries. (!)")
    print("  ↳ For more information about this process: https://gist.github.com/AngeloD2022/e949c1c7c2a51513c620ac5dd5212b94\n\n")

    lic_name = input("Enter desired license name (can be fake): ")
    lic_email = input("Enter license email address (can be fake): ")

    print("Generating license base...")
    lic_base = license_structure(lic_name, lic_email, "48-2437-ACBD-29")

    print("Signing...")
    lic_base["signature"] = sign_hexlic(lic_base["payload"])

    print("Generating ida.hexlic...")
    serialized = json_stringify_alphabetical(lic_base)

    with open("ida.hexlic", "w") as file:
        file.write(serialized)

    print("Finished.")


if __name__ == '__main__':
    main()
