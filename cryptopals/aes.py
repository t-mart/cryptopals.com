from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptopals.xor import xor_bytes

BLK_SZ_BYTES = 16


def ecb_encrypt(s: bytes, key: bytes) -> bytes:
    """plz pad before"""

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()  # type: ignore

    ct = encryptor.update(s) + encryptor.finalize()

    return ct  # type: ignore


def ecb_decrypt(s: bytes, key: bytes) -> bytes:
    """plz pad after"""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()  # type: ignore

    pt = decryptor.update(s) + decryptor.finalize()

    return pt  # type: ignore


def cbc_encrypt(s: bytes, key: bytes, iv: bytes) -> bytes:
    """plz pad before"""
    assert len(iv) == BLK_SZ_BYTES

    ct = b""
    last_ct_blk = iv

    for blk in (s[i : i + BLK_SZ_BYTES] for i in range(0, len(s), BLK_SZ_BYTES)):
        xored = xor_bytes(last_ct_blk, blk)
        new_ct_blk = ecb_encrypt(xored, key)
        ct += new_ct_blk
        last_ct_blk = new_ct_blk

    return ct


def cbc_decrypt(s: bytes, key: bytes, iv: bytes) -> bytes:
    """plz pad after"""
    assert len(iv) == BLK_SZ_BYTES

    pt = b""
    last_ct_blk = iv

    for blk in (s[i : i + BLK_SZ_BYTES] for i in range(0, len(s), BLK_SZ_BYTES)):
        new_pt_blk = ecb_decrypt(blk, key)
        xored = xor_bytes(last_ct_blk, new_pt_blk)
        pt += xored
        last_ct_blk = blk

    return pt
