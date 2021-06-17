from __future__ import annotations
import secrets

from cryptopals.aes import cbc_encrypt, ecb_encrypt, BLK_SZ_BYTES
from cryptopals.padding import pkcs7_pad
from cryptopals.bintext import b64dec


class RandomEncryption:
    def __init__(self, *, ciphertext: bytes, mode: str) -> None:
        self.ciphertext = ciphertext
        self.mode = mode


def _rand_key(sz: int) -> bytes:
    return secrets.token_bytes(sz)


def _rand_iv(blk_sz: int) -> bytes:
    return secrets.token_bytes(blk_sz)


def _encrypt_with_rand_key(s: bytes, key_sz: int) -> RandomEncryption:
    """
    Return a RandomEncryption object of which our oracle should be able to determine the
    mode.

    The ciphertext in the object will be from a plaintext that has 5-10 random bytes
    prefixed and suffixed to it. The encryption algorithm will be AES, with a 50-50
    chance of being in ECB or CBC mode.

    The RandomEncryption object records the mode to create the ciphertext, but
    obviously, this should only be used to verify our guess.
    """
    # have the function append 5-10 bytes (count chosen randomly) before the plaintext
    # and 5-10 bytes after the plaintext.
    # i use hex strings instead of true random so that it's easier to decode later
    rand_prefix = secrets.token_hex(secrets.choice(range(5, 11))).encode("utf-8")
    rand_suffix = secrets.token_hex(secrets.choice(range(5, 11))).encode("utf-8")

    s = pkcs7_pad(rand_prefix + s + rand_suffix, BLK_SZ_BYTES)

    use_ecb = secrets.choice([True, False])

    key = _rand_key(key_sz)

    if use_ecb:
        return RandomEncryption(
            ciphertext=ecb_encrypt(s, key),
            mode="ecb",
        )
    else:
        return RandomEncryption(
            ciphertext=cbc_encrypt(s, key, _rand_iv(BLK_SZ_BYTES)),
            mode="cbc",
        )


def oracle_guess(plaintext: bytes) -> bool:
    """
    From https://cryptopals.com/sets/2/challenges/11:
    "Detect the block cipher mode the function is using each time. You should end up
    with a piece of code that, pointed at a block box that might be encrypting ECB or
    CBC, tells you which one is happening."

    So yeah, this function does that detection. What I'm assuming is okay is I know:
        - I know about the random byte prefix/suffix additions
        - I can feed this oracle whatever text I want. Specifically, with an plaintext
          of all the same bytes, I'll know ECB was used if I can find identical blocks.
          (I suppose it's possible CBC might produce identical blocks in this case too,
          but it's super rare... like 1/2**16 chance.)

    The return value is a boolean representing whether we made the right guess or not.
    """

    rand_enc = _encrypt_with_rand_key(plaintext, 16)
    ciphertext = rand_enc.ciphertext

    n_blks = len(ciphertext) // BLK_SZ_BYTES

    middle_blk_a_start_idx = ((n_blks // 2) - 1) * BLK_SZ_BYTES
    middle_blk_b_start_idx = (n_blks // 2) * BLK_SZ_BYTES
    middle_blk_b_end_idx = ((n_blks // 2) + 1) * BLK_SZ_BYTES

    middle_blk_a = ciphertext[middle_blk_a_start_idx:middle_blk_b_start_idx]
    middle_blk_b = ciphertext[middle_blk_b_start_idx:middle_blk_b_end_idx]

    assert len(middle_blk_a) == len(middle_blk_b), "ciphertext too small to guess on"

    using_ecb = middle_blk_a == middle_blk_b

    return (rand_enc.mode == "ecb" and using_ecb) or not using_ecb


class ECBRandEncryptor:
    """
    An object that can encrypt plaintexts with the same key. Plaintexts are appended-to
    with some fixed data, which we are trying to attack. We're not supposed to know the
    key nor the actual value of the data.
    """

    unknown_data = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )

    def __init__(self, key: bytes) -> None:
        self.key = key

    @classmethod
    def create(cls, key_sz: int = 16) -> ECBRandEncryptor:
        return cls(key=_rand_key(key_sz))

    def encrypt(self, plaintext: bytes) -> bytes:
        return ecb_encrypt(
            s=pkcs7_pad(plaintext + b64dec(self.unknown_data), BLK_SZ_BYTES),
            key=self.key,
        )


def discover_blk_sz(encryptor: ECBRandEncryptor) -> int:
    """
    Return the block size of AES-128 in bytes. (lol, hint: it's 128 bits/16 bytes). But
    this is an exercise for when the algorithm's properties are unknown.
    """

    blk_sz = 1
    char = b"A"

    while True:
        # insert 2 blocks in of the same data
        my_data = char * blk_sz * 2
        ciphertext = encryptor.encrypt(my_data)

        # then get 2 blocks from the ciphertext
        blk_a = ciphertext[:blk_sz]
        blk_b = ciphertext[blk_sz : blk_sz * 2]

        # see if they're equal
        if blk_a == blk_b:
            return blk_sz

        blk_sz += 1


def discover_unknown_data_length(encryptor: ECBRandEncryptor, blk_sz: int) -> int:
    my_data = b""
    initial_length = len(encryptor.encrypt(my_data))

    # initial length contains padding, we know this.
    # when the new data triggers an additional byte, we know that that many
    # bytes filled the last block and caused a new padding block to be output.
    # therefore, initial length - len(bytes that cause trigger) = original len
    while True:
        my_data += b"A"
        new_length = len(encryptor.encrypt(my_data))
        if new_length > initial_length:
            return initial_length - len(my_data)


def crack_ecb_contents(
    encryptor: ECBRandEncryptor,
    blk_sz: int,
    contents_sz: int,
) -> bytes:
    cur_blk_idx = 0

    contents = b""

    while True:
        for fill_count in range(15, -1, -1):
            plaintext = b"A" * fill_count
            ciphertext = encryptor.encrypt(plaintext)
            cur_blk = ciphertext[blk_sz * cur_blk_idx : blk_sz * (cur_blk_idx + 1)]

            for byte in (bytes([b]) for b in range(256)):
                brute_plaintext = plaintext + contents + byte
                brute_ciphertext = encryptor.encrypt(brute_plaintext)
                brute_blk = brute_ciphertext[
                    blk_sz * cur_blk_idx : blk_sz * (cur_blk_idx + 1)
                ]
                if brute_blk == cur_blk:
                    contents += byte
                    break
            else:
                raise ValueError(f"Couldn't crack byte #{len(contents)}")

            if len(contents) == contents_sz:
                return contents

        cur_blk_idx += 1
