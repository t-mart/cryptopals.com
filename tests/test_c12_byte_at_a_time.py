from cryptopals.oracle import (
    crack_ecb_contents,
    discover_blk_sz,
    ECBRandEncryptor,
    discover_unknown_data_length,
)
from cryptopals.bintext import b64dec


def test_challenge() -> None:
    encryptor = ECBRandEncryptor.create()

    blk_sz = discover_blk_sz(encryptor)

    assert blk_sz == 16

    unknown_data_length = discover_unknown_data_length(encryptor, blk_sz)

    unknown_data = crack_ecb_contents(encryptor, blk_sz, unknown_data_length)

    assert b64dec(encryptor.unknown_data) == unknown_data
