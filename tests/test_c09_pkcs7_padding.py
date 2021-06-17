from cryptopals.padding import pkcs7_pad, pkcs7_unpad


def test_challenge() -> None:
    data = b"YELLOW SUBMARINE"
    pad_to_length = 20

    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    padded = pkcs7_pad(data, pad_to_length)

    assert padded == expected

    unpadded = pkcs7_unpad(padded)

    assert data == unpadded
