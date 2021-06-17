def pkcs7_pad(s: bytes, blk_sz: int) -> bytes:
    """
    pads s to a block size of blk_sz bytes
    """
    assert 0 < blk_sz < 256, "blk_sz must be in range [1, 255] inclusive."
    assert int(blk_sz) == blk_sz, "blk_sz must be an integer"

    padding_to_add = blk_sz - (len(s) % blk_sz)

    return s + bytes([padding_to_add]) * padding_to_add


def pkcs7_unpad(s: bytes) -> bytes:
    """
    unpads s from a block size of blk_sz bytes
    """

    padding_to_remove = s[-1]

    assert all(
        byte == padding_to_remove for byte in s[len(s) - padding_to_remove :]
    ), "pad characters are not consistent"

    return s[:-padding_to_remove]
