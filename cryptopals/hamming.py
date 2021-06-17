def hamming_distance(a: bytes, b: bytes) -> int:
    assert len(a) == len(b)

    dist = 0

    for a_byte, b_byte in zip(a, b):
        dist += _hamming_distance_byte(a_byte, b_byte)

    return dist


def _hamming_distance_byte(a: int, b: int) -> int:
    z = a ^ b
    dist = 0
    while z:
        if z & 1:
            dist += 1
        z >>= 1
    return dist


if __name__ == "__main__":
    a = b"this is a test"
    b = b"wokka wokka!!!"
    assert hamming_distance(a, b) == 37
