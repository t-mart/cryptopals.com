_ALPHABETS = {
    16: "0123456789ABCDEF",
    64: R"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
}

_ENCODE = {
    base: {value: encoding for value, encoding in enumerate(alphabet)}
    for base, alphabet in _ALPHABETS.items()
}

_B64_ENCODE = _ENCODE[64]
_B16_ENCODE = _ENCODE[16]

_B64_DECODE = {encoding: value for value, encoding in _B64_ENCODE.items()}
_B16_DECODE = {encoding: value for value, encoding in _B16_ENCODE.items()}

PAD_CHAR = "="


def b64dec(s: str) -> bytes:
    codes_in_quantum = 4
    out = []
    buf = 0
    padding_seen = 0

    if len(s) % codes_in_quantum != 0:
        raise ValueError("Input string must have length divisible by 4.")

    quanta = (s[i : i + codes_in_quantum] for i in range(0, len(s), codes_in_quantum))
    for quantum in quanta:
        for code in quantum:
            buf <<= 6
            if code in _B64_DECODE:
                if padding_seen > 0:
                    raise ValueError(
                        "Found padding character in middle of input string"
                    )
                buf += _B64_DECODE[code]
            elif code == PAD_CHAR:
                padding_seen += 1
            else:
                raise ValueError("Illegal character in input string")

        # padding == 0, 1, or 2: add octet 0 (always)
        byte_0 = (buf & 0xFF0000) >> 16
        out.append(byte_0)

        # padding == 0 or 1: add octet 1
        if padding_seen < 2:
            byte_1 = (buf & 0xFF00) >> 8
            out.append(byte_1)

        # padding == 0: add octet 2
        if padding_seen == 0:
            byte_2 = buf & 0xFF
            out.append(byte_2)

        if padding_seen >= 3:
            raise ValueError("Illegal number of padding characters in input string")

        buf = 0

    return bytes(out)


def b16dec(s: str) -> bytes:
    codes_in_quantum = 2
    out = []
    byte = 0

    s = s.upper()

    if len(s) % codes_in_quantum != 0:
        raise ValueError("Input string must have length divisible by 2.")

    quanta = (s[i : i + codes_in_quantum] for i in range(0, len(s), codes_in_quantum))
    for quantum in quanta:
        for code in quantum:
            byte <<= 4
            if code in _B16_DECODE:
                byte += _B16_DECODE[code]
            else:
                raise ValueError("Illegal character in input string")
        out.append(byte)
        byte = 0

    return bytes(out)


def b64enc(s: bytes) -> str:
    bits_in_quantum = 24
    buf = 0
    bits_in_buf = 0
    out = []

    for c in s:
        # keep feeding bits into buffer...
        buf <<= 8
        buf += c
        bits_in_buf += 8

        # until buffer has 24 bits
        if bits_in_buf == bits_in_quantum:
            # use masks and shifts to obtain the 6 bits of each code
            sextet_0 = (buf & 0xFC0000) >> 18
            sextet_1 = (buf & 0x3F000) >> 12
            sextet_2 = (buf & 0xFC0) >> 6
            sextet_3 = buf & 0x3F

            # lookup those codes in code dict and add them to output
            out.extend(
                [
                    _B64_ENCODE[sextet_0],
                    _B64_ENCODE[sextet_1],
                    _B64_ENCODE[sextet_2],
                    _B64_ENCODE[sextet_3],
                ]
            )

            buf = 0
            bits_in_buf = 0

    # if there are remaining bits in the buffer...
    if bits_in_buf == 16:
        # 16 bits left means 1 pad character needs to be added
        sextet_0 = (buf & 0xFC00) >> 10
        sextet_1 = (buf & 0x3F0) >> 4
        sextet_2 = (buf & 0xF) << 2
        out.extend(
            [
                _B64_ENCODE[sextet_0],
                _B64_ENCODE[sextet_1],
                _B64_ENCODE[sextet_2],
                PAD_CHAR,
            ]
        )
    elif bits_in_buf == 8:
        # 8 bits left means 2 pad characters need to be added
        sextet_0 = (buf & 0xFC) >> 2
        sextet_1 = (buf & 0x3) << 4
        out.extend(
            [
                _B64_ENCODE[sextet_0],
                _B64_ENCODE[sextet_1],
                PAD_CHAR,
                PAD_CHAR,
            ]
        )

    return "".join(out)


def b16enc(s: bytes) -> str:
    out = []

    for c in s:
        quartet_0 = (c & 0xF0) >> 4
        quartet_1 = c & 0xF
        out.extend(
            [
                _B16_ENCODE[quartet_0],
                _B16_ENCODE[quartet_1],
            ]
        )

    return "".join(out)
