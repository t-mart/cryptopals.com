from cryptopals.bintext import b16dec
from cryptopals.xor import score_single_byte_xor_keys
from tests.fixtures import data_file_lines


def test_challenge() -> None:
    cts = [
        b16dec(line.strip())
        for line in data_file_lines("c04_detect_single_byte_xor.txt")
    ]

    results = [result for ct in cts for result in score_single_byte_xor_keys(ct)]

    results.sort(reverse=True)

    best = results[0]

    # cryptopals doesn't reveal the answers, i only know that these are correct because
    # i solved the challenge before writing the test.
    assert best.msg == b"Now that the party is jumping\n"
    assert best.key == b"5"
