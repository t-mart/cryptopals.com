from cryptopals.bintext import b64dec
from tests.fixtures import data_file_lines
from cryptopals.aes import BLK_SZ_BYTES


def test_challenge() -> None:
    cts = [b64dec(line) for line in data_file_lines("c08_detect_aes_ecb.txt")]

    smallest_uniq_blks = len(cts[0]) // BLK_SZ_BYTES
    smallest_uniq_blks_idx = -1

    for idx, ct in enumerate(cts):
        uniq_blks = set(
            ct[i : i + BLK_SZ_BYTES] for i in range(0, len(ct), BLK_SZ_BYTES)
        )

        if len(uniq_blks) < smallest_uniq_blks:
            smallest_uniq_blks = len(uniq_blks)
            smallest_uniq_blks_idx = idx

    assert smallest_uniq_blks == 12
    assert smallest_uniq_blks_idx == 132
