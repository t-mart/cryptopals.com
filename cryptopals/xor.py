from itertools import cycle, combinations
import math
from statistics import mean
from collections.abc import Iterable

from cryptopals.hamming import hamming_distance
from cryptopals.score import ScoreResult, score_bytes_for_english


def repeating_key_xor(s: bytes, key: bytes) -> bytes:
    # encrypt bytes in s by xor-ing them with the bytes in key. bytes from key are
    # applied cyclically to s. so, with a plaintext "Hello, there!" and key "ICE", the
    # xoring is done in the following way:
    #
    #    Hello, there!
    #  ^ ICEICEICEICEI
    #  ---------------
    #      <result>
    out = []

    for c, k in zip(s, cycle(key)):
        out.append(c ^ k)

    return bytes(out)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    # this is just a special case of repeating key xor where the "key" is only cycled
    # through one time
    assert len(a) == len(b)
    return repeating_key_xor(a, b)


def single_byte_xor(s: bytes, key: int) -> bytes:
    # encrypt bytes in s by xor-ing them with key
    # yet another special case of repeating key xor where key has length == 1
    return repeating_key_xor(s, bytes([key]))


def score_single_byte_xor_keys(s: bytes) -> Iterable[ScoreResult]:
    results = []
    for key in range(256):
        msg = single_byte_xor(s, key)
        score = score_bytes_for_english(msg)
        result = ScoreResult(score=score, msg=msg, key=bytes([key]))
        results.append(result)

    yield from sorted(results, reverse=True)


def find_repeating_xor_key(s: bytes) -> bytes:
    best_key_sz = _key_szs_ranked(s)[0]

    key_bytes = []

    for idx in range(best_key_sz):
        nth_bytes_from_blks = _nth_bytes_of_blks(s, best_key_sz, idx)
        best_result = next(
            iter(score_single_byte_xor_keys(b"".join(nth_bytes_from_blks)))
        )
        key_bytes.append(best_result.key)

    return b"".join(key_bytes)


def _key_szs_ranked(
    s: bytes, sz_low: int = 2, sz_hi: int = 40, compares: int = 16
) -> list[int]:
    """
    Return in decreasing order the most probable size of a key that has been used to
    repeating-xor-encrypt the english-language data in the bytes of s.

    The most probable key size for these contents is the one with the smallest hamming
    distance between arbitrary blocks of that size in s. The number of distances taken
    is specified by the compares parameter. It's possible that more comparisons than
    possible is specified, in which case this function will raise a ValueError.

    Key sizes from sz_low to sz_hi (inclusive) will be considered.
    """
    key_szs = []

    for key_sz in range(sz_low, sz_hi + 1):
        n_blocks = len(s) // key_sz

        if math.comb(n_blocks, 2) < compares:
            raise ValueError(
                f"Can't make {compares} comparisons with {n_blocks} blocks"
            )

        norm_dists = []
        blk_combs = combinations(range(n_blocks), 2)
        for _ in range(compares):
            blk_a_idx, blk_b_idx = next(blk_combs)

            blk_a = s[key_sz * blk_a_idx : key_sz * blk_a_idx + key_sz]
            blk_b = s[key_sz * blk_b_idx : key_sz * blk_b_idx + key_sz]

            norm_dist = hamming_distance(blk_a, blk_b) / key_sz
            norm_dists.append(norm_dist)

        avg_norm_dist = mean(norm_dists)

        key_szs.append((avg_norm_dist, key_sz))

    return [key_sz for _, key_sz in sorted(key_szs)]


def _nth_bytes_of_blks(s: bytes, blk_sz: int, n: int) -> list[bytes]:
    out = []
    for chunk_start in range(0, len(s), blk_sz):
        idx = chunk_start + n
        if idx < len(s):
            out.append(bytes([s[idx]]))
    return out
