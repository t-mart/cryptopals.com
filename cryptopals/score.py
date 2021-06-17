import string
from functools import total_ordering

ENGLISH_LETTER_FREQUENCY = {
    "e": 0.13,
    "t": 0.091,
    "a": 0.082,
    "o": 0.075,
    "i": 0.07,
    "n": 0.067,
    "s": 0.063,
    "h": 0.061,
    "r": 0.06,
    "d": 0.043,
    "l": 0.04,
    "u": 0.028,
    "c": 0.028,
    "w": 0.024,
    "m": 0.024,
    "f": 0.022,
    "y": 0.02,
    "g": 0.02,
    "p": 0.019,
    "b": 0.015,
    "v": 0.0098,
    "k": 0.0077,
    "x": 0.0015,
    "j": 0.0015,
    "q": 0.00095,
    "z": 0.00074,
}


def score_bytes_for_english(s: bytes) -> float:
    # kinda an arbitrary scorer for finding english text
    # letter frequency is taken into account, where more frequently letters improve the
    # score
    # if the letter is not printable, the score is reduced
    # if the bytes contain spaces (i.e. word delimiters), the score is improved
    total = 0.0

    for c in s:
        char = chr(c).lower()
        if char in ENGLISH_LETTER_FREQUENCY:
            total += ENGLISH_LETTER_FREQUENCY[char]
        elif char not in string.printable:
            total += -0.1

    total *= s.count(b" ") + 1

    return total


@total_ordering
class ScoreResult:
    def __init__(self, *, score: float, msg: bytes, key: bytes):
        self.score = score
        self.msg = msg
        self.key = key

    def __eq__(self, o: object) -> bool:
        return hasattr(o, "score") and self.score == o.score

    def __lt__(self, o: object) -> bool:
        return hasattr(o, "score") and self.score < o.score
