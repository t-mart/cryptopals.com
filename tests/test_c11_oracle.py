from cryptopals.oracle import oracle_guess


def test_challenge() -> None:
    # sketchy test here: relies on randomness
    trials = 2**16

    plaintext = (
        b"A" * (16 - 5)
        + b"A" * (16 * 2)  # assume smallest random prefix
        + b"A" * (16 - 5)  # 2 blocks of A  # assume smallest random suffix
    )

    assert all(oracle_guess(plaintext) for _ in range(trials))
