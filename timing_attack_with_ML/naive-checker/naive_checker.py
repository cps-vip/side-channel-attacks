"""Original early-return byte comparator, extracted from timing_lab.py."""

def vulnerable_check(candidate, secret, work=0):
    if len(candidate) != len(secret):
        return False
    for actual, expected in zip(candidate, secret):
        if actual != expected:
            return False
        # Explicit teaching amplification; use --work 0 for the natural leak.
        value = 0
        for i in range(work):
            value ^= i
    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", nargs="?", default="cabd")
    parser.add_argument("--secret", default="cabd", help="synthetic lab value")
    args = parser.parse_args()
    print("Accepted:", vulnerable_check(args.candidate.encode("ascii"), args.secret.encode("ascii")))
