"""Split utility adapted from v1; timing and learning are implemented separately in v2."""
import hashlib
import math
import random

def make_secrets(count, alphabet, min_length, max_length, seed, excluded=()):
    """Balance lengths and stratify whole unique secrets, never timing rows.

    Largest-remainder allocation approximates 70/15/15 within each length.
    Ties alternate to avoid systematically favoring validation over test.
    At least one secret per split/length is required.
    """
    rng = random.Random(seed)
    entries, seen = [], set(excluded)
    lengths = list(range(min_length, max_length + 1))
    if count < 3 * len(lengths):
        raise ValueError('need at least 3 passwords per requested length')
    for offset, length in enumerate(lengths):
        n = count // len(lengths) + int(offset < count % len(lengths))
        used = sum(len(s) == length and all(c in alphabet for c in s) for s in seen)
        if n > len(alphabet) ** length - used:
            raise ValueError('not enough distinct passwords for this alphabet and length')
        passwords = []
        while len(passwords) < n:
            secret = ''.join(rng.choice(alphabet) for _ in range(length))
            if secret not in seen:
                seen.add(secret)
                passwords.append(secret)
        # Reserve one per split, then approximate the requested percentages.
        exact = [n * .7, n * .15, n * .15]
        counts = [max(1, math.floor(x)) for x in exact]
        while sum(counts) > n:
            i = max((i for i in range(3) if counts[i] > 1),
                    key=lambda i: counts[i] - exact[i])
            counts[i] -= 1
        while sum(counts) < n:
            order = [0, 1, 2] if offset % 2 == 0 else [0, 2, 1]
            i = max(order, key=lambda i: exact[i] - counts[i])
            counts[i] += 1
        start = 0
        for split, size in zip(('train', 'validation', 'test'), counts):
            for secret in passwords[start:start + size]:
                entries.append({'secret_id': hashlib.sha256(secret.encode()).hexdigest()[:16],
                                'secret': secret, 'length': length, 'split': split})
            start += size
    rng.shuffle(entries)
    return entries


def audit_manifest(manifest):
    entries = manifest['passwords']
    if len({p['secret'] for p in entries}) != len(entries):
        raise ValueError('duplicate passwords in manifest')
    if len({p['secret_id'] for p in entries}) != len(entries):
        raise ValueError('duplicate password IDs in manifest')
    if {p['split'] for p in entries} != {'train', 'validation', 'test'}:
        raise ValueError('all three splits are required')
    for entry in entries:
        if entry['length'] != len(entry['secret']):
            raise ValueError('incorrect length in manifest')

