"""Shared constraints for synthetic passwords in the local research lab."""
import string

DEFAULT_ALPHABET = string.ascii_lowercase + string.digits
MIN_LENGTH = 4
MAX_LENGTH = 16


def validate_secret(secret):
    if not MIN_LENGTH <= len(secret) <= MAX_LENGTH:
        raise ValueError('synthetic passwords must contain 4–16 characters')
    if any(c not in DEFAULT_ALPHABET.encode('ascii') for c in secret):
        raise ValueError('synthetic passwords must use lowercase a–z or digits 0–9')


def validate_alphabet(alphabet):
    allowed = DEFAULT_ALPHABET.encode('ascii')
    if (not 2 <= len(alphabet) <= len(allowed) or
            len(set(alphabet)) != len(alphabet) or
            any(c not in allowed for c in alphabet)):
        raise ValueError('alphabet must contain 2–36 unique lowercase letters or digits')
