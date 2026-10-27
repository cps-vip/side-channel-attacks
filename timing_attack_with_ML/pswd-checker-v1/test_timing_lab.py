import unittest
from timing_lab import constant_check, vulnerable_check, make_oracle
from lab_config import DEFAULT_ALPHABET, validate_secret, validate_alphabet


class CheckerTests(unittest.TestCase):
    def test_supported_lengths_and_alphanumeric_passwords(self):
        for length in range(4, 17):
            secret = (b'a0z9b1y8c2x7d3w6')[:length]
            for mode in ('vulnerable', 'constant'):
                oracle = make_oracle(secret, mode, 0)
                self.assertTrue(oracle(secret))
                self.assertFalse(oracle(secret[:-1]))
                self.assertFalse(oracle(b'!' + secret[1:]))

    def test_password_and_alphabet_constraints(self):
        self.assertEqual(len(DEFAULT_ALPHABET), 36)
        validate_alphabet(DEFAULT_ALPHABET.encode())
        for secret in (b'', b'abc', b'a' * 17, b'Ab12', b'ab!2', b'ab 2'):
            with self.assertRaises(ValueError):
                validate_secret(secret)
            with self.assertRaises(ValueError):
                make_oracle(secret, 'vulnerable', 0)
        for alphabet in (b'a', b'aabc', b'abCD', b'ab!1'):
            with self.assertRaises(ValueError):
                validate_alphabet(alphabet)

    def test_checkers_accept_only_exact_password(self):
        for checker in (vulnerable_check, constant_check):
            for candidate in (b'', b'c', b'cab', b'cabdd', b'abcd', b'cabe'):
                self.assertFalse(checker(candidate, b'cabd'))
            self.assertTrue(checker(b'cabd', b'cabd'))


if __name__ == '__main__':
    unittest.main()
