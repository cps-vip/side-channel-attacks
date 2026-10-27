import unittest

from naive_checker import vulnerable_check


class OriginalCheckerTests(unittest.TestCase):
    def test_exact_match_and_rejections(self):
        self.assertTrue(vulnerable_check(b'cabd', b'cabd'))
        for candidate in (b'', b'cab', b'cabdd', b'abcd', b'cabe'):
            self.assertFalse(vulnerable_check(candidate, b'cabd'))

    def test_digit_password_and_original_optional_work(self):
        self.assertTrue(vulnerable_check(b'a0z9', b'a0z9', work=10))
        self.assertFalse(vulnerable_check(b'a0z8', b'a0z9', work=10))


if __name__ == '__main__':
    unittest.main()
