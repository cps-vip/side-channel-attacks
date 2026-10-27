import unittest
import sys
from pathlib import Path
from native_attack import NativeLab


@unittest.skipUnless(sys.platform == 'win32' and Path(__file__).with_name('native_windows.dll').exists(),
                     'requires Windows and a built native DLL')
class NativeTests(unittest.TestCase):
    def test_all_supported_lengths_and_native_constraints(self):
        for length in range(4, 17):
            secret = b'a0z9b1y8c2x7d3w6'[:length]
            lab = NativeLab(secret)
            try:
                for mode in (0, 1):
                    self.assertTrue(lab.check(secret, mode))
                    self.assertFalse(lab.check(secret[:-1], mode))
                    self.assertFalse(lab.check(b'!' + secret[1:], mode))
                # Exercise C validation directly, bypassing Python validation.
                for invalid in (b'abc', b'a' * 17):
                    self.assertEqual(lab.dll.lab_init(invalid, len(invalid), 0, -1), 1)
                self.assertEqual(lab.dll.lab_init(b'Ab12', 4, 0, -1), 6)
            finally:
                lab.close()

    def test_correctness_and_counter_readings(self):
        lab = NativeLab(b'cabd')
        try:
            for mode in (0, 1):
                self.assertTrue(lab.check(b'cabd', mode))
                for candidate in (b'', b'c', b'cabdd', b'abcd', b'cabe', b'ca\x00d'):
                    self.assertFalse(lab.check(candidate, mode))
                reading = lab.measure(b'cabd', mode, 10000)
                self.assertGreater(reading.wall_ns, 0)
                self.assertGreater(reading.tsc_ticks, 0)
                self.assertGreater(reading.thread_cycles, 0)
        finally:
            lab.close()


if __name__ == '__main__':
    unittest.main()
