"""V2 ctypes bridge; run experiments through research_pipeline.py."""
import ctypes as ct
from pathlib import Path
from lab_config import validate_secret


class Measurement(ct.Structure):
    _fields_ = [('wall_ns', ct.c_double), ('tsc_ticks', ct.c_uint64),
                ('thread_cycles', ct.c_uint64), ('aux_start', ct.c_uint),
                ('aux_end', ct.c_uint)]


class NativeLab:
    def __init__(self, secret, work=0, cpu=-1):
        validate_secret(secret)
        self.dll = ct.CDLL(str(Path(__file__).with_name('native_windows.dll')))
        self.dll.lab_init.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_uint, ct.c_int]
        self.dll.lab_init.restype = ct.c_int
        self.dll.lab_check.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int]
        self.dll.lab_check.restype = ct.c_int
        self.dll.lab_measure.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int,
                                        ct.c_uint, ct.POINTER(Measurement)]
        self.dll.lab_measure.restype = ct.c_int
        self.dll.lab_close.argtypes = []
        self.dll.lab_close.restype = None
        status = self.dll.lab_init(secret, len(secret), work, cpu)
        if status:
            self.dll.lab_close()
            raise RuntimeError(f'Native initialization failed ({status}): '
                               '1=length, 2=RDTSCP, 3=invariant TSC, 4=QPC, 5=affinity, 6=password alphabet, 7=SHA-256 provider')

    def check(self, guess, mode):
        return bool(self.dll.lab_check(guess, len(guess), mode))

    def measure(self, guess, mode, batch):
        result = Measurement()
        status = self.dll.lab_measure(guess, len(guess), mode, batch, ct.byref(result))
        if status:
            raise RuntimeError(f'Native measurement failed ({status})')
        return result

    def close(self):
        self.dll.lab_close()

