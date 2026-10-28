"""V2 ctypes bridge; run experiments through research_pipeline.py."""
import ctypes as ct
from pathlib import Path
import sys
import threading
from experiment_schema import LINUX, native_backend
from lab_config import validate_secret


class WindowsMeasurement(ct.Structure):
    _fields_ = [('wall_ns', ct.c_double), ('tsc_ticks', ct.c_uint64),
                ('thread_cycles', ct.c_uint64), ('aux_start', ct.c_uint),
                ('aux_end', ct.c_uint)]


class LinuxMeasurement(ct.Structure):
    _fields_ = [('wall_ns', ct.c_double), ('tsc_ticks', ct.c_uint64),
                ('thread_cpu_ns', ct.c_uint64), ('aux_start', ct.c_uint),
                ('aux_end', ct.c_uint)]


Measurement = LinuxMeasurement if sys.platform == 'linux' else WindowsMeasurement


class NativeLab:
    def __init__(self, secret, work=0, cpu=-1):
        validate_secret(secret)
        self.backend = native_backend()
        self._closed = True
        self._thread = threading.get_ident()
        if not isinstance(work, int) or not 0 <= work <= 0xffffffff:
            raise ValueError('work must be a nonnegative uint32')
        if not isinstance(cpu, int) or not -1 <= cpu <= 0x7fffffff:
            raise ValueError('cpu must be -1 or a nonnegative int32')
        if self.backend == LINUX and work:
            raise ValueError('Linux measurements require work=0; amplification is unsupported')
        self._measurement = LinuxMeasurement if self.backend == LINUX else WindowsMeasurement
        filename = 'native_linux.so' if self.backend == LINUX else 'native_windows.dll'
        try:
            self.dll = ct.CDLL(str(Path(__file__).with_name(filename)))
        except OSError as error:
            raise RuntimeError(f'Cannot load {filename}; build it on this machine first: {error}') from error
        self.dll.lab_init.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_uint, ct.c_int]
        self.dll.lab_init.restype = ct.c_int
        self.dll.lab_check.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int]
        self.dll.lab_check.restype = ct.c_int
        self.dll.lab_measure.argtypes = [ct.c_char_p, ct.c_size_t, ct.c_int,
                                        ct.c_uint, ct.POINTER(self._measurement)]
        self.dll.lab_measure.restype = ct.c_int
        self.dll.lab_close.argtypes = []
        self.dll.lab_close.restype = ct.c_int if self.backend == LINUX else None
        status = self.dll.lab_init(secret, len(secret), work, cpu)
        if status:
            # A rejected second Linux instance must not close the first one.
            if status != 9:
                self.dll.lab_close()
            raise RuntimeError(f'Native initialization failed ({status}): '
                               '1=length, 2=RDTSCP, 3=invariant TSC, 4=clock/QPC, '
                               '5=affinity, 6=password alphabet, 7=SHA-256 provider, '
                               '8=amplification unsupported, 9=another lab is already open')
        self._closed = False

    def _require_open(self):
        if self._closed:
            raise RuntimeError('Native lab is closed')
        if self._thread != threading.get_ident():
            raise RuntimeError('Use and close NativeLab on its initializing thread')

    def _require_mode(self, mode, measuring=False):
        allowed = (0, 1, 2) if measuring else (0, 1)
        if self.backend == LINUX and mode not in allowed:
            raise ValueError('Linux supports naive=0, control=1, and measurement baseline=2 only')

    def check(self, guess, mode):
        self._require_open()
        self._require_mode(mode)
        return bool(self.dll.lab_check(guess, len(guess), mode))

    def measure(self, guess, mode, batch):
        self._require_open()
        self._require_mode(mode, measuring=True)
        if not isinstance(batch, int) or not 1 <= batch <= 1000000:
            raise ValueError('batch must be an integer within 1–1000000')
        result = self._measurement()
        status = self.dll.lab_measure(guess, len(guess), mode, batch, ct.byref(result))
        if status:
            raise RuntimeError(f'Native measurement failed ({status})')
        return result

    def close(self):
        if not self._closed:
            self._require_open()
            status = self.dll.lab_close()
            if status:
                raise RuntimeError('Could not restore original CPU affinity; retry close()')
            self._closed = True

