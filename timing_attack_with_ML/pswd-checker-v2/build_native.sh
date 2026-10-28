#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'Native build requires Linux x86-64; run this script on the project server.' >&2
    exit 1
fi
# Python records the actual compiler argv and hashes without shell interpolation.
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess

compiler = shlex.split(os.environ.get('CC', 'cc'))
flags = ['-std=c11', '-O2', '-fno-lto', '-fPIC', '-fvisibility=hidden',
         '-Wall', '-Wextra', '-Werror', '-shared', 'native_linux.c', '-o', 'native_linux.so']
command = compiler + flags
subprocess.run(command, check=True)
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
metadata = {'compiler': subprocess.check_output(compiler + ['--version'], text=True).splitlines()[0],
            'command': command, 'platform': platform.platform(), 'machine': platform.machine(),
            'source_sha256': digest('native_linux.c'), 'library_sha256': digest('native_linux.so')}
Path('native_linux.build.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
print('Built native_linux.so (work=0 only); recorded native_linux.build.json')
PY
