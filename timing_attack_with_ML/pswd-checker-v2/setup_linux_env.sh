#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Ubuntu's project server has venv support but omits ensurepip/python3-venv.
# --without-pip works there and never changes the system Python installation.
python3 -m venv --without-pip .venv
if ! .venv/bin/python -m pip --version >/dev/null 2>&1; then
    curl --fail --location --show-error --silent --max-time 60 \
        https://bootstrap.pypa.io/get-pip.py -o .venv/get-pip.py
    .venv/bin/python .venv/get-pip.py --disable-pip-version-check
fi
.venv/bin/python -m pip install --disable-pip-version-check 'matplotlib>=3.8,<4'
.venv/bin/python -m pip freeze > .venv/installed-packages.txt
echo 'Ready. Activate with: . .venv/bin/activate'
