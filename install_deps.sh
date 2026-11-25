#!/data/data/com.termux/files/usr/bin/bash
set -e

export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"

echo "=== INSTALANDO PACOTES PYTHON ==="
pip install --no-cache-dir -r "$HOME/netwatch-e6/requirements.txt"

echo "=== TESTANDO IMPORTAÇÕES PYTHON ==="
python -c "import flask, dns.resolver, sqlite3; print('Flask version:', flask.__version__); print('dnspython version:', dns.__version__); print('Tudo importado com sucesso!')"
