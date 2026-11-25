#!/data/data/com.termux/files/usr/bin/bash
set -e

export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"

echo "=== AMBIENTE TERMUX ==="
echo "PREFIX=$PREFIX"
echo "PATH=$PATH"
echo "UID=$(id)"

echo "=== VERIFICANDO DIRETORIO APT ==="
ls -la "$PREFIX/etc/apt" || true
if [ -f "$PREFIX/etc/apt/sources.list" ]; then
    cat "$PREFIX/etc/apt/sources.list"
fi

echo "=== TESTANDO PKG / APT ==="
apt-get update || true
apt-get install -y python iproute2 openssh curl || true

echo "=== STATUS PYTHON ==="
python --version || true
python3 --version || true
pip --version || true
