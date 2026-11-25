#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# NetWatch E6 — Script de Inicialização Automatizada no Termux (Android 9 ARMv7)
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

export NETWATCH_HOST="${NETWATCH_HOST:-127.0.0.1}"
export NETWATCH_PORT="${NETWATCH_PORT:-5000}"

echo "=========================================================="
echo "  Iniciando NetWatch E6 no Motorola Moto E6 Play (bali)"
echo "=========================================================="

# 1. Ativar Wake Lock para impedir que o Android suspenda a CPU
if command -v termux-wake-lock &> /dev/null; then
    echo "[1/4] Ativando termux-wake-lock..."
    termux-wake-lock
else
    echo "[1/4] termux-wake-lock não disponível ou já ativo."
fi

# 2. Atualizar repositórios e instalar pacotes essenciais
echo "[2/4] Verificando dependências do sistema (Python, iproute2, openssh)..."
pkg update -y
pkg install -y python iproute2 openssh

# 3. Instalar pacotes Python do requirements.txt
echo "[3/4] Instalando pacotes Python..."
pip install --upgrade pip
pip install -r requirements.txt

# 4. Inicializar banco e iniciar o servidor Flask (Bind Seguro 127.0.0.1:5000)
echo "[4/4] Inicializando servidor NetWatch E6..."
echo "Servidor disponível em: http://${NETWATCH_HOST}:${NETWATCH_PORT}"
exec python app.py
