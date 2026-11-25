#!/data/data/com.termux/files/usr/bin/bash
export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"
export NETWATCH_HOST="${NETWATCH_HOST:-127.0.0.1}"
export NETWATCH_PORT="${NETWATCH_PORT:-5000}"

cd "$HOME/netwatch-e6"

# Finaliza instâncias anteriores se houver
pkill -f "python.*app\.py" || true
sleep 1

# Inicia em background fechando stdin (< /dev/null) para não prender sessões ADB
nohup python app.py < /dev/null > "$HOME/netwatch-e6/netwatch.log" 2>&1 &
PID=$!

echo "Iniciando NetWatch E6 em ${NETWATCH_HOST}:${NETWATCH_PORT} (PID $PID)... aguardando 3s..."
sleep 3

if ps aux | grep -v grep | grep "python app.py" > /dev/null; then
    echo "=== NetWatch E6 INICIADO COM SUCESSO ==="
    cat "$HOME/netwatch-e6/netwatch.log"
else
    echo "=== ERRO NA INICIALIZAÇÃO ==="
    cat "$HOME/netwatch-e6/netwatch.log"
    exit 1
fi
