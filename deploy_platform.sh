#!/data/data/com.termux/files/usr/bin/bash
set -e

export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"

echo "=== [1/4] Atualizando arquivos do projeto NetWatch E6 no Termux ==="
mkdir -p "$HOME/netwatch-e6/modules" "$HOME/netwatch-e6/templates" "$HOME/netwatch-e6/static" "$HOME/netwatch-e6/tests"

cp -f /sdcard/Download/netwatch-e6/app.py "$HOME/netwatch-e6/app.py"
cp -f /sdcard/Download/netwatch-e6/database.py "$HOME/netwatch-e6/database.py"
cp -f /sdcard/Download/netwatch-e6/apresentacao_banca_senac.html "$HOME/netwatch-e6/apresentacao_banca_senac.html" 2>/dev/null || true
cp -f /sdcard/Download/netwatch-e6/start_netwatch.sh "$HOME/netwatch-e6/start_netwatch.sh"
cp -f /sdcard/Download/netwatch-e6/start_netwatch.sh "$HOME/start_netwatch.sh"
cp -f /sdcard/Download/netwatch-e6/bootstrap_termux.sh "$HOME/netwatch-e6/bootstrap_termux.sh"
cp -f /sdcard/Download/netwatch-e6/modules/*.py "$HOME/netwatch-e6/modules/"
cp -f /sdcard/Download/netwatch-e6/templates/* "$HOME/netwatch-e6/templates/"
cp -f /sdcard/Download/netwatch-e6/static/* "$HOME/netwatch-e6/static/"
cp -f /sdcard/Download/netwatch-e6/tests/*.py "$HOME/netwatch-e6/tests/"

chmod 755 "$HOME/netwatch-e6/start_netwatch.sh" "$HOME/start_netwatch.sh" "$HOME/netwatch-e6/bootstrap_termux.sh"

echo "=== [2/4] Configurando Auto-Boot (~/.termux/boot/start-netwatch.sh) ==="
mkdir -p "$HOME/.termux/boot"
cat << 'EOF' > "$HOME/.termux/boot/start-netwatch.sh"
#!/data/data/com.termux/files/usr/bin/bash
export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TMPDIR="$PREFIX/tmp"
export NETWATCH_HOST="127.0.0.1"
export NETWATCH_PORT="5000"

# Ativa Wake Lock para manter o monitoramento ativo em background
if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock </dev/null >/dev/null 2>&1 &
fi

cd "$HOME/netwatch-e6"

# Loop resiliente para manter o servidor ativo sempre que o celular ligar
while true; do
    if ! pgrep -f "python.*app\.py" >/dev/null 2>&1; then
        python "$HOME/netwatch-e6/app.py" </dev/null >> "$HOME/netwatch-e6/netwatch.log" 2>&1
    fi
    sleep 10
done </dev/null >/dev/null 2>&1 &
EOF
chmod 755 "$HOME/.termux/boot/start-netwatch.sh"
ls -la "$HOME/.termux/boot/start-netwatch.sh"

echo "=== [3/4] Configurando Termux:Widget (~/.shortcuts/Abrir NetWatch E6) ==="
mkdir -p "$HOME/.shortcuts"
cat << 'EOF' > "$HOME/.shortcuts/Abrir NetWatch E6"
#!/data/data/com.termux/files/usr/bin/bash
export PREFIX="/data/data/com.termux/files/usr"
export HOME="/data/data/com.termux/files/home"
export PATH="$PREFIX/bin:$PREFIX/bin/applets:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib"

if ! pgrep -f "python.*app\.py" >/dev/null 2>&1; then
    "$HOME/netwatch-e6/start_netwatch.sh" </dev/null >/dev/null 2>&1 &
    sleep 2
fi

am start -a android.intent.action.VIEW -d http://127.0.0.1:5000
EOF
chmod 755 "$HOME/.shortcuts/Abrir NetWatch E6"
ls -la "$HOME/.shortcuts/"

echo "=== [4/4] Reiniciando servidor NetWatch E6 ==="
"$HOME/netwatch-e6/start_netwatch.sh"
