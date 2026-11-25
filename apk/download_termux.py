import urllib.request
import json
import os
import sys

API_URL = "https://api.github.com/repos/termux/termux-app/releases/latest"
DEST_PATH = r"D:\Projetos\netwatch-e6\apk\termux-armv7.apk"

def download_termux():
    print(f"Consultando releases oficiais do Termux em {API_URL}...")
    req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    
    tag = data.get("tag_name", "desconhecida")
    print(f"Versão mais recente identificada: {tag}")
    
    assets = data.get("assets", [])
    target_asset = None
    
    # Procurar primeiro o build github-debug_armeabi-v7a.apk
    for a in assets:
        name = a.get("name", "")
        if "github-debug" in name and "armeabi-v7a" in name and name.endswith(".apk"):
            target_asset = a
            break
            
    # Fallback: qualquer armeabi-v7a.apk
    if not target_asset:
        for a in assets:
            name = a.get("name", "")
            if "armeabi-v7a" in name and name.endswith(".apk"):
                target_asset = a
                break

    if not target_asset:
        print("[ERRO] Nenhum asset armeabi-v7a encontrado na release!")
        for a in assets:
            print(" -", a.get("name"))
        sys.exit(1)
        
    download_url = target_asset["browser_download_url"]
    file_name = target_asset["name"]
    expected_size = target_asset.get("size", 0)
    print(f"Asset selecionado: {file_name} ({expected_size / 1024 / 1024:.2f} MB)")
    print(f"Baixando de: {download_url}...")
    
    urllib.request.urlretrieve(download_url, DEST_PATH)
    
    actual_size = os.path.getsize(DEST_PATH)
    print(f"Download concluído: {DEST_PATH}")
    print(f"Tamanho em disco: {actual_size} bytes ({actual_size / 1024 / 1024:.2f} MB)")
    
    if actual_size < 20 * 1024 * 1024:
        print(f"[ERRO] Tamanho inválido ({actual_size} bytes < 20 MB).")
        sys.exit(1)
    else:
        print("[SUCESSO] Tamanho validado (> 20 MB).")

if __name__ == "__main__":
    download_termux()
