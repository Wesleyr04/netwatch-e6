import urllib.request
import json
import os

APK_DIR = r"D:\Projetos\netwatch-e6\apk"

REPOS = [
    ("termux-boot", "https://api.github.com/repos/termux/termux-boot/releases/latest", "termux-boot.apk"),
    ("termux-widget", "https://api.github.com/repos/termux/termux-widget/releases/latest", "termux-widget.apk"),
]

def download_latest_addon(name, api_url, out_filename):
    print(f"=== Consultando release oficial de {name} ===")
    req = urllib.request.Request(api_url, headers={"User-Agent": "NetWatch-E6-Updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    assets = data.get("assets", [])
    chosen = None
    # Prioriza build github-debug para compatibilidade de assinatura sharedUserId com o Termux github-debug instalado
    for a in assets:
        aname = a["name"].lower()
        if aname.endswith(".apk") and "github-debug" in aname:
            chosen = a
            break

    if not chosen:
        for a in assets:
            if a["name"].lower().endswith(".apk"):
                chosen = a
                break

    if not chosen:
        raise RuntimeError(f"Nenhum APK encontrado na release de {name}")

    dl_url = chosen["browser_download_url"]
    out_path = os.path.join(APK_DIR, out_filename)
    print(f"Baixando {chosen['name']} ({chosen['size']} bytes) -> {out_path}")

    dl_req = urllib.request.Request(dl_url, headers={"User-Agent": "NetWatch-E6-Updater"})
    with urllib.request.urlopen(dl_req, timeout=60) as dl_resp, open(out_path, "wb") as f:
        f.write(dl_resp.read())

    print(f"Concluído: {out_path} ({os.path.getsize(out_path)} bytes)")
    return out_path

if __name__ == "__main__":
    os.makedirs(APK_DIR, exist_ok=True)
    for name, url, fname in REPOS:
        download_latest_addon(name, url, fname)
