# NetWatch E6 — Monitor de Rede para Sistemas Embarcados / Android

Sistema de monitoramento e auditoria contínua de rede local e conectividade de borda projetado especificamente para operar em ambiente userspace não-root no **Motorola Moto E6 Play (`XT2029-3` / `bali`)**, equipado com SoC MediaTek MT6739WW e Android 9 Pie (API 28, ARMv7 32-bit).

---

## 1. Arquitetura e Especificações
* **Plataforma Alvo:** Motorola Moto E6 Play (32-bit `armeabi-v7a`, Android 9 Pie API 28).
* **Modo de Execução:** Userspace Não-Root dentro do Termux v0.118.3.
* **Banco de Dados:** SQLite em modo `WAL` (`Write-Ahead Logging`) e `synchronous=NORMAL` para evitar *locks* e minimizar desgaste de memória flash eMMC.
* **Consumo de Memória:** ~30–45 MB de RAM (adequado para os 2 GB totais do aparelho).
* **Workers de Descoberta:** Varredura paralela limitada a 32 threads com sondas TCP rápidas e fallback para ping nativo (`/system/bin/ping`).

---

## 2. Estrutura do Projeto
```text
D:\Projetos\netwatch-e6\
├── apk/
│   ├── download_termux.py       # Script de download automatizado do Termux ARMv7
│   └── termux-armv7.apk         # APK oficial debuggable do Termux
├── modules/
│   ├── network_discovery.py     # Detecção de interface wlan0, IP, máscara, CIDR e DNS
│   ├── device_discovery.py      # Varredura do bloco /24 com ThreadPoolExecutor
│   ├── connectivity_monitor.py  # Diagnóstico Gateway / WAN / DNS com causa raiz
│   ├── service_monitor.py       # Auditoria de serviços (SSH, DNS, HTTP, HTTPS, TCP)
│   └── report_generator.py      # Consolidação e exportação em Markdown e JSON
├── templates/
│   └── index.html               # Interface Web SPA mobile-first
├── static/
│   ├── style.css                # Estilização moderna Dark Mode
│   └── app.js                   # Lógica reativa assíncrona com polling
├── tests/
│   └── test_scenarios.py        # Suíte de testes unitários
├── app.py                       # Servidor Flask e daemon de monitoramento (60s)
├── database.py                  # Camada de persistência SQLite WAL
├── requirements.txt             # Dependências Python (flask, dnspython)
├── bootstrap_termux.sh          # Script de bootstrap dentro do Termux
└── README.md                    # Documentação do projeto
```

---

## 3. Classificação de Causa Raiz de Conectividade
O módulo `connectivity_monitor.py` avalia continuamente a integridade da saída para a rede e classifica o estado em:
1. **`OPERACIONAL`**: Gateway local, IP externo (1.1.1.1) e resolução DNS respondem normalmente.
2. **`FALHA_LOCAL_GATEWAY`**: O Gateway padrão está inacessível (falha física ou Wi-Fi desconectado).
3. **`FALHA_WAN_EXTERNA`**: O Gateway responde, mas a comunicação com a Internet externa falhou (link do provedor inoperante).
4. **`FALHA_RESOLUCAO_DNS`**: O link WAN e Gateway estão ativos, mas a resolução de nomes (DNS) falhou.

---

## 4. Como Executar e Acessar o Dashboard

### Inicialização no Dispositivo
Para iniciar o serviço em segundo plano no Termux do smartphone conectado via ADB:
```powershell
adb shell "run-as com.termux /data/data/com.termux/files/usr/bin/bash /data/data/com.termux/files/home/start_netwatch.sh"
```

### Redirecionamento de Portas ADB
Com o aparelho conectado via USB com depuração ativa:
```powershell
adb forward tcp:5000 tcp:5000
```

### Acesso ao Painel
* **No computador do operador:** **[http://127.0.0.1:5000](http://127.0.0.1:5000)**
* **Direto na rede local (LAN):** `http://<IP_DO_CELULAR>:5000` (ex: `http://192.168.1.7:5000`)

---

## 5. Endpoints REST da API
* `GET  /api/dashboard`: Métricas consolidadas, dados de rede, conectividade e contadores.
* `GET  /api/devices`: Lista de dispositivos descobertos no bloco `/24` com portas e latência.
* `POST /api/scan`: Dispara varredura paralela assíncrona (32 workers) na sub-rede local.
* `GET  /api/services`: Lista serviços monitorados com status e tempo de resposta.
* `POST /api/services`: Adiciona novo serviço monitorado (`name`, `host`, `port`, `service_type`).
* `POST /api/services/verify`: Força verificação imediata de todos os serviços cadastrados.
* `GET  /api/events`: Histórico cronológico de eventos e alertas da rede.
* `GET  /api/report/markdown`: Exporta relatório técnico completo formatado em Markdown (`.md`).
* `GET  /api/report/json`: Exporta dados consolidados em formato JSON para auditoria.
