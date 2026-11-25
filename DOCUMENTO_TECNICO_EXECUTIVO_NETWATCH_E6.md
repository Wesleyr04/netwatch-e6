# NetWatch E6 — Especificação Técnica e Visão de Produto

*Monitoramento Autônomo de Redes Locais, Diagnóstico de Conectividade e Defesa Automatizada em Hardware de Baixo Custo Sem Acesso Root*

| Metadado | Especificação |
| :--- | :--- |
| **Versão do Documento** | 1.0 — Edição Executiva e Arquitetural |
| **Plataforma de Referência** | Motorola Moto E6 Play (Android 9 / ARMv7 32 bits) |
| **Classificação** | Documento Técnico e Proposta de Evolução de Produto |
| **Modo de Operação** | 100% Local, Autônomo e Sem Modificação de Sistema (Sem Root) |

---

## 1. Abstract (Resumo Executivo)

A visibilidade de redes locais em ambientes residenciais e em pequenas e médias empresas enfrenta historicamente uma barreira de custo e complexidade: soluções corporativas exigem hardware dedicado, licenciamento recorrente, acesso administrativo a roteadores ou infraestrutura em nuvem que compromete a privacidade dos usuários. O **NetWatch E6** soluciona essa lacuna ao converter um smartphone comercial de baixo custo — operando integralmente com o sistema original de fábrica, sem acesso root e sem dependência de servidores externos — em uma estação autônoma de monitoramento de rede, diagnóstico de conectividade e detecção de ameaças. A arquitetura embarcada combina coletores assíncronos em Python, banco de dados SQLite em modo de alta concorrência e servidor web isolado em interface local (`127.0.0.1`). Em operação real, o sistema mapeia uma rede IPv4 `/24` completa (254 endereços) em aproximadamente **3,6 segundos** (~0,8 segundo para ativos conhecidos), audita **16 portas TCP** por equipamento e executa **5 sensores contínuos de defesa** alinhados à matriz MITRE ATT&CK em regime 24/7. Além da prova de conceito validada em campo, o projeto estabelece a base técnica para evolução comercial rumo a uma plataforma de experiência simplificada, integrando filtragem DNS na porta 53, controle parental e atuação ativa em hardware dedicado ou ambiente privilegiado.

**Palavras-chave:** Monitoramento de Redes Locais; Detecção de Intrusão Sem Root; Diagnóstico de Conectividade; MITRE ATT&CK; Segurança Embarcada em Android.

---

## 2. Contextualização do Problema e Proposta de Valor

### 2.1. O Problema de Mercado
Redes Wi-Fi residenciais, escritórios enxutos, clínicas e comércios operam hoje com dezenas de dispositivos conectados — computadores, celulares, televisores inteligentes, câmeras e equipamentos de automação — sem qualquer instrumento de visibilidade ou defesa local. Quando ocorre degradação de conectividade ou lentidão, o usuário comum não consegue distinguir se a falha reside no roteador interno, no link da operadora ou no serviço de resolução de nomes (DNS). De forma ainda mais crítica, a entrada de equipamentos não autorizados, a exposição acidental de portas sensíveis ou ataques de interceptação local ocorrem de maneira invisível. As alternativas disponíveis no mercado exigem computadores permanentemente ligados, substituição de roteadores ou conhecimentos avançados de administração de redes.

### 2.2. A Proposta Técnica
O **NetWatch E6** demonstra que é tecnicamente viável entregar monitoramento contínuo, diagnóstico de causa raiz e vigilância defensiva utilizando um smartphone de entrada sem nenhuma alteração invasiva no sistema operacional. Ao respeitar integralmente as travas originais do fabricante (inicialização segura verificada e políticas estritas de isolamento de processos do Android 9), a solução elimina o risco de inutilização do aparelho e comprova que algoritmos de descoberta e correlação bem projetados no espaço de usuário suprem as demandas essenciais de visibilidade e auditoria de segurança.

### 2.3. Diferencial Estratégico e Viés de Negócio
Sob a ótica de produto e investimento, o NetWatch E6 apresenta quatro vantagens competitivas claras:
1. **Custo Marginal de Hardware:** viabiliza o reaproveitamento de smartphones comerciais amplamente disponíveis ou a adoção de hardware embarcado de baixíssimo custo.
2. **Implantação Imediata:** não requer configuração no roteador da residência ou da empresa; basta conectar o aparelho ao Wi-Fi para iniciar o mapeamento e a proteção.
3. **Privacidade por Padrão (Zero Nuvem):** todo o processamento, armazenamento de histórico e geração de relatórios ocorre dentro do próprio dispositivo, eliminando custos de infraestrutura em nuvem e riscos de vazamento de dados de clientes.
4. **Confiabilidade Operacional:** projetado para funcionar como equipamento dedicado 24/7, com recuperação automática em caso de reinicialização e consumo energético mínimo.

---

## 3. Arquitetura Técnica Atual (Versão Sem Root)

A arquitetura do NetWatch E6 foi estruturada em quatro camadas independentes e desacopladas, executadas sobre o ambiente Termux no Android 9:

```
+-----------------------------------------------------------------------+
| 4. INTERFACE WEB EM TELA CHEIA (5 MÓDULOS OPERACIONAIS)               |
|    Visão Geral | Dispositivos | Serviços | Defesa (SOC) | Relatórios  |
+-----------------------------------------------------------------------+
                                    ^
                                    | HTTP/JSON (Exclusivo 127.0.0.1:5000)
                                    v
+-----------------------------------------------------------------------+
| 3. SERVIDOR WEB ISOLADO (FLASK)                                       |
|    API REST local invisível para os demais equipamentos do Wi-Fi      |
+-----------------------------------------------------------------------+
                                    ^
                                    | Leitura e Escrita Concorrente
                                    v
+-----------------------------------------------------------------------+
| 2. PERSISTÊNCIA LOCAL (SQLITE EM MODO WAL)                            |
|    Isolamento por sub-rede | Histórico de latência | Deduplicação     |
+-----------------------------------------------------------------------+
                                    ^
                                    | Atualização Contínua Assíncrona
                                    v
+-----------------------------------------------------------------------+
| 1. COLETORES EM PYTHON (DOIS CICLOS INDEPENDENTES)                    |
|    Ciclo Rápido Local (15s)  |  Ciclo Externo e Integridade (30s)     |
+-----------------------------------------------------------------------+
```

### 3.1. Camada 1 — Coletores em Python (Dois Ciclos Independentes)
Para evitar que testes externos lentos atrasem a detecção de dispositivos que entram ou saem do Wi-Fi, o motor de coleta opera em duas linhas de execução paralelas:

- **Ciclo Rápido de Rede Local (a cada 15 segundos):**
  - *Fase Prioritária (~0,8s):* revalida imediatamente os dispositivos que já estavam conectados no ciclo anterior, atualizando latência e estado com resposta quase instantânea.
  - *Varredura Completa da Sub-rede `/24` (~3,6s):* sonda os 254 endereços possíveis utilizando paralelismo controlado. Como smartphones modernos e computadores frequentemente bloqueiam respostas de ping tradicional (ICMP), o coletor combina quatro provas de presença: tentativa de conexão TCP rápida (considerando ativo tanto o aceite da porta quanto a recusa imediata da pilha de rede do equipamento), envio de pacotes leves UDP, leitura da tabela interna de vizinhos do sistema operacional e fallback de ping.
- **Ciclo de Conectividade Externa e Integridade (a cada 30 segundos):**
  - Avalia sequencialmente a saúde do roteador local, a saída para a internet externa e o funcionamento dos servidores DNS, isolando com precisão a etapa exata em caso de queda.
  - Executa testes funcionais reais nos protocolos DNS, SSH, HTTP e HTTPS/TLS, além de acionar os verificadores de integridade de DNS e validade de certificados digitais.
- **Identificação Precisa de Equipamentos:**
  - Para cada dispositivo ativo, o sistema audita **16 portas TCP** voltadas a serviços comuns, coleta assinaturas leves de aplicação (como cabeçalhos HTTP e identificação SSH) e consulta uma base local offline de fabricantes de placas de rede (prefixos MAC). Quando um equipamento utiliza endereço MAC aleatório ou apresenta divergência, o sistema prioriza a assinatura real capturada na camada de aplicação (Camada 7), garantindo identificação fidedigna de roteadores e servidores.

### 3.2. Camada 2 — Persistência Local (SQLite em Modo WAL)
O armazenamento utiliza banco de dados relacional SQLite configurado com registro prévio em log (*Write-Ahead Logging* — WAL), permitindo que os coletores gravem novas medições simultaneamente às consultas da interface web sem bloqueios. O banco isola os dispositivos por sub-rede Wi-Fi, preserva as últimas **100 medições de latência por endereço IP** (com limpeza automática para controle de armazenamento), contabiliza tempo de sessão acumulado, registra quedas e mantém deduplicação automática de alertas de segurança.

### 3.3. Camada 3 — Servidor Web Isolado (Flask)
A camada de controle e API REST é servida pelo framework Flask, configurada estritamente no endereço de retorno interno (`127.0.0.1:5000`). Essa decisão arquitetural garante que o servidor não abra portas para a rede Wi-Fi monitorada: nenhum outro computador ou celular conectado ao mesmo roteador consegue acessar ou enxergar o painel do NetWatch E6.

### 3.4. Camada 4 — Interface Web em Tela Cheia (5 Módulos)
Projetada como aplicação web instalável na tela inicial do Android e otimizada para leitura direta no visor do aparelho, a interface divide a operação em cinco módulos:
1. **Visão Geral:** painel executivo com o estado operacional da rede, latência por etapa (Roteador, Internet e DNS), informações da interface Wi-Fi e contadores de ativos.
2. **Dispositivos:** inventário em tempo real com destaque visual para entradas e saídas recentes, medição de tráfego recebido e enviado (RX/TX) pelo próprio aparelho, identificação de fabricante e ficha individual detalhada por equipamento.
3. **Serviços:** verificação funcional contínua de DNS, SSH, HTTP e HTTPS com tempos de resposta e diagnóstico de disponibilidade.
4. **Defesa (SOC):** indicador de postura de risco da rede (Seguro, Atenção ou Crítico), painel dos cinco sensores de segurança, botão de trava de rede confiável e lista de alertas ativos com confirmação de leitura.
5. **Relatórios:** linha do tempo auditável de eventos e exportação imediata de relatórios completos ou individuais nos formatos Markdown e JSON.

---

## 4. Engenharia de Escopo, Desempenho e Comportamento em IPv4/IPv6

### 4.1. Proteção em Redes Grandes (Teto Automático `/24`)
Ao conectar um dispositivo móvel a redes corporativas, universitárias ou espaços públicos, é comum encontrar máscaras de sub-rede amplas — como `/22` (1.022 endereços), `/20` (4.094 endereços) ou `/16` (65.534 endereços IP). Executar uma varredura ativa sequencial sobre dezenas de milhares de endereços em um processador móvel de entrada causaria exaustão de memória, aquecimento, drenagem severa de bateria e ciclos de atualização lentos.

Para garantir estabilidade absoluta em qualquer cenário, o NetWatch E6 implementa um **teto automático de escopo `/24`**: sempre que detecta uma rede com máscara superior a 254 endereços, o motor recorta matematicamente a varredura ativa apenas para o segmento local `/24` onde o próprio endereço IP do smartphone está alocado. Dessa forma, o tempo de varredura permanece previsível em **~3,6 segundos**, mantendo consumo constante de memória e processador.

| Parâmetro de Rede | Rede Corporativa (`/16`) Sem Proteção | Rede Corporativa (`/16`) Com Teto NetWatch E6 |
| :--- | :--- | :--- |
| **Endereços Possíveis na Faixa** | 65.534 endereços IP | Recorte automático para 254 endereços locais (`/24`) |
| **Tempo Estimado de Ciclo** | Superior a 15 minutos (inviável em tempo real) | **~3,6 segundos** (constante e previsível) |
| **Impacto em Memória e Bateria** | Crítico (risco de encerramento pelo Android) | Baixo e estável para operação contínua 24/7 |

### 4.2. Comportamento em Redes IPv6
A arquitetura adota transparência total quanto às diferenças matemáticas entre IPv4 e IPv6:
- A varredura ativa por sondagem de faixa opera exclusivamente sobre **IPv4**, onde uma sub-rede local padrão (`/24`) comporta 254 endereços verificáveis em poucos segundos.
- Em **IPv6**, uma sub-rede local padrão (`/64`) contém aproximadamente **18 quintilhões de endereços** ($1,84 \times 10^{19}$), o que torna matematicamente impossível a varredura sequencial endereço por endereço por qualquer equipamento do mercado.
- Como a quase totalidade das redes residenciais e corporativas atuais opera em **pilha dupla (IPv4 e IPv6 simultâneos)**, o NetWatch E6 monitora e identifica normalmente todos os equipamentos através da camada IPv4. Em cenários raros de redes exclusivamente IPv6, o sistema desativa a varredura de faixa e passa a registrar apenas os equipamentos identificados passivamente na tabela interna de vizinhos do sistema operacional (protocolo NDP).

---

## 5. Motor de Defesa Automática (Mapeamento MITRE ATT&CK)

O módulo de defesa executa cinco sensores automáticos a cada ciclo de coleta, correlacionando anomalias locais diretamente com técnicas documentadas na matriz **MITRE ATT&CK**, sem exigir configuração manual ou intervenção técnica do usuário:

| Sensor de Defesa | Código MITRE ATT&CK |Severidade Padrão | Mecanismo de Detecção e Valor Defensivo |
| :--- | :--- | :--- | :--- |
| **1. Proteção ARP (Integridade do Roteador)** | `T1557.002` *(ARP Cache Poisoning)* | **CRÍTICO** | Memoriza o endereço físico (MAC) original do roteador ao conectar na rede e alerta imediatamente caso outro equipamento tente assumir o endereço do roteador ou haja duplicidade na tabela ARP. |
| **2. Integridade de DNS** | `T1557` *(Adversary-in-the-Middle)* | **CRÍTICO** | Compara a resolução DNS entregue pelo roteador local com consultas criptografadas via DNS sobre HTTPS (DoH). Caso os endereços divirjam, valida o certificado TLS real na porta 443 do destino, eliminando falsos alarmes comuns em grandes sites que utilizam múltiplos servidores (CDNs). |
| **3. Portas Críticas e Alterações de Superfície** | `T1021` / `T1046` *(Remote Services / Network Service Discovery)* | **ALTO / MÉDIO** | Identifica a exposição de portas de alto risco na rede interna (FTP 21, Telnet 23, SMB 445, RDP 3389 e ADB 5555) e alerta sempre que um equipamento conhecido abre uma nova porta que não existia nas varreduras anteriores. |
| **4. Trava de Rede Confiável** | `T1200` *(Hardware Additions)* | **ALTO** | Permite autorizar com um toque todos os equipamentos legítimos presentes na rede. A partir do travamento, qualquer novo dispositivo desconhecido que se conecte ao Wi-Fi gera alerta imediato de intrusão física ou lógica. |
| **5. Auditoria de Certificados TLS** | `T1557` *(Adversary-in-the-Middle)* | **ALTO / MÉDIO** | Inspeciona serviços HTTPS ativos na rede local e em destinos monitorados, verificando a data real de expiração do certificado digital para alertar certificados vencidos ou com menos de 15 dias de validade. |

> **Nota Operacional sobre a Trava de Rede Confiável:** O recurso de travamento de lista confiável (`T1200`) foi projetado para ambientes sob gestão do usuário (residências, escritórios, consultórios e pequenas empresas). Em redes públicas abertas (como aeroportos ou cafeterias), onde dezenas de desconhecidos entram e saem a todo instante, recomenda-se manter a trava desativada para evitar geração excessiva de alertas irrelevantes.

---

## 6. Segurança Operacional, Confiabilidade e Limites Atuais

### 6.1. Isolamento e Continuidade Operacional 24/7
Para operar como um instrumento confiável de segurança, o próprio dispositivo monitor não pode se tornar um vetor de vulnerabilidade na rede:
- **Isolamento em Interface Interna:** a aplicação escuta apenas em `127.0.0.1:5000`. Quando há necessidade de espelhar o painel em uma tela maior durante auditorias, o acesso ocorre exclusivamente por túnel via cabo USB (ADB), sem expor portas na interface Wi-Fi.
- **Trava Automática Fora do Wi-Fi:** o coletor verifica continuamente se a interface ativa pertence ao padrão sem fio local (`wlan`). Caso o sinal Wi-Fi caia ou o aparelho comute para dados móveis da operadora celular, todas as varreduras são suspensas instantaneamente.
- **Persistência em Segundo Plano e Inicialização Automática:** através de scripts de inicialização automática no boot do Android, bloqueio de suspensão de processador (*Wake Lock*) e isenção de otimização agressiva de bateria (*Doze Mode*), o serviço inicia sozinho ao ligar o smartphone e mantém os ciclos de 15s e 30s ativos mesmo com a tela bloqueada.
- **Garantia de Qualidade:** toda a lógica de banco de dados, descoberta, sensores MITRE ATT&CK e geração de relatórios é validada por uma suíte automatizada de **10 testes unitários**, garantindo integridade a cada atualização.

### 6.2. Transparência sobre Limites Arquiteturais do Modo Sem Root
O rigor técnico do projeto exige documentar com exatidão o que o espaço de usuário padrão do Android permite e o que é restrito pelo núcleo do sistema operacional quando não há acesso root:
1. **Medição de Consumo de Dados (RX/TX):** o sistema contabiliza com precisão o volume real de bytes recebidos e transmitidos pelo próprio smartphone através dos contadores da interface de rede. Entretanto, devido ao isolamento natural das redes comutadas (Camada 2), o tráfego trocado entre outros equipamentos (como uma Smart TV assistindo a um vídeo diretamente do roteador) não transita pela placa de rede do celular e, portanto, não é contabilizado para terceiros.
2. **Ausência de Captura Promíscua de Pacotes:** sem privilégios de superusuário, o sistema não coloca a placa Wi-Fi em modo promíscuo e não intercepta o conteúdo das comunicações de outros moradores ou colaboradores, preservando a privacidade e a conformidade legal.
3. **Atuação Estritamente Passiva e Defensiva:** na versão sem root, o sistema detecta e alerta ameaças em tempo real, mas não executa bloqueio ativo de tráfego nem desconexão forçada de equipamentos invasores.

---

## 7. Proposta Futura e Potencial de Desenvolvimento (Roadmap de Produto e Investimento)

A versão atual do NetWatch E6 valida com sucesso o motor de descoberta, diagnóstico e inteligência defensiva em condições severas de restrição de hardware e sistema. Para escalar essa tecnologia rumo a um **produto comercial de alto valor agregado** voltado aos mercados residencial (*Smart Home*) e de pequenas e médias empresas (PMEs), o plano de evolução estrutura-se em três pilares estratégicos:

### 7.1. Pilar 1 — Evolução para Ambiente Privilegiado (Acesso Root ou Hardware Dedicado)
A transição do ambiente restrito de usuário para uma camada com privilégios de sistema — seja mediante dispositivos Android homologados e desbloqueados, seja pela embarcação do motor NetWatch em mini-computadores dedicados de baixo custo (arquitetura ARM com Linux embarcado) — remove todas as barreiras físicas atuais:
- **Defesa Ativa e Resposta Automática a Incidentes:** capacidade de isolar ou bloquear instantaneamente um dispositivo invasor assim que o sensor `T1200` ou `T1557.002` detectar uma anomalia, protegendo a rede antes que o administrador precise intervir.
- **Visibilidade Completa de Tráfego por Equipamento:** atuação opcional como gateway ou coletor avançado de fluxo, permitindo medir o consumo exato de banda de cada computador, celular ou equipamento IoT da rede.
- **Inspeção Aprofundada de Pacotes:** detecção de varreduras maliciosas internas e comunicações com servidores de comando e controle em tempo real.

### 7.2. Pilar 2 — Módulo Integrado de Filtragem DNS e Controle Parental
Com privilégios para operar diretamente na porta padrão `53`, o produto incorpora um **servidor DNS local inteligente de alta velocidade**:
- **Escudo Contra Ameaças e Rastreamento:** bloqueio automático, para todos os aparelhos da casa ou escritório, de domínios associados a *phishing*, códigos maliciosos (*malware*), telemetria invasiva e publicidade abusiva.
- **Controle Parental e Gestão de Produtividade:** criação de perfis por usuário ou por dispositivo (ex.: celulares das crianças, televisores da sala ou computadores do escritório), permitindo bloquear categorias de conteúdo impróprio, limitar redes sociais ou pausar o acesso à internet em horários programados com um único toque.
- **Transformação de Proposta de Valor:** essa evolução converte o produto de uma ferramenta de diagnóstico técnico para um **guardião diário de segurança, privacidade digital e bem-estar familiar**, gerando percepção contínua de valor pelo consumidor final.

### 7.3. Pilar 3 — Plataforma Amigável e Experiência de Produto para o Público Geral
Para atingir escala comercial além do público especialista em tecnologia, a interface evoluirá para uma plataforma focada em simplicidade e tomada de decisão assistida:
- **Linguagem Natural e Ações de Um Toque:** substituição de termos técnicos por recomendações diretas e acionáveis (ex.: *"Um celular desconhecido conectou ao seu Wi-Fi — Deseja bloquear o acesso?"*, *"Pausar internet dos quartos até as 07h"* ou *"Seu roteador está seguro"*).
- **Notificações Instantâneas e Gestão Híbrida Opcional:** envio de alertas em tempo real para o celular principal do proprietário ou gestor de TI, mantendo o processamento local como diferencial de privacidade, mas oferecendo um canal criptografado opcional para administração remota.
- **Modelos de Comercialização Escaláveis:**
  1. *Appliance Plug-and-Play:* dispositivo físico pré-configurado pronto para conectar à tomada e ao Wi-Fi.
  2. *Licenciamento de Software e Assinatura (SaaS Local):* aplicativo avançado com atualização contínua de listas de inteligência de ameaças, regras de filtragem DNS e relatórios executivos automatizados.

---

## 8. Conclusão

O **NetWatch E6** comprova, com métricas reais aferidas em hardware de entrada, que a segurança e a visibilidade de redes locais não precisam ser privilégio de grandes corporações. Ao entregar descoberta completa de sub-rede em **~3,6 segundos**, diagnóstico preciso da cadeia de conectividade e **5 sensores contínuos mapeados ao MITRE ATT&CK** sem exigir acesso root nem infraestrutura em nuvem, o projeto estabelece uma fundação tecnológica enxuta, auditável e funcional.

Combinando a maturidade do motor atual com o roteiro de evolução para ambiente privilegiado, filtragem DNS integrada com controle parental e uma experiência de usuário simplificada para o grande público, o NetWatch E6 posiciona-se como uma oportunidade sólida de produto com baixo custo de produção, alta barreira técnica de eficiência e forte apelo comercial nos segmentos residencial e de pequenos negócios.
