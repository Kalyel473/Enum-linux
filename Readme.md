📡 LinEnumX

Enumeração avançada de hosts Linux em Python  o "enum4linux" do Linux.

O LinEnumX é uma ferramenta de reconhecimento/Enumeração que espelha o espírito do clássico enum4linux (voltado para Windows/SMB) e o aplica ao lado Linux de um alvo: descobre serviços, banners e versões, tenta enumeração de usuários (SSH/SMTP/LDAP/RPC), monta NFS, lê shares SMB, varre SNMP, explora bancos/serviços sem autenticação, detecta CVEs por banner e ancora tudo com detecção de tecnologia web, varredura UDP e relatórios em múltiplos formatos.

    ⚠️ Uso autorizado apenas contra sistemas que você possui ou para os quais possui autorização formal por escrito (testes de penetração, auditorias e CTFs autorizados).

✨ Funcionalidades
Varredura e Fingerprint

    ✅ Varredura TCP paralela e rápida (ThreadPoolExecutor, ~70 portas Linux mapeadas)
    ✅ Gravação de banner com detecção transparente de TLS (sniff do 1º byte do handshake)
    ✅ Fingerprint de serviço (OpenSSH, vsftpd, ProFTPD, nginx, Apache...)
    ✅ Varredura UDP (DNS, SNMP, NTP, NetBIOS, SSDP, mDNS) com probes
    ✅ Estimativa de OS por TTL (ping: Linux ~64 vs Windows ~128) + fingerprint por banner
    ✅ Zone transfer DNS (AXFR) — alto risco se liberado
    ✅ NTP monlist — detecta amplificador de DDoS
    ✅ Detecção de CVEs conhecidas por versão de banner

Enumeração de usuários

    🔑 SSH — enumeração por timing de autenticação (baseline + usuário fantasma)
    📧 SMTP — VRFY/EXPN
    👤 LDAP — bind anônimo + coleta de usuários da base
    🔁 RID cycling SMB — enumera a SAM remotamente (espelho do enum4linux -r)
    🧩 NetBIOS (nmblookup) e shares SMB (smbclient)

Serviços / Bancos de dados

    🗄️ Sem autenticação: Redis (testa escrita → RCE), MongoDB, Memcached, MySQL, PostgreSQL, Elasticsearch
    🐳 Docker API exposta (sem TLS → RCE crítico)
    📁 NFS (showmount -e), rsync, RPC (rpcinfo)
    🌐 HTTP profundo: brute de diretórios, headers, método TRACE (XST), detecção de CMS/tech stack
    🔐 Telnet

Credenciais e Pós-exploração

    🧪 Checagem de credenciais SSH/FTP (sshpass, com rate-limit)
    🕵️ Pós-exploração SSH automática quando a cred valida (id, sudo -l, SUID, crons, /etc/passwd)

Relatórios

    📊 Risk score 0–10 agregado por severidade
    📄 Saída colorida no terminal + exportação em TXT, JSON, HTML, Markdown e YAML

🧰 Requisitos
Python 3.7+

Dependências Python (opcionais, exceto colorama para cores):
bash

pip install colorama pyyaml ldap3

Ferramentas externas (padrão no Kali)
bash

apt install sshpass smbclient nmblookup rpcbind nfs-common \
            snmp ntpq dnsutils ldap-utils rpcclient -y

    rpcclient costuma vir no pacote samba-common-bin/smbclient do Kali.

🚀 Como usar
bash

# Salve o script
chmod +x linenumx.py

# Enumeração padrão
sudo python3 linenumx.py -t 10.10.10.10

# Total: todas as portas TCP + UDP + HTTP profundo + todos os módulos
sudo python3 linenumx.py -t 10.10.10.10 -p 1-65535 --udp --http-deep

# Foco em domínio (zone transfer + RID cycling)
sudo python3 linenumx.py -t 10.10.10.10 --domain corp.local --rid-cycle --udp

# Com checagem de credenciais + relatórios completos
sudo python3 linenumx.py -t 10.10.10.10 --creds-file creds.txt \
     -f text,json,html,md,yaml -o ./reports

# Somente usuários via SSH com wordlist própria
python3 linenumx.py -t 10.10.10.10 --service ssh --user-file usuarios.txt

🎛️ Opções de linha de comando
Argumento	Descrição
-t, --target	(obrigatório) IP ou hostname do alvo
-p, --ports	Portas TCP (ex.: 1-65535 ou 22,80,443). Padrão: lista de ~70 portas Linux
--timeout	Timeout de conexão em segundos (padrão 4.0)
--threads	Threads de varredura (padrão 256)
--no-scan	Não varre portas; assume serviços abertos (modo serviços)
--service	Executar apenas protocolos: ssh, smb, nfs, smtp, snmp, rpc, http (repetível)
--users	Lista de usuários (vírgula) para enumeração
--user-file	Arquivo com usuários (um por linha)
--udp	Varredura UDP das portas-chave
--http-deep	Enumeração HTTP profunda (diretórios, headers, tech, TRACE)
--domain	Domínio para zone transfer DNS e RID cycling
--rid-cycle	RID cycling SMB (enumeração de usuários da SAM)
--max-rid	RID máximo para o cycling (padrão 2000)
--creds-file	Arquivo user:pass (uma por linha) para checagem
--user / --password	Credenciais para operações (RID, cred checks)
--no-ping	Pula a detecção de OS por TTL
-o, --outdir	Diretório de saída dos relatórios (padrão .)
-f, --format	text, json, html, md, yaml (combina com vírgula)
🧭 Fluxo de execução

    Varredura TCP paralela com banner + TLS + fingerprint de serviço
    Fingerprint de OS (TTL do ping + análise de banners)
    Checagem de CVEs conhecidas por versão de banner
    Varredura UDP (DNS/SNMP/NTP/SSDP/mDNS)
    DNS zone transfer + NTP monlist
    Enumeração de protocolos: SMB/NetBIOS, NFS, RPC, SSH (timing), SMTP (VRFY), SNMP
    HTTP profundo (diretórios, headers, métodos, tech stack)
    Probing de bancos/serviços sem auth (Redis, Mongo, Memcached, MySQL, PG, ES, Docker, LDAP, rsync, Telnet)
    RID cycling SMB (opcional)
    Checagem de credenciais + pós-exploração SSH
    Relatório (console + arquivos nos formatos escolhidos)

🗂️ Estrutura do código
Módulo	Responsabilidade
Scanner	Varredura TCP paralela com banner/TLS
OpenPort / User / Finding / Target	Dataclasses com o modelo de dados
http_deep / detect_web_tech	Enumeração e fingerprint HTTP
enum_* (redis, mysql, mongo...)	Probes de serviços/bancos sem auth
smb_enum / rid_cycle / nfs_enum / rpc_enum	Camada de compartilhamento de arquivos
ssh_user_enum / smtp_vrfy / enum_ldap / snmp_walk	Enumeração de usuários
cve_check	Mini-base de CVEs por versão
Reporter	Saída colorida + TXT/JSON/HTML/MD/YAML + risk score
🔧 Personalização

Edite as listas no topo do script (ou carregue de arquivos externos):

    DIR_WORDLIST — wordlist de diretórios do HTTP profundo
    COMMON_USERS — usuários padrão da enumeração
    SNMP_COMMUNITIES — communities a testar
    CVE_DB (em cve_check) — adicione suas próprias regras CVE

⚠️ Avisos e Boas Práticas

    O RID cycling usa rpcclient e assume a sintaxe do samba-common-bin; o regex de parse pode exigir calibração em ambientes com domínio real.
    Enumeração de usuários SSH por timing e SMTP VRFY são técnicas ativas (mas leves); ajuste os atrasos (delay) para reduzir ruído/logs.
    Varredura de porta completa é barulhenta — respeite o escopo do seu teste e aplique rate-limit em redes sensíveis.
    O probing de Docker API (2375) só tenta conexão; verifique manualmente o impacto antes de prosseguir.

🛠️ Roadmap (ideias de evolução)

    Modo stealth (scan SYN via scapy, jitter, menos ruído)
    Brute de senhas direcionado por serviço (SSH/FTP/RDP)
    Front-end web para leitura dos relatórios
    Wordlists externas configuráveis (YAML de configuração)
    Módulos adicionais (Kerberos, WebSocket, APIs REST)
    Parsing refinado do rpcclient lookupsids por distribuição

📄 Licença

Ferramenta de segurança ofensiva destinada a profissionais autorizados (pentest, auditoria, defesa). Use com responsabilidade. O autor não se responsabiliza pelo uso indevido.
