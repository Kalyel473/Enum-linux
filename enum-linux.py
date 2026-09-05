
import argparse, json, os, re, socket, ssl, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _C:
        def __getattr__(self, n): return ""
    Fore = Style = _C()

VERSION = "2.0.0"
BANNER = f"""{Fore.CYAN}
  _     _       _                   __  __
 | |   (_)_ __ | | _____  ___ _ __  \\ \\/ /
 | |   | | '_ \\| |/ / _ \\/ _ \\ '_ \\  \\  /
 | |___| | | | |   <  __/  __/ | | | /  \\
 |_____|_|_| |_|_|\\_\\___|\\___|_| |_|/_/\\_\\
{Style.RESET_ALL}
 Linux Host Advanced Enumerator  v{VERSION}
"""

# ===========================================================================
# Estruturas de dados
# ===========================================================================
@dataclass
class OpenPort:
    port: int
    proto: str = "tcp"
    service: str = ""
    banner: str = ""
    ssl: bool = False
    notes: List[str] = field(default_factory=list)

@dataclass
class User:
    name: str
    source: str = ""
    uid: Optional[str] = None
    extra: str = ""

@dataclass
class Finding:
    title: str
    detail: str
    severity: str = "info"        # info|low|medium|high|critical
    cve: str = ""

@dataclass
class Target:
    ip: str
    hostname: str = ""
    os_hint: str = ""
    ports: List[OpenPort] = field(default_factory=list)
    users: List[User] = field(default_factory=list)
    shares: List[dict] = field(default_factory=list)
    mounts: List[dict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    up: bool = False
    # --- v2.0 ---
    http_results: List[dict] = field(default_factory=list)
    web_tech: List[str] = field(default_factory=list)
    vhosts: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    db_info: List[dict] = field(default_factory=list)
    svc_banners: List[dict] = field(default_factory=list)
    dns_zone: str = ""
    udp_open: List[OpenPort] = field(default_factory=list)
    cred_checks: List[dict] = field(default_factory=list)
    postex: List[str] = field(default_factory=list)

# ===========================================================================
# Utilidades de rede
# ===========================================================================
def tcp_connect(ip: str, port: int, timeout: float) -> Optional[socket.socket]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port)); return s
    except Exception:
        try: s.close()
        except Exception: pass
        return None

def grab_banner(ip: str, port: int, timeout: float = 5.0, tls: bool = False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b"\x00")
        first = s.recv(1)
        using_tls = (first == b"\x16")
        if using_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(b"\r\n")
        data = b""
        try:
            while len(data) < 4096:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
        except socket.timeout:
            pass
        return data.decode("utf-8", errors="replace").strip()[:1500], using_tls
    except ssl.SSLError:
        return "", True
    except Exception:
        return "", False
    finally:
        try: s.close()
        except Exception: pass

def _sock(ip, port, timeout):
    return tcp_connect(ip, port, timeout)

SERVICE_MAP = {
    21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",67:"dhcp",68:"dhcp",
    69:"tftp",80:"http",88:"kerberos",110:"pop3",111:"rpcbind",123:"ntp",
    135:"rpc",137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",143:"imap",
    161:"snmp",162:"snmptrap",389:"ldap",443:"https",445:"microsoft-ds",
    464:"kpasswd",465:"smtps",512:"exec",513:"login",514:"shell",587:"submission",
    636:"ldaps",873:"rsync",993:"imaps",995:"pop3s",1080:"socks",
    1099:"rmiregistry",1433:"mssql",1521:"oracle",2049:"nfs",2181:"zookeeper",
    2375:"docker",2376:"docker-tls",3000:"grafana",3128:"squid",3306:"mysql",
    3389:"rdp",4369:"epmd",5000:"upnp",5432:"postgresql",5672:"amqp",
    5900:"vnc",5984:"couchdb",6379:"redis",7001:"weblogic",8000:"http-alt",
    8009:"ajp",8080:"http-proxy",8081:"http-alt",8443:"https-alt",
    8888:"http-alt",9000:"php-fpm",9090:"cockpit",9200:"elasticsearch",
    9300:"elasticsearch",10000:"webmin",11211:"memcached",27017:"mongod",
    50000:"sap",50070:"namenode",50075:"datanode",
}

@dataclass
class Scanner:
    ip: str
    ports: List[int]
    timeout: float
    threads: int
    results: List[OpenPort] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def scan_port(self, port: int) -> Optional[OpenPort]:
        if not tcp_connect(self.ip, port, self.timeout):
            return None
        service = SERVICE_MAP.get(port, "unknown")
        banner, is_tls = grab_banner(self.ip, port, self.timeout)
        if not banner and service in ("http","http-proxy","http-alt","https-alt",
                                      "grafana","webmin","php-fpm","cockpit","squid"):
            banner = http_probe(self.ip, port)
        op = OpenPort(port=port, service=service, banner=banner, ssl=is_tls)
        fingerprint_service(op)
        return op

    def run(self) -> List[OpenPort]:
        done = 0
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.scan_port, p): p for p in self.ports}
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    with self._lock:
                        self.results.append(r)
                done += 1
                sys.stdout.write(f"\r  [*] portas testadas: {done}/{len(self.ports)}"
                                 f"  abertas: {len(self.results)}   ")
                sys.stdout.flush()
        print()
        return sorted(self.results, key=lambda x: x.port)

def fingerprint_service(op: OpenPort):
    b = op.banner.lower()
    if op.service == "ssh":
        m = re.search(r"ssh-[\d.]+-(\S+)", b)
        if m: op.notes.append(f"implementação: {m.group(1)}")
        if "dropbear" in b: op.notes.append("Dropbear SSH")
        if "openssh" in b: op.notes.append("OpenSSH")
    elif op.service == "ftp":
        if "vsftpd" in b: op.notes.append("vsftpd")
        elif "proftpd" in b: op.notes.append("ProFTPD")
        elif "pure-ftpd" in b: op.notes.append("Pure-FTPd")
    elif op.service.startswith("http") or op.service == "grafana":
        if "openssh" in b or "nginx" in b: op.notes.append("Nginx")
        elif "apache" in b: op.notes.append("Apache")

# ===========================================================================
# Probes de protocolo
# ===========================================================================
def http_probe(ip: str, port: int, tls: bool = False) -> str:
    scheme = "https" if (tls or port in (443, 8443)) else "http"
    try:
        import urllib.request
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        req = urllib.request.Request(f"{scheme}://{ip}:{port}/", headers={
            "User-Agent": "Mozilla/5.0 LinEnumX", "Connection": "close"})
        with urllib.request.urlopen(req, timeout=5,
                                    context=ctx if scheme == "https" else None) as r:
            server = r.headers.get("Server", "")
            body = r.read(4000).decode("utf-8", "replace")
            t = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
            title = t.group(1).strip()[:80] if t else ""
            return f"HTTP/{r.status} Server={server} Title={title}".strip()
    except Exception as e:
        return f"(probe http falhou: {type(e).__name__})"

# --- Rede / infraestrutura ---------------------------------------------------
def os_ttl_guess(ip: str, timeout: float) -> str:
    try:
        out = subprocess.run(["ping", "-c", "1", "-W", str(int(timeout)), ip],
                             capture_output=True, text=True, timeout=timeout + 2)
        m = re.search(r"ttl=(\d+)", out.stdout, re.I)
        if m:
            ttl = int(m.group(1))
            return "Linux/Unix (TTL~64)" if ttl <= 64 else \
                   "Windows (TTL~128)" if ttl <= 128 else f"TTL={ttl}"
    except Exception:
        pass
    return ""

# --- UDP --------------------------------------------------------------------
UDP_PORTS = {53:"dns",69:"tftp",123:"ntp",137:"netbios-ns",138:"netbios-dgm",
             161:"snmp",162:"snmptrap",500:"isakmp",1900:"ssdp",4500:"ipsec-nat",
             5353:"mdns",5355:"llmnr"}
def scan_udp(ip: str, timeout: float = 3.0) -> List[OpenPort]:
    open_p = []
    probes = {
        53: b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00",
        123: b"\x1b" + b"\x00" * 47,
        137: bytes.fromhex("ffffffffffff0000000000000000000000000000002000000000010000000000000000200000000100"),
        1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
        5353: bytes.fromhex("000000000001000000000000016c6f63616c00000c0001"),
    }
    for port, svc in UDP_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(probes.get(port, b"\x00"), (ip, port))
            try:
                data, _ = s.recvfrom(512)
                if data:
                    open_p.append(OpenPort(port=port, proto="udp", service=svc,
                                           banner=data[:80].hex()))
            except socket.timeout:
                pass
        except Exception:
            pass
        finally:
            s.close()
    return open_p

def dns_zone_transfer(target, ip, domain, timeout):
    try:
        out = subprocess.run(["dig", f"@{ip}", "AXFR", domain, "+time=4"],
                             capture_output=True, text=True, timeout=timeout + 8)
        if "XFR size" in out.stdout and "failed" not in out.stdout:
            target.dns_zone = out.stdout[:2000]
            target.findings.append(Finding("DNS zone transfer",
                f"AXFR permitido para '{domain}' — exposição total do DNS.", "high"))
    except Exception:
        pass

def ntp_monlist(target, ip, timeout):
    if not any(p.port == 123 for p in target.udp_open): return
    try:
        out = subprocess.run(["ntpq", "-c", "monlist", ip],
                             capture_output=True, text=True, timeout=timeout + 6)
        if out.returncode == 0 and re.search(r"\d+\.\d+\.\d+\.\d+", out.stdout):
            target.findings.append(Finding("NTP amplificação",
                "monlist habilitado — vetor de DDoS por amplificação.", "medium"))
    except Exception:
        pass

# ===========================================================================
# SMB / NetBIOS / NFS / RPC
# ===========================================================================
def smb_enum(target, ip, timeout):
    for tool, args, label in [("nmblookup", ["-A", ip], "NetBIOS")]:
        try:
            out = subprocess.run([tool, *args], capture_output=True, text=True,
                                 timeout=timeout + 10)
            if out.stdout.strip():
                target.findings.append(Finding("NetBIOS/SMB", out.stdout[:300], "low"))
        except Exception:
            pass
    try:
        out = subprocess.run(["smbclient", "-L", "//" + ip, "-N", "-g"],
                             capture_output=True, text=True, timeout=timeout + 15)
        for line in out.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                target.shares.append({"name": parts[0], "type": parts[1],
                                      "note": "; ".join(parts[2:])})
    except Exception:
        pass

def nfs_enum(ip, port, timeout, target):
    if not tcp_connect(ip, 2049, timeout): return
    try:
        out = subprocess.run(["showmount", "-e", ip], capture_output=True, text=True,
                             timeout=timeout + 15)
        lines = [l for l in out.stdout.splitlines() if l.strip() and "/" in l]
        for l in lines:
            cols = l.split()
            if cols:
                target.mounts.append({"export": cols[0], "opts": " ".join(cols[1:])})
    except Exception:
        pass

def rpc_enum(target, ip, timeout):
    if not any(p.port in (111, 135) for p in target.ports): return
    for tool, args in [("rpcinfo", ["-p", ip]), ("rpcinfo", ["-s", ip])]:
        try:
            out = subprocess.run([tool, *args], capture_output=True, text=True,
                                 timeout=timeout + 10)
            if out.stdout.strip() and "No remote programs" not in out.stdout:
                for line in out.stdout.splitlines():
                    low = line.lower()
                    if any(k in low for k in ("mount", "nfs", "ypserv", "portmapper")):
                        target.findings.append(Finding("RPC", line.strip()[:120], "low"))
        except Exception:
            pass

def rid_cycle(target, ip, timeout, user="", pwd="", max_rid=2000, domain=""):
    cred = f"-U{user}%{pwd}" if user else "-N"
    try:
        out = subprocess.run(["rpcclient", cred, "-c", "lookupnames administrator", ip],
                             capture_output=True, text=True, timeout=timeout + 10)
        m = re.search(r"\(S-1-5-21-\d+-\d+-\d+-\d+\)", out.stdout)
        if m:
            sid = m.group(0).strip("()")
            base = sid.rsplit("-", 1)[0]
            rids = [500, 501, 502, 503, 512, 513, 514, 515, 516, 1000]
            rids += list(range(1000, max_rid + 1, 10))
            # em blocos de 40 para caber no comando
            for i in range(0, len(rids), 40):
                chunk = rids[i:i + 40]
                cmd = "lookupsids " + base + "-" + " ".join(str(r) for r in chunk)
                out2 = subprocess.run(["rpcclient", cred, "-c", cmd, ip],
                                      capture_output=True, text=True, timeout=timeout + 20)
                for line in out2.stdout.splitlines():
                    mm = re.search(r"\*S-1-5-21-\d+-\d+-\d+-(\d+)\s+\d+\s+\*([^*]*)\*", line)
                    if mm:
                        uid, name = mm.groups()
                        if int(uid) >= 500 and name:
                            target.users.append(User(name=name, uid=uid,
                                                     source="smb-rid", extra=base))
        else:
            target.findings.append(Finding("SMB RID",
                "Não foi possível obter SID do domínio (lookup anônimo negado).", "info"))
    except Exception:
        pass

# ===========================================================================
# SSH / SMTP / SNMP (enumeração de usuários)
# ===========================================================================
def ssh_user_enum(target, ip, timeout, usernames, delay=0.4):
    if not any(p.port == 22 for p in target.ports): return
    test_users = usernames + ["zzzdefinitelynotexist_" + str(int(time.time() * 1000))]
    base = None
    for u in test_users:
        t0 = time.time()
        try:
            subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "NumberOfPasswordPrompts=0",
                            f"{u}@{ip}", "exit"],
                           capture_output=True, timeout=timeout + 6)
        except Exception:
            pass
        dt = time.time() - t0
        time.sleep(delay)
        if u.startswith("zzz"):
            base = dt; continue
        if base and dt > base * 1.35 and dt > 1.0:
            target.users.append(User(name=u, source="ssh-timing",
                                     extra=f"tempo={dt:.2f}s baseline={base:.2f}s"))

def smtp_vrfy(target, ip, timeout, usernames):
    if not any(p.port in (25, 465, 587) for p in target.ports): return
    s = tcp_connect(ip, 25, timeout)
    if not s: return
    s.settimeout(timeout)
    try:
        s.recv(1024)
        s.sendall(b"HELO enum.local\r\n"); s.recv(1024)
        for u in usernames:
            s.sendall(f"VRFY {u}\r\n".encode())
            try:
                resp = s.recv(1024).decode("utf-8", "replace")
            except socket.timeout:
                continue
            if resp.startswith("252") or (resp.startswith("250") and "not" not in resp.lower()):
                target.users.append(User(name=u, source="smtp-vrfy",
                                         extra=resp[:60].strip()))
            time.sleep(0.3)
        s.sendall(b"QUIT\r\n")
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def snmp_walk(target, ip, timeout, communities):
    if not any(p.port == 161 for p in target.ports): return
    for comm in communities:
        try:
            out = subprocess.run(["snmpwalk", "-v", "2c", "-c", comm, "-t", "2",
                                  "-r", "0", ip, "1.3.6.1.2.1.1"],
                                 capture_output=True, text=True, timeout=timeout + 15)
            if out.returncode == 0 and out.stdout.strip():
                info = {"community": comm, "sysdescr": "", "hostname": "", "uptime": ""}
                for line in out.stdout.splitlines():
                    if "sysDescr" in line: info["sysdescr"] = line.split(":", 1)[-1].strip()
                    if "sysName" in line: info["hostname"] = line.split(":", 1)[-1].strip()
                    if "sysUpTime" in line: info["uptime"] = line.split(":", 1)[-1].strip()
                target.findings.append(Finding("SNMP community pública",
                    f"Community '{comm}' permite leitura ({info['sysdescr'][:90]})", "medium"))
                return
        except Exception:
            pass

# ===========================================================================
# HTTP profundo
# ===========================================================================
DIR_WORDLIST = ["admin","login","api","wp-admin","wp-login.php","uploads","backup",
    "config.php",".git/HEAD",".env","phpinfo.php","robots.txt","sitemap.xml","cgi-bin",
    "server-status","info.php","test.php","shell.php","vendor","node_modules","private",
    "logs","db","sql","dumps","phpmyadmin","pma","dashboard","manager","console","debug",
    "graphql","v1","swagger","api/v1","jenkins","tomcat","manager/html","user",
    "wordpress","administrator","admin.php","login.php","index.php","config","etc"]

def detect_web_tech(target, body, headers, entry):
    tech = []
    checks = [
        (r"wp-content|wordpress", "WordPress"), (r"drupal", "Drupal"),
        (r"joomla|com_content", "Joomla"), (r"magento|Mage\.Cookies", "Magento"),
        (r"csrfmiddlewaretoken|django", "Django"), (r"laravel|csrf-token", "Laravel"),
        (r"rails|data-turbolinks", "Ruby on Rails"), (r"__VIEWSTATE", "ASP.NET"),
        (r"nuxt|__NUXT__", "Nuxt/Vue"), (r"next\.js|__NEXT_DATA__", "Next.js/React"),
        (r"generator.{0,20}php|X-Powered-By:\s*PHP", "PHP"), (r"jQuery|jquery", "jQuery"),
        (r"bootstrap", "Bootstrap"), (r"react", "React"), (r"vue\.js|vue", "Vue.js"),
        (r"angular", "AngularJS"), (r"shiny|plotly", "Shiny/Plotly"),
        (r"flask|werkzeug", "Flask/Werkzeug"), (r"express|node\.js", "Node/Express"),
    ]
    joined = body + " " + json.dumps(dict(headers)).lower()
    for pat, name in checks:
        if re.search(pat, joined, re.I) and name not in tech:
            tech.append(name)
    if headers.get("Server"): tech.append("Server: " + headers["Server"])
    if headers.get("X-Powered-By"): tech.append(headers["X-Powered-By"])
    if tech:
        entry["tech"] = tech
        target.web_tech += [t for t in tech if t not in target.web_tech]

def http_deep(target, ip, timeout):
    import urllib.request, urllib.error
    import ssl as _ssl
    web_ports = [p.port for p in target.ports
                 if p.service.startswith("http") or p.service == "grafana"]
    for port in web_ports:
        is_tls = any(p.port == port and p.ssl for p in target.ports)
        scheme = "https" if is_tls or port in (443, 8443) else "http"
        ctx = _ssl.create_default_context(); ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        root = f"{scheme}://{ip}:{port}"
        entry = {"port": port, "scheme": scheme, "url": root, "paths": []}
        try:
            req = urllib.request.Request(root + "/", method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 LinEnumX"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                entry["status_root"] = r.status
                entry["headers"] = {k: r.headers.get(k) for k in
                    ("Server","X-Powered-By","X-AspNet-Version","Location",
                     "WWW-Authenticate","Content-Security-Policy") if r.headers.get(k)}
        except urllib.error.HTTPError as e:
            entry["status_root"] = e.code
            entry["headers"] = {"Server": e.headers.get("Server", "")}
        except Exception:
            entry["status_root"] = "?"
        found = []
        for d in DIR_WORDLIST:
            url = f"{root}/{d}"
            try:
                req = urllib.request.Request(url, method="HEAD",
                    headers={"User-Agent": "Mozilla/5.0 LinEnumX"})
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    if 200 <= r.status < 400:
                        found.append((url, r.status))
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404, 405, 401):
                    found.append((url, e.code))
            except Exception:
                pass
        entry["paths"] = found
        target.http_results.append(entry)
        target.directories += [f"{u} [{c}]" for u, c in found]
        try:
            req = urllib.request.Request(root + "/", method="OPTIONS",
                headers={"User-Agent": "LinEnumX"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                allow = r.headers.get("Allow", "")
                if allow:
                    entry["allow"] = allow
                    if "TRACE" in allow.upper():
                        target.findings.append(Finding("HTTP TRACE habilitado",
                            f"{root} permite TRACE (risco XST).", "low"))
        except Exception:
            pass
        try:
            req = urllib.request.Request(root + "/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(20000).decode("utf-8", "replace")
                detect_web_tech(target, body, r.headers, entry)
        except Exception:
            pass

# ===========================================================================
# Bancos / serviços sem autenticação
# ===========================================================================
def enum_redis(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(b"INFO\r\n"); data = s.recv(4096)
        txt = data.decode("utf-8", "replace")
        if "redis_version" in txt:
            m = re.search(r"redis_version:([\d.]+)", txt)
            v = m.group(1) if m else "?"
            target.db_info.append({"type": "redis", "port": port, "version": v,
                                   "anon_write": False})
            s.sendall(b"SET enumx__test 1\r\n")
            time.sleep(0.3)
            if b"+OK" in s.recv(128):
                s.sendall(b"DEL enumx__test\r\n")
                target.db_info[-1]["anon_write"] = True
                target.findings.append(Finding("Redis sem auth",
                    "Escrita anônima permitida — risco de RCE via cron/ssh key.", "high"))
            target.findings.append(Finding("Redis exposto", f"Redis {v} sem credenciais.", "medium"))
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_mysql(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(bytes.fromhex("0a0000000a352e372e3331000000000000000000000000000000000000000000"))
        data = s.recv(1024)
        if data:
            txt = data.decode("utf-8", "replace")
            m = re.search(r"([\d.]+)", txt)
            target.db_info.append({"type": "mysql", "port": port,
                "version": m.group(1) if m else txt[:40],
                "auth_required": "Access denied" in txt})
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_postgres(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        data = s.recv(2048)
        txt = data.decode("utf-8", "replace")
        if txt.startswith("R"):
            target.db_info.append({"type": "postgresql", "port": port,
                                   "auth_requested": True})
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_memcached(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(b"stats\r\n"); data = b""
        s.settimeout(timeout)
        try:
            while b"END" not in data:
                d = s.recv(1024)
                if not d: break
                data += d
        except socket.timeout:
            pass
        txt = data.decode("utf-8", "replace")
        if "STAT" in txt and "pid" in txt:
            m = re.search(r"STAT version ([\d.]+)", txt)
            target.db_info.append({"type": "memcached", "port": port,
                "version": m.group(1) if m else "?"})
            target.findings.append(Finding("Memcached exposto",
                "Leitura sem auth (dados em memória expostos).", "medium"))
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_mongodb(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(bytes.fromhex("3a0000000100000000000000d407000000000000002e0000001069736d6173746572000100000000"))
        data = s.recv(2048)
        if data and (b"ismaster" in data or len(data) > 30):
            target.db_info.append({"type": "mongodb", "port": port,
                                   "auth_not_required": True})
            target.findings.append(Finding("MongoDB exposto",
                "Sem autenticação — possível exfiltração/ransomware de dados.", "high"))
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_docker(ip, port, timeout, target):
    if port not in (2375, 2376): return
    try:
        import urllib.request
        url = f"http://{ip}:2375/version"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.loads(r.read().decode())
            target.db_info.append({"type": "docker", "port": 2375,
                "version": d.get("Version", ""), "api": "sem TLS"})
            target.findings.append(Finding("Docker API exposta",
                "Daemon sem TLS — RCE total via containers.", "critical"))
    except Exception:
        pass

def enum_elastic(ip, port, timeout, target):
    if port not in (9200, 9300): return
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{ip}:{port}/", timeout=timeout) as r:
            d = json.loads(r.read().decode())
            target.db_info.append({"type": "elasticsearch", "port": port,
                "version": d.get("version", {}).get("number", "")})
            target.findings.append(Finding("Elasticsearch exposto", "API sem auth.", "medium"))
    except Exception:
        pass

def enum_rsync(ip, port, timeout, target):
    if port != 873: return
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        s.sendall(b"\x00"); data = s.recv(4096).decode("utf-8", "replace")
        if "@RSYNCD" in data:
            s.sendall(b"#list\n"); time.sleep(0.5)
            mods = b""
            try:
                while True:
                    d = s.recv(4096)
                    if not d: break
                    mods += d
                    if b"@RSYNCD: EXIT" in mods: break
            except socket.timeout:
                pass
            target.db_info.append({"type": "rsync", "port": 873,
                "modules": mods.decode("utf-8", "replace")[:1000]})
            if b"@RSYNCD: EXIT" in mods and b"error" not in mods.lower():
                target.findings.append(Finding("Rsync lista módulos",
                    "Shares rsync enumeráveis sem auth.", "medium"))
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

def enum_ldap(ip, port, timeout, target):
    if port not in (389, 636): return
    try:
        import ldap3
        scheme = "ldaps" if port == 636 else "ldap"
        srv = ldap3.Server(ip, get_info=ldap3.ALL, port=port)
        conn = ldap3.Connection(srv, auto_bind=True)
        ncs = conn.server.info.naming_contexts
        if ncs:
            target.db_info.append({"type": "ldap", "port": port,
                "naming_contexts": [str(n) for n in ncs], "anon_bind": True})
            target.findings.append(Finding("LDAP bind anônimo",
                f"Base DN: {ncs[0]}", "medium"))
            try:
                conn.search(str(ncs[0]), "(objectClass=person)",
                            attributes=["cn", "uid", "mail"], size_limit=10)
                for e in conn.entries:
                    uid = getattr(e, 'uid', None)
                    if uid and uid.value:
                        target.users.append(User(name=str(uid.value), source="ldap-anon"))
            except Exception:
                pass
    except ImportError:
        target.db_info.append({"type": "ldap", "port": port,
            "note": "ldap3 ausente; instale: pip install ldap3"})
    except Exception:
        pass

def enum_telnet(ip, port, timeout, target):
    s = _sock(ip, port, timeout)
    if not s: return
    try:
        data = s.recv(1024)
        if data:
            target.svc_banners.append({"type": "telnet", "port": port,
                "banner": data.decode("utf-8", "replace")[:200]})
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

# ===========================================================================
# Credenciais e pós-exploração
# ===========================================================================
def _ssh_auth(ip, user, pwd, timeout):
    try:
        r = subprocess.run(["sshpass", "-p", pwd, "ssh",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "ConnectTimeout=4",
                            "-o", "NumberOfPasswordPrompts=1",
                            f"{user}@{ip}", "echo __ok__"],
                           capture_output=True, text=True, timeout=timeout + 6)
        return "__ok__" in r.stdout
    except Exception:
        return False

def _postexploit_ssh(target, ip, user, pwd, timeout):
    cmds = ["id && uname -a",
            "cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v /bin/false",
            "sudo -l 2>/dev/null | head -30",
            "find / -perm -4000 -type f 2>/dev/null | head -30",
            "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null | head -20",
            "ip a 2>/dev/null || ifconfig -a 2>/dev/null",
            "cat /proc/version 2>/dev/null"]
    for cmd in cmds:
        try:
            r = subprocess.run(["sshpass", "-p", pwd, "ssh",
                                "-o", "StrictHostKeyChecking=no",
                                "-o", "ConnectTimeout=4", f"{user}@{ip}", cmd],
                               capture_output=True, text=True, timeout=timeout + 10)
            if r.stdout.strip():
                target.postex.append(f"$ {cmd}\n{r.stdout.strip()[:1500]}")
        except Exception:
            pass

def try_credentials(target, ip, timeout, creds):
    svc_ssh = any(p.port == 22 for p in target.ports)
    svc_ftp = any(p.port == 21 for p in target.ports)
    for u, p in creds:
        if svc_ssh and _ssh_auth(ip, u, p, timeout):
            target.cred_checks.append({"service": "ssh", "user": u, "pass": p, "ok": True})
            target.findings.append(Finding("Credencial SSH válida", f"{u}:{p}", "high"))
            _postexploit_ssh(target, ip, u, p, timeout)
        if svc_ftp:
            import ftplib
            try:
                ftp = ftplib.FTP(); ftp.connect(ip, 21, timeout=timeout)
                ftp.login(u, p)
                target.cred_checks.append({"service": "ftp", "user": u, "pass": p, "ok": True})
                target.findings.append(Finding("Credencial FTP válida", f"{u}:{p}", "high"))
                ftp.quit()
            except Exception:
                pass
        time.sleep(0.3)
    if not target.cred_checks:
        target.findings.append(Finding("Creds",
            "Nenhuma credencial testada validou.", "info"))

# ===========================================================================
# Fingerprint de OS + CVEs
# ===========================================================================
OS_PATTERNS = [
    (r"debian|ubuntu", "Debian/Ubuntu"), (r"centos|red ?hat|fedora|rocky|alma", "RHEL-family"),
    (r"suse|opensuse", "SUSE"), (r"arch", "Arch"), (r"alpine", "Alpine"),
    (r"gentoo", "Gentoo"), (r"linux", "Linux"),
]
def guess_os(ports, banner_text=""):
    b = (banner_text or " ").lower()
    if not banner_text:
        b = " ".join(p.banner.lower() for p in ports)
    for pat, name in OS_PATTERNS:
        if re.search(pat, b): return name
    return "Linux (indeterminado)"

def cve_check(op):
    res = []
    rules = {
        "ftp": [("vsftpd (\\d+\\.\\d+\\.\\d+)", [("^2\\.3\\.4$", "high",
                 "CVE-2011-2523 — backdoor vsftpd 2.3.4")]),
                ("proftpd (\\d+\\.\\d+\\.\\d+)", [("^1\\.3\\.5$", "high",
                 "CVE-2015-3306 — mod_copy RCE")])],
        "http": [("apache/(\\d+\\.\\d+\\.\\d+)", [("^2\\.4\\.49$", "critical",
                  "CVE-2021-41773 — path traversal/RCE"),
                 ("^2\\.4\\.50$", "high", "CVE-2021-42013 — path traversal bypass")]),
                 ("nginx/(\\d+\\.\\d+\\.\\d+)", [("^1\\.6\\.2$", "high",
                  "CVE-2014-0088? — revisar")])],
    }
    key = op.service
    if key in ("http-proxy", "http-alt", "https-alt", "grafana"): key = "http"
    for ver_re, rule_list in rules.get(key, []):
        m = re.search(ver_re, op.banner)
        if not m: continue
        ver = ".".join(m.groups())
        for pat, sev, title in rule_list:
            try:
                if re.match(pat, ver):
                    res.append(Finding(f"CVE em {op.service}", title, sev))
            except re.error:
                if re.match(pat, ver): pass
    return res

# ===========================================================================
# Relatórios
# ===========================================================================
class Reporter:
    def __init__(self, target):
        self.t = target

    def risk_score(self):
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.t.findings:
            k = f.severity if f.severity in sev else "info"
            sev[k] += 1
        score = min(10.0, sev["critical"] * 3 + sev["high"] * 2 +
                    sev["medium"] * 1 + sev["low"] * 0.5)
        return score, sev

    def text(self):
        L = [BANNER]
        score, sev = self.risk_score()
        L.append(f"{Fore.YELLOW}[+] Alvo      : {self.t.ip}  {self.t.hostname}")
        L.append(f"[+] OS suspeito: {self.t.os_hint}")
        L.append(f"[+] Host ativo : {self.t.up}")
        all_p = self.t.ports + self.t.udp_open
        L.append(f"\n{Fore.CYAN}[=] Portas abertas ({len(all_p)}):{Style.RESET_ALL}")
        for p in all_p:
            sslm = f" {Fore.MAGENTA}[TLS]{Style.RESET_ALL}" if getattr(p, 'ssl', False) else ""
            L.append(f"  {Fore.GREEN}{p.port:>6}/{p.proto:<3}{Style.RESET_ALL}"
                     f" {p.service:<14}{sslm}")
            if p.banner:
                L.append(f"          banner: {p.banner[:160]}")
            for n in p.notes:
                L.append(f"          -> {n}")
        if self.t.http_results:
            L.append(f"\n{Fore.CYAN}[=] HTTP ({len(self.t.http_results)} portas web):{Style.RESET_ALL}")
            for h in self.t.http_results:
                L.append(f"  {h['scheme']}://{self.t.ip}:{h['port']}/  (status {h.get('status_root','?')})")
                if h.get('headers'):
                    L.append(f"      headers: {h['headers']}")
                if h.get('tech'):
                    L.append(f"      tech: {', '.join(h['tech'])}")
                for url, code in h.get('paths', [])[:25]:
                    L.append(f"      [*] {url} -> {code}")
        if self.t.web_tech:
            L.append(f"\n[=] Tecnologias web: {', '.join(self.t.web_tech)}")
        if self.t.db_info:
            L.append(f"\n{Fore.CYAN}[=] Serviços/bancos enumerados:{Style.RESET_ALL}")
            for d in self.t.db_info:
                L.append(f"  {d}")
        if self.t.svc_banners:
            L.append(f"\n[=] Banners diversos:")
            for b in self.t.svc_banners:
                L.append(f"  {b}")
        if self.t.users:
            L.append(f"\n{Fore.CYAN}[=] Usuários encontrados ({len(self.t.users)}):{Style.RESET_ALL}")
            for u in self.t.users:
                L.append(f"  {Fore.GREEN}{u.name}{Style.RESET_ALL}  via {u.source}"
                         + (f"  ({u.extra})" if u.extra else ""))
        if self.t.shares:
            L.append(f"\n{Fore.CYAN}[=] Shares SMB:{Style.RESET_ALL}")
            for s in self.t.shares:
                L.append(f"  {s['name']:<30} {s['type']:<12} {s.get('note', '')}")
        if self.t.mounts:
            L.append(f"\n{Fore.CYAN}[=] NFS exports:{Style.RESET_ALL}")
            for m in self.t.mounts:
                L.append(f"  {m['export']:<40} {m['opts']}")
        if self.t.dns_zone:
            L.append(f"\n[=] Zona DNS transferida:")
            L.append(self.t.dns_zone[:1500])
        if self.t.cred_checks:
            L.append(f"\n[=] Credenciais válidas:")
            for c in self.t.cred_checks:
                if c.get('ok'):
                    L.append(f"  {c['service']}: {c['user']}:{c['pass']}")
        if self.t.postex:
            L.append(f"\n{Fore.GREEN}[=] Pós-exploração SSH:{Style.RESET_ALL}")
            for p in self.t.postex:
                L.append("  " + p.replace("\n", "\n  ")[:2000])
        if self.t.findings:
            sev_col = {"info": Fore.WHITE, "low": Fore.BLUE, "medium": Fore.YELLOW,
                       "high": Fore.MAGENTA, "critical": Fore.RED}
            L.append(f"\n{Fore.CYAN}[=] Achados ({len(self.t.findings)}):{Style.RESET_ALL}")
            for f in self.t.findings:
                c = sev_col.get(f.severity, Fore.WHITE)
                cve = f"  [{f.cve}]" if f.cve else ""
                L.append(f"  {c}[{f.severity.upper():^8}]{Style.RESET_ALL} {f.title}: {f.detail}{cve}")
        L.append(f"\n{Fore.CYAN}[=] RISK SCORE: {score:.1f}/10  "
                 f"(crit={sev['critical']} high={sev['high']} med={sev['medium']} "
                 f"low={sev['low']}){Style.RESET_ALL}")
        L.append(f"\n{Fore.CYAN}-- LinEnumX {VERSION} concluído em "
                 f"{datetime.now().isoformat()} --{Style.RESET_ALL}")
        return "\n".join(L)

    def to_dict(self):
        return {"ip": self.t.ip, "hostname": self.t.hostname, "os_hint": self.t.os_hint,
                "up": self.t.up, "generated": datetime.now().isoformat(),
                "tool": f"LinEnumX {VERSION}",
                "ports": [asdict(p) for p in self.t.ports],
                "udp_ports": [asdict(p) for p in self.t.udp_open],
                "users": [asdict(u) for u in self.t.users],
                "shares": self.t.shares, "mounts": self.t.mounts,
                "http": self.t.http_results, "web_tech": self.t.web_tech,
                "db_info": self.t.db_info, "svc_banners": self.t.svc_banners,
                "dns_zone": self.t.dns_zone, "cred_checks": self.t.cred_checks,
                "postex": self.t.postex,
                "findings": [asdict(f) for f in self.t.findings]}

    def json(self):
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def html(self):
        d = self.to_dict()
        rows = "".join(
            f"<tr><td>{p['port']}/{p['proto']}</td><td>{p['service']}</td>"
            f"<td>{p.get('banner', '')[:140]}</td><td>{p.get('ssl')}</td></tr>"
            for p in d["ports"] + d["udp_ports"])
        us = "".join(f"<li><b>{u['name']}</b> via {u['source']}</li>"
                     for u in d["users"]) or "<li>—</li>"
        fs = "".join(
            f"<li><span style='color:{ 'red' if f['severity']=='critical' else 'orange' if f['severity'] in ('high','medium') else 'green' }'>{f['severity'].upper()}</span> &mdash; {f['title']}: {f['detail']}</li>"
            for f in d["findings"]) or "<li>—</li>"
        db = "".join(f"<li>{v}</li>" for v in d["db_info"]) or "<li>—</li>"
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>LinEnumX — {self.t.ip}</title></head><body>
<h1>LinEnumX — {self.t.ip}</h1>
<p>OS: <b>{d['os_hint']}</b> | gerado {d['generated']}</p>
<h2>Portas</h2><table border=1><tr><th>Porta</th><th>Serviço</th><th>Banner</th><th>TLS</th></tr>{rows}</table>
<h2>Usuários</h2><ul>{us}</ul>
<h2>Bancos/Serviços</h2><ul>{db}</ul>
<h2>Achados</h2><ul>{fs}</ul></body></html>"""

    def yaml(self):
        d = self.to_dict()
        def _clean(o):
            if isinstance(o, dict):
                return {k: _clean(v) for k, v in o.items() if v not in ("", None)}
            if isinstance(o, list):
                return [_clean(x) for x in o]
            return o
        try:
            import yaml
            return yaml.safe_dump(_clean(d), sort_keys=False, allow_unicode=True,
                                  default_flow_style=False)
        except ImportError:
            return "# pip install pyyaml para gerar YAML\n" + self.json()

    def markdown(self):
        d = self.to_dict()
        L = [f"# LinEnumX — {self.t.ip}", "",
             f"**OS suspeito:** {d['os_hint']}  **Gerado:** {d['generated']}", "",
             "## Portas abertas", "", "| Porta | Serviço | Banner | TLS |", "|---|---|---|---|"]
        for p in d["ports"] + d["udp_ports"]:
            L.append(f"| {p['port']}/{p['proto']} | {p['service']} | "
                     f"{p.get('banner', '')[:80].replace('|', '/')} | {p.get('ssl')} |")
        L += ["", "## Usuários", ""]
        L += [f"- **{u['name']}** via {u['source']}" for u in d["users"]] or ["- —"]
        L += ["", "## Achados", ""]
        for f in d["findings"]:
            cve = f" (`{f['cve']}`)" if f.get('cve') else ""
            L.append(f"- **[{f['severity'].upper()}]** {f['title']}: {f['detail']}{cve}")
        if self.t.postex:
            L += ["", "## Pós-exploração", ""]
            for p in self.t.postex:
                L += ["```bash", p, "```"]
        return "\n".join(L)

# ===========================================================================
# Argumentos / fluxo principal
# ===========================================================================
DEFAULT_PORTS = "22,80,139,443,445,111,2049,25,21,3306,5432,6379,8080,8443,161,873,23,53,88,389,636,5900,7001,9200,27017,11211,4369,2375,11211,3000,9090"
COMMON_USERS = ["root","admin","administrator","user","ubuntu","debian","test",
                "oracle","postgres","mysql","www-data","backup","guest","ftp","nobody"]
SNMP_COMMUNITIES = ["public","private","community","monitor","admin"]

def expand_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def parse_args():
    ap = argparse.ArgumentParser(
        description="LinEnumX — enumeração avançada de hosts Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-t", "--target", required=True, help="IP ou hostname")
    ap.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="portas TCP")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--threads", type=int, default=256)
    ap.add_argument("--no-scan", action="store_true")
    ap.add_argument("--service", action="append",
                    choices=["ssh","smb","nfs","smtp","snmp","rpc","http"],
                    help="apenas protocolos selecionados (repetível)")
    ap.add_argument("--users", help="usuários separados por vírgula")
    ap.add_argument("--user-file", help="arquivo com usuários")
    ap.add_argument("--udp", action="store_true", help="varredura UDP")
    ap.add_argument("--http-deep", action="store_true", help="enumeração HTTP profunda")
    ap.add_argument("--domain", default="", help="domínio p/ zone transfer e RID")
    ap.add_argument("--rid-cycle", action="store_true", help="RID cycling SMB")
    ap.add_argument("--max-rid", type=int, default=2000)
    ap.add_argument("--creds-file", help="arquivo user:pass (uma por linha)")
    ap.add_argument("--user", default="", help="usuário p/ operações com creds")
    ap.add_argument("--password", default="", help="senha p/ operações com creds")
    ap.add_argument("--no-ping", action="store_true")
    ap.add_argument("-o", "--outdir", default=".")
    ap.add_argument("-f", "--format", default="text",
                    help="text,json,html,md,yaml (combina com vírgula)")
    return ap.parse_args()

def main():
    args = parse_args()
    print(BANNER)
    ip = args.target
    target = Target(ip=ip)

    users = COMMON_USERS
    if args.users:
        users = [u.strip() for u in args.users.split(",") if u.strip()]
    if args.user_file and os.path.isfile(args.user_file):
        with open(args.user_file) as fh:
            users = [l.strip() for l in fh if l.strip()]

    print(f"{Fore.YELLOW}[*] Alvo: {ip}{Style.RESET_ALL}")

    # --- 1) varredura TCP ---
    if not args.no_scan:
        ports = expand_ports(args.ports)
        print(f"{Fore.YELLOW}[*] Varredura TCP de {len(ports)} portas "
              f"(timeout={args.timeout}s, threads={args.threads})...{Style.RESET_ALL}")
        t0 = time.time()
        target.ports = Scanner(ip, ports, args.timeout, args.threads).run()
        print(f"    varredura concluída em {time.time()-t0:.1f}s — "
              f"{len(target.ports)} portas abertas")
    else:
        target.ports = [OpenPort(port=p, service=SERVICE_MAP.get(p, "unknown"))
                        for p in expand_ports(args.ports)]

    target.up = bool(target.ports) or (tcp_connect(ip, 22, args.timeout) is not None)

    # --- 2) fingerprint de OS ---
    if not args.no_ping and not target.os_hint:
        target.os_hint = os_ttl_guess(ip, args.timeout)
    if not target.os_hint:
        target.os_hint = guess_os(target.ports)

    # --- 3) CVEs por banner ---
    for p in target.ports:
        target.findings.extend(cve_check(p))

    # --- 4) UDP ---
    if args.udp:
        print("[*] Varredura UDP...")
        target.udp_open = scan_udp(ip, args.timeout)
        for u in target.udp_open:
            print(f"    {Fore.GREEN}{u.port}/udp {u.service}{Style.RESET_ALL}")

    # --- 5) DNS / NTP ---
    if args.domain and any(p.port == 53 for p in target.ports):
        print(f"[*] Zone transfer de {args.domain}...")
        dns_zone_transfer(target, ip, args.domain, args.timeout)
    ntp_monlist(target, ip, args.timeout)

    # --- 6) protocolos de enumeração de usuários/serviços ---
    selected = set(args.service) if args.service else \
        {"ssh", "smb", "nfs", "smtp", "snmp", "rpc", "http"}
    present = {p.service for p in target.ports}
    print(f"{Fore.YELLOW}[*] Protocolos a enumerar: {', '.join(sorted(selected))}{Style.RESET_ALL}")

    if "smb" in selected and any(p.port in (139, 445) for p in target.ports):
        print("[*] Enumerando SMB/NetBIOS..."); smb_enum(target, ip, args.timeout)
    if "nfs" in selected and any(p.port == 2049 for p in target.ports):
        print("[*] Enumerando NFS..."); nfs_enum(ip, 2049, args.timeout, target)
    if "ssh" in selected and any(p.port == 22 for p in target.ports):
        print("[*] Enumerando usuários SSH por timing...")
        ssh_user_enum(target, ip, args.timeout, users)
    if "smtp" in selected and any(p.port in (25, 465, 587) for p in target.ports):
        print("[*] Enumerando usuários via SMTP VRFY...")
        smtp_vrfy(target, ip, args.timeout, users)
    if "snmp" in selected and any(p.port == 161 for p in target.ports):
        print("[*] Varrendo SNMP..."); snmp_walk(target, ip, args.timeout, SNMP_COMMUNITIES)
    if "rpc" in selected and any(p.port in (111, 135) for p in target.ports):
        print("[*] Enumerando RPC..."); rpc_enum(target, ip, args.timeout)

    # --- 7) HTTP profundo ---
    if args.http_deep and any(p.service.startswith("http") or p.service == "grafana"
                              for p in target.ports):
        print("[*] Enumeração HTTP profunda...")
        http_deep(target, ip, args.timeout)

    # --- 8) serviços/bancos sem auth ---
    print("[*] Probing de serviços comuns...")
    svc_checks = {2049: nfs_enum, 873: enum_rsync, 6379: enum_redis,
                  3306: enum_mysql, 5432: enum_postgres, 11211: enum_memcached,
                  27017: enum_mongodb}
    for port, fn in svc_checks.items():
        if any(p.port == port for p in target.ports):
            fn(ip, port, args.timeout, target)
    for port in (9200, 9300):
        if any(p.port == port for p in target.ports):
            enum_elastic(ip, port, args.timeout, target)
    for port in (2375, 2376):
        if any(p.port == port for p in target.ports):
            enum_docker(ip, port, args.timeout, target)
    for port in (389, 636):
        if any(p.port == port for p in target.ports):
            enum_ldap(ip, port, args.timeout, target)
    if any(p.port == 23 for p in target.ports):
        enum_telnet(ip, 23, args.timeout, target)

    # --- 9) RID cycling ---
    if args.rid_cycle and any(p.port in (139, 445) for p in target.ports):
        print("[*] RID cycling SMB...")
        rid_cycle(target, ip, args.timeout, args.user, args.password,
                  args.max_rid, args.domain)

    # --- 10) credenciais ---
    if args.creds_file and os.path.isfile(args.creds_file):
        print("[*] Checando credenciais...")
        creds = []
        with open(args.creds_file) as fh:
            for line in fh:
                line = line.strip()
                if ":" in line:
                    u, p = line.split(":", 1)
                    creds.append((u, p))
        if creds:
            try_credentials(target, ip, args.timeout, creds)

    # --- 11) relatórios ---
    rep = Reporter(target)
    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.join(args.outdir, f"linenumx_{ip}")
    fmts = [f.strip() for f in args.format.split(",")]
    for f in fmts:
        try:
            if f == "text":
                txt = rep.text(); print(txt)
                with open(base + ".txt", "w", encoding="utf-8") as fh: fh.write(txt)
                print(f"\n[+] relatório texto: {base}.txt")
            elif f == "json":
                with open(base + ".json", "w") as fh: fh.write(rep.json())
                print(f"[+] relatório json : {base}.json")
            elif f == "html":
                with open(base + ".html", "w") as fh: fh.write(rep.html())
                print(f"[+] relatório html : {base}.html")
            elif f in ("md", "markdown"):
                with open(base + ".md", "w") as fh: fh.write(rep.markdown())
                print(f"[+] relatório markdown: {base}.md")
            elif f in ("yaml", "yml"):
                with open(base + ".yaml", "w") as fh: fh.write(rep.yaml())
                print(f"[+] relatório yaml : {base}.yaml")
        except Exception as e:
            print(f"[!] erro ao gravar relatório {f}: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] interrompido pelo usuário.{Style.RESET_ALL}")
        sys.exit(130)
