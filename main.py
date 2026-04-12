#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import threading
import httpx
import urllib3
import asyncio
import ipaddress
import signal
import ssl
import dns.resolver
from queue import Queue
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
shutdown = False

# ================= SIGNAL =================
def handle_exit(sig, frame):
    global shutdown
    shutdown = True
    console.print("\n[red]🛑 Stopping scan...[/red]")

signal.signal(signal.SIGINT, handle_exit)

# ================= UI =================
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    # Simple Text Banner
    console.print("\n[bold red]║------------------------------------------------║[/bold red]")
    console.print("[bold green]                V O I D F L A R E                 [/bold green]")
    console.print("[dim green]          Advanced Network Multi-Scanner          [/dim green]")
    console.print("[bold red]║------------------------------------------------║[/bold red]\n")

def main_menu():
    console.print(Panel.fit(
        "🔥 [bold red] VoidFlare v1.0[/bold red]\n[dim]The Ultimate Tools for Discovery & Tunneling[/dim]",
        style="bold white",
        border_style="red"
    ))
    console.print("\n[bold cyan]╔════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║        SELECT OPTION               ║[/bold cyan]")
    console.print("[bold cyan]╠════════════════════════════════════╣[/bold cyan]")
    console.print("[bold cyan]║  [1] Domain File Scanner           ║[/bold cyan]")
    console.print("[bold cyan]║  [2] Advanced TCP/HTTP Scanner     ║[/bold cyan]")
    console.print("[bold cyan]║  [3] CDN Finder                    ║[/bold cyan]")
    console.print("[bold cyan]║  [4] Tunable Checker               ║[/bold cyan]")
    console.print("[bold cyan]║  [5] Subdomain Finder (NEW)        ║[/bold cyan]")
    console.print("[bold cyan]║  [6] Exit                          ║[/bold cyan]")
    console.print("[bold cyan]╚════════════════════════════════════╝[/bold cyan]")
    return console.input("[bold yellow]➤ Choose option: [/bold yellow]").strip()

# ================= TOOL 1: DOMAIN SCANNER =================
class DomainScanner:
    def __init__(self):
        self.THREADS = 180
        self.TIMEOUT = 2
        self.CHUNK_SIZE = 500
        self.q = Queue()
        self.lock = threading.Lock()

    def resolve_ip(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            return "-"

    def scan(self, host, ports, outfile, client):
        ip = self.resolve_ip(host)

        for port in ports:
            if port == 443:
                url = f"https://{host}"
            else:
                url = f"http://{host}:{port}"

            try:
                r = client.get(
                    url,
                    timeout=self.TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                if r.status_code == 302:
                    return

                server = r.headers.get("Server", "Unknown")
                result = f"{r.status_code} | {ip} | {server} | {host}:{port}"

                with self.lock:
                    console.print(
                        f"[green]{r.status_code:<5}[/green] │ "
                        f"[cyan]{ip:<15}[/cyan] │ "
                        f"[magenta]{server:<22}[/magenta] │ "
                        f"[yellow]{host}:{port}[/yellow]"
                    )
                    outfile.write(result + "\n")
                    outfile.flush()
            except:
                pass

    def worker(self, ports, outfile, progress, task):
        with httpx.Client(verify=False, timeout=self.TIMEOUT, http2=True) as client:
            while True:
                host = self.q.get()
                if host is None:
                    break
                self.scan(host, ports, outfile, client)
                progress.update(task, advance=1)
                self.q.task_done()

    def run(self):
        clear()
        console.print(Panel.fit("[bold green]DOMAIN FILE SCANNER (httpx)[/bold green]", style="bold green"))
        
        domain_file = input("\n[?] Domain file: ").strip()

        if not os.path.isfile(domain_file):
            console.print("[red]✗ File not found![/red]")
            input("\n[?] Press Enter to continue...")
            return

        ports_input = input("[?] Ports (default 443): ").strip()

        if ports_input == "":
            ports = [443]
        else:
            ports = [int(x) for x in ports_input.split(",")]

        resume_line = input("[?] Resume from line (0=start): ").strip()

        try:
            resume_line = int(resume_line)
        except:
            resume_line = 0

        output_file = "results.txt"
        domains = []

        with open(domain_file) as f:
            for line in f:
                d = line.strip()
                if d:
                    domains.append(d)

        total_domains = len(domains)

        if resume_line > total_domains:
            console.print("[red]✗ Resume line exceeds file length![/red]")
            input("\n[?] Press Enter to continue...")
            return

        domains = domains[resume_line:]
        total = len(domains)

        console.print("\n[bold]Code │ IP │ Server │ Host[/bold]\n")

        with open(output_file, "a") as outfile:
            with Progress(
                TextColumn("[bold cyan]SCANNING"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("scan", total=total)
                threads = []

                for _ in range(self.THREADS):
                    t = threading.Thread(
                        target=self.worker,
                        args=(ports, outfile, progress, task),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)

                for i in range(0, total, self.CHUNK_SIZE):
                    chunk = domains[i:i + self.CHUNK_SIZE]
                    for domain in chunk:
                        self.q.put(domain)

                self.q.join()

                for _ in range(self.THREADS):
                    self.q.put(None)

                for t in threads:
                    t.join()

        console.print(f"\n[green]✓ Results saved to {output_file}[/green]")
        input("\n[?] Press Enter to return to menu...")

# ================= TOOL 2: ADVANCED TCP/HTTP SCANNER =================
class AdvancedScanner:
    def __init__(self):
        self.output = "result.txt"

    def get_config(self):
        ports_str = console.input("[bold cyan]Ports (default 80,443) > [/bold cyan]").strip()
        try:
            ports = [int(x.strip()) for x in ports_str.split(",") if x.strip()]
            if not ports:
                ports = [80, 443]
        except:
            ports = [80, 443]

        threads = IntPrompt.ask("TCP Threads", default=500)
        timeout = IntPrompt.ask("TCP Timeout", default=2)

        return ports, threads, timeout

    async def run_async(self):
        clear()
        banner()
        console.print(Panel.fit(
            "⚡ NEXA Advanced Scanner\n[dim]TCP + HTTP/HTTPS HEAD + Fingerprint[/dim]",
            style="bold red",
            title="v3.3"
        ))
        
        console.print("\n[1] CIDR Scan")
        console.print("[2] IP File")
        console.print("[3] Back to Menu")
        choice = console.input("[bold cyan]Select > [/bold cyan]").strip()

        if choice == "3":
            return

        ports, threads, timeout = self.get_config()
        scanner = AdvancedScannerCore(ports, threads, timeout)

        progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
        )

        if choice == "1":
            while True:
                cidr = console.input("[bold cyan]CIDR > [/bold cyan]").strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    break
                except:
                    console.print("[red]Invalid CIDR[/red]")

            async def run():
                task_id = progress.add_task(
                    f"[cyan]{cidr} ({net.num_addresses:,} IPs)",
                    total=net.num_addresses
                )

                batch = []
                for ip in net:
                    if shutdown:
                        break

                    batch.append(str(ip))

                    if len(batch) >= 5000:
                        await asyncio.gather(*[
                            scanner.scan_ip(i, progress, task_id) for i in batch
                        ])
                        batch.clear()

                if batch:
                    await asyncio.gather(*[
                        scanner.scan_ip(i, progress, task_id) for i in batch
                    ])

            with progress:
                await run()

        elif choice == "2":
            file = console.input("[bold cyan]File > [/bold cyan]").strip()

            with progress:
                await scanner.scan_file(file, progress)

        table = Table(title="Summary")
        table.add_row("Found", str(scanner.found))
        table.add_row("Output", scanner.output)
        console.print(table)
        
        input("\n[?] Press Enter to return to menu...")

class AdvancedScannerCore:
    def __init__(self, ports, threads, timeout):
        self.ports = ports
        self.timeout = timeout
        self.sem = asyncio.Semaphore(threads)
        self.http_sem = asyncio.Semaphore(100)
        self.output = "result.txt"
        self.seen = set()
        self.found = 0
        open(self.output, "w").close()

    async def tcp_check(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def http_head(self, ip, port):
        async with self.http_sem:
            try:
                ssl_ctx = None
                if port == 443:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_ctx),
                    timeout=3
                )

                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()

                data = await asyncio.wait_for(reader.read(2048), timeout=3)
                text = data.decode(errors="ignore")

                lines = text.splitlines()
                code = None

                if lines and "HTTP" in lines[0]:
                    parts = lines[0].split()
                    if len(parts) > 1 and parts[1].isdigit():
                        code = parts[1]

                server = "Unknown"
                for line in lines:
                    low = line.lower()
                    if low.startswith("server:"):
                        server = line.split(":", 1)[1].strip()

                writer.close()
                await writer.wait_closed()
                return code, server
            except:
                return None, None

    def save(self, line):
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        with open(self.output, "a") as f:
            f.write(f"[{ts}] {line}\n")

    async def scan_ip(self, ip, progress, task_id):
        if ip in self.seen:
            progress.update(task_id, advance=1)
            return

        self.seen.add(ip)

        async with self.sem:
            for port in self.ports:
                if shutdown:
                    return

                if not await self.tcp_check(ip, port):
                    continue

                code, server = await self.http_head(ip, port)

                if code is None:
                    continue

                console.print(
                    f"[green]✓[/green] [cyan]{ip}[/cyan]:[yellow]{port}[/yellow] "
                    f"[magenta][{code}][/magenta] [blue]{server}[/blue]"
                )

                self.save(f"{ip}:{port} [{code}] {server}")
                self.found += 1
                break

        progress.update(task_id, advance=1)

    async def scan_file(self, filename, progress):
        if not os.path.isfile(filename):
            console.print(f"[red]✗ File {filename} not found![/red]")
            return
            
        total = sum(1 for _ in open(filename))
        task_id = progress.add_task(f"[cyan]{filename}", total=total)

        batch = []
        with open(filename) as f:
            for line in f:
                if shutdown:
                    break

                ip = line.strip()
                if not ip:
                    progress.update(task_id, advance=1)
                    continue

                batch.append(ip)

                if len(batch) >= 5000:
                    await asyncio.gather(*[
                        self.scan_ip(i, progress, task_id) for i in batch
                    ])
                    batch.clear()

        if batch:
            await asyncio.gather(*[
                self.scan_ip(i, progress, task_id) for i in batch
            ])

# ================= TOOL 3: CDN FINDER =================
class CDNFinder:
    def __init__(self):
        self.cdn_signatures = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cf-polished", "server: cloudflare"],
            "CloudFront": ["x-amz-cf-", "x-cache", "cloudfront"],
            "Google (sffe/esf/GFE)": ["google-frontend", "gfe", "sffe", "esf", "server: google"],
            "Fastly (varnish)": ["x-fastly-", "x-served-by", "x-cache-hits", "fastly", "varnish"],
            "Cachefly": ["x-cachefly", "cachefly"],
            "Bunny": ["x-bunny-", "bunnycdn", "bunny.net"],
            "Tengine (Alibaba)": ["server: tengine", "alibaba", "ali-cdn"],
            "Sucuri/Cloudproxy": ["x-sucuri-", "x-cloudproxy", "sucuri"],
            "Gcore": ["x-gcore", "gcdn", "gcore"],
            "Imperva": ["x-imperva-", "incapsula", "imperva"],
            "Tencent": ["x-tencent-", "tencent-cdn", "tecdn"],
        }

    def detect_cdn(self, headers):
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        detected = set()
        for cdn, patterns in self.cdn_signatures.items():
            for pattern in patterns:
                if pattern.startswith("server:"):
                    server_header = headers_lower.get("server", "")
                    if pattern[7:] in server_header:
                        detected.add(cdn)
                        break
                else:
                    for key, value in headers_lower.items():
                        if pattern in key or pattern in value:
                            detected.add(cdn)
                            break
        return list(detected) if detected else ["Unknown"]

    def run(self):
        clear()
        banner()
        console.print(Panel.fit("[bold cyan]CDN Finder[/bold cyan]\n[dim]Enter a domain to see HTTP headers and CDN provider[/dim]", style="bold cyan"))
        domain = console.input("\n[bold yellow]SNI Domain > [/bold yellow]").strip()
        if not domain:
            console.print("[red]No domain provided.[/red]")
            input("\nPress Enter to return...")
            return

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                with httpx.Client(verify=False, timeout=10, follow_redirects=False, http2=True) as client:
                    resp = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    console.print(f"\n[bold green]➤ Response from {url}[/bold green]")
                    console.print(f"[bold]Status Code:[/bold] {resp.status_code}")
                    console.print("[bold]Headers:[/bold]")
                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Header", style="cyan")
                    table.add_column("Value", style="white")
                    for k, v in resp.headers.items():
                        table.add_row(k, v)
                    console.print(table)

                    cdn = self.detect_cdn(resp.headers)
                    console.print(f"\n[bold yellow]CDN Detection:[/bold yellow] {', '.join(cdn)}")
                    break
            except Exception as e:
                console.print(f"[red]{scheme.upper()} failed: {e}[/red]")
        else:
            console.print("[red]Could not connect to the domain.[/red]")

        input("\n[?] Press Enter to return to menu...")

# ================= TOOL 4: TUNNABLE CHECKER =================
class TunableChecker:
    """
    Checks if a domain/SNI is tunable.
    Rules:
    1. Server must be in the tunable list (Cloudflare, CloudFront, Google, Fastly, Cachefly, Bunny, Tengine, Sucuri, Gcore, Imperva, Tencent)
    2. IP must NOT start with 23, 49, or 184
    BOTH conditions must be TRUE for TUNNABLE
    """
    
    def __init__(self):
        # Non-tunable IP prefixes
        self.non_tunable_prefixes = ["23.", "49.", "184."]
        
        # List of servers that CAN be tunable (if IP allows)
        self.tunable_servers = [
            "Cloudflare", "CloudFront", "Google", "Fastly", "Cachefly", 
            "Bunny", "Tengine", "Sucuri", "Gcore", "Imperva", "Tencent"
        ]
        
    def resolve_ip(self, domain):
        """Resolve domain to IP address"""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return ips[0] if ips else None
        except:
            return None
            
    def check_port(self, host, port):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def check_ports_443_8080(self, ip):
        """Check if ports 443 and 8080 are open"""
        port443 = self.check_port(ip, 443)
        port8080 = self.check_port(ip, 8080)
        return port443, port8080
        
    def detect_server(self, domain):
        """Detect CDN/Server type from HTTP response"""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                with httpx.Client(verify=False, timeout=10, follow_redirects=False, http2=True) as client:
                    resp = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                    
                    # Check server header first
                    server_header = headers_lower.get("server", "")
                    all_headers = str(headers_lower)
                    
                    # Cloudflare
                    if any(x in all_headers for x in ["cf-ray", "cf-cache-status", "cloudflare"]):
                        return "Cloudflare"
                    
                    # CloudFront
                    if any(x in all_headers for x in ["x-amz-cf", "cloudfront"]):
                        return "CloudFront"
                    
                    # Google
                    if any(x in server_header for x in ["google", "gfe", "sffe", "esf"]):
                        if "sffe" in server_header:
                            return "Google (sffe)"
                        elif "esf" in server_header:
                            return "Google (esf)"
                        elif "gfe" in server_header:
                            return "Google (GFE)"
                        return "Google"
                    
                    # Fastly
                    if any(x in all_headers for x in ["x-fastly", "fastly", "varnish"]):
                        return "Fastly (varnish)"
                    
                    # Cachefly
                    if "cachefly" in all_headers:
                        return "Cachefly"
                    
                    # Bunny
                    if any(x in all_headers for x in ["x-bunny", "bunnycdn"]):
                        return "Bunny"
                    
                    # Tengine
                    if "tengine" in server_header or "alibaba" in all_headers:
                        return "Tengine (Alibaba)"
                    
                    # Sucuri
                    if any(x in all_headers for x in ["x-sucuri", "sucuri"]):
                        return "Sucuri/Cloudproxy"
                    
                    # Gcore
                    if any(x in all_headers for x in ["x-gcore", "gcdn"]):
                        return "Gcore"
                    
                    # Imperva
                    if any(x in all_headers for x in ["x-imperva", "incapsula"]):
                        return "Imperva"
                    
                    # Tencent
                    if any(x in all_headers for x in ["x-tencent", "tencent-cdn"]):
                        return "Tencent"
                    
                    return "Unknown Server"
            except Exception as e:
                continue
        return "Unknown (No Response)"
        
    def is_tunable(self, ip, server_type):
        """
        Determine if the target is tunable.
        BOTH conditions must be TRUE:
        1. Server is in tunable_servers list
        2. IP does NOT start with 23, 49, or 184
        """
        # Check if server is in tunable list
        server_tunable = False
        matched_server = None
        
        for tunable in self.tunable_servers:
            if tunable.lower() in server_type.lower():
                server_tunable = True
                matched_server = tunable
                break
        
        if not server_tunable:
            return False, f"Server '{server_type}' is not in tunable list", None
        
        # Check IP prefix
        if ip:
            for prefix in self.non_tunable_prefixes:
                if ip.startswith(prefix):
                    return False, f"IP {ip} starts with {prefix} (non-tunable range)", matched_server
        
        # Both conditions passed
        return True, f"Server '{matched_server}' is tunable AND IP {ip} not in non-tunable ranges", matched_server
        
    def get_ssh_payload(self, domain, server_type):
        """Generate SSH payload for tunable targets"""
        payloads = {
            "Cloudflare": f"""# SSH Payload for {domain} (Cloudflare - TUNNABLE)
# Best method: WebSocket with Cloudflare headers

GET / HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
CF-Connecting-IP: 127.0.0.1
CF-IPCountry: US
CF-Ray: tunnel-request

# Alternative CONNECT method:
CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1
CF-Worker: tunnel

# Recommended ports: 443, 8080, 2053, 2096, 2087, 2083
""",
            "CloudFront": f"""# SSH Payload for {domain} (CloudFront - TUNNABLE)
# Best with: HTTP/2 + CloudFront headers

:method: CONNECT
:authority: {domain}
:scheme: https
x-amz-cf-id: tunnel-request
cloudfront-forwarded-proto: https
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

# WebSocket method:
GET / HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
Sec-WebSocket-Version: 13
Origin: https://{domain}

# Recommended ports: 443, 8080
""",
            "Google": f"""# SSH Payload for {domain} (Google - TUNNABLE)
# High success rate with HTTP/2

# Method 1: HTTP/2 CONNECT
:method: CONNECT
:authority: {domain}
:scheme: https
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
x-forwarded-for: 8.8.8.8
x-client-data: tunnel

# Method 2: WebSocket Upgrade
GET / HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://{domain}

# Recommended ports: 443, 8080
""",
            "Fastly": f"""# SSH Payload for {domain} (Fastly/Varnish - TUNNABLE)
# Works well with host header spoofing

CONNECT {domain}:443 HTTP/1.1
Host: {domain}
Fastly-Client-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Orig-IP: 127.0.0.1
X-Tunnel: true
User-Agent: Mozilla/5.0 (X11; Linux x86_64)

# WebSocket method:
GET /ws HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# Recommended ports: 443, 8080
""",
            "Bunny": f"""# SSH Payload for {domain} (Bunny CDN - TUNNABLE)
# Good for WebSocket tunneling

CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
x-bunny-request-id: tunnel123
x-bunny-tunnel: true

# WebSocket method:
GET / HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://{domain}

# Recommended ports: 443, 8080
""",
            "Tengine": f"""# SSH Payload for {domain} (Tengine/Alibaba - TUNNABLE)
# Works with X-Forwarded headers

CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 10.0.0.1
X-Real-IP: 10.0.0.1
X-Client-IP: 10.0.0.1
X-Tengine-Tunnel: true
User-Agent: AlibabaCloud (Linux)

# Alternative:
GET / HTTP/1.1
Host: {domain}
X-Forwarded-Host: {domain}
X-Orig-Host: {domain}

# Recommended ports: 443, 8080, 80
""",
            "Sucuri": f"""# SSH Payload for {domain} (Sucuri/Cloudproxy - TUNNABLE)
# May require specific headers

CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Sucuri-ClientIP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Cloudproxy-Tunnel: true
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

# Recommended ports: 443, 8080
""",
            "Gcore": f"""# SSH Payload for {domain} (Gcore - TUNNABLE)
CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1
X-Gcore-Tunnel: true
User-Agent: Mozilla/5.0

# Recommended ports: 443, 8080
""",
            "Imperva": f"""# SSH Payload for {domain} (Imperva - TUNNABLE)
CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1
X-Imperva-Tunnel: true
X-CDN: Imperva
User-Agent: Mozilla/5.0

# Recommended ports: 443, 8080
""",
            "Cachefly": f"""# SSH Payload for {domain} (Cachefly - TUNNABLE)
CONNECT {domain}:443 HTTP/1.1
Host: {domain}
X-Forwarded-For: 127.0.0.1
X-Cachefly-Tunnel: true
User-Agent: Mozilla/5.0

# Recommended ports: 443, 8080
"""
        }
        
        # Check for specific matches
        for key in payloads:
            if key.lower() in server_type.lower():
                return payloads[key]
                
        # Generic payload for other tunable servers
        return f"""# SSH Payload for {domain} ({server_type})
# Generic payload - Test different methods

# Method 1: Standard CONNECT
CONNECT {domain}:443 HTTP/1.1
Host: {domain}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
X-Forwarded-For: 127.0.0.1
Connection: keep-alive

# Method 2: WebSocket upgrade
GET / HTTP/1.1
Host: {domain}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

# Method 3: HTTP/2 with PRI
PRI * HTTP/2.0
Host: {domain}

# Recommended ports: 443, 8080, 80
"""
        
    def get_protocols(self, ip, domain):
        """Determine which protocols work"""
        protocols = []
        
        # Check HTTPS
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                resp = client.get(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code < 500:
                    protocols.append("HTTPS (Working)")
        except:
            pass
            
        # Check HTTP
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                resp = client.get(f"http://{domain}", headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code < 500:
                    protocols.append("HTTP (Working)")
        except:
            pass
            
        # Check if ports are open
        port443, port8080 = self.check_ports_443_8080(ip)
        if port443:
            protocols.append("Port 443 (Open)")
        if port8080:
            protocols.append("Port 8080 (Open)")
            
        return protocols
        
    def run(self):
        clear()
        banner()
        console.print(Panel.fit(
            "[bold yellow]Tunable Checker v3.0 (FINAL)[/bold yellow]\n[dim]Check if a domain/SNI is tunable for SSH tunneling[/dim]",
            style="bold yellow"
        ))
        
        console.print("[dim]Tunable Servers: Cloudflare, CloudFront, Google, Fastly, Cachefly, Bunny, Tengine, Sucuri, Gcore, Imperva, Tencent[/dim]\n")
        
        domain = console.input("\n[bold cyan]Enter SNI Host/Domain > [/bold cyan]").strip()
        
        if not domain:
            console.print("[red]No domain provided![/red]")
            input("\nPress Enter to return...")
            return
            
        console.print(f"\n[bold blue]🔍 Checking: {domain}[/bold blue]\n")
        
        # Step 1: Resolve IP
        console.print("[yellow]→ Resolving IP address...[/yellow]")
        ip = self.resolve_ip(domain)
        
        if ip:
            console.print(f"[green]✓ IP Address: {ip}[/green]")
        else:
            console.print("[red]✗ Could not resolve domain![/red]")
            input("\nPress Enter to return...")
            return
            
        # Step 2: Detect server type
        console.print("[yellow]→ Detecting server/CDN type...[/yellow]")
        server_type = self.detect_server(domain)
        console.print(f"[cyan]✓ Server Type: {server_type}[/cyan]")
        
        # Step 3: Check ports
        console.print("[yellow]→ Checking ports 443 & 8080...[/yellow]")
        port443, port8080 = self.check_ports_443_8080(ip)
        
        port_status = []
        if port443:
            port_status.append("[green]✓ Port 443: OPEN[/green]")
        else:
            port_status.append("[red]✗ Port 443: CLOSED[/red]")
            
        if port8080:
            port_status.append("[green]✓ Port 8080: OPEN[/green]")
        else:
            port_status.append("[red]✗ Port 8080: CLOSED[/red]")
            
        for status in port_status:
            console.print(f"  {status}")
            
        # Step 4: Check if tunable (BOTH conditions)
        console.print("[yellow]→ Checking tunability (Server + IP conditions)...[/yellow]")
        is_tunable, reason, matched_server = self.is_tunable(ip, server_type)
        
        console.print("")
        if is_tunable:
            console.print(f"[bold green]╔════════════════════════════════════════╗[/bold green]")
            console.print(f"[bold green]║     ✓ STATUS: TUNNABLE ✓               ║[/bold green]")
            console.print(f"[bold green]╚════════════════════════════════════════╝[/bold green]")
            console.print(f"\n[green]✓ Reason: {reason}[/green]")
        else:
            console.print(f"[bold red]╔════════════════════════════════════════╗[/bold red]")
            console.print(f"[bold red]║     ✗ STATUS: NON-TUNNABLE ✗           ║[/bold red]")
            console.print(f"[bold red]╚════════════════════════════════════════╝[/bold red]")
            console.print(f"\n[red]✗ Reason: {reason}[/red]")
            
        # Step 5: Get protocols
        console.print("\n[yellow]→ Checking available protocols...[/yellow]")
        protocols = self.get_protocols(ip, domain)
        
        if protocols:
            console.print("[green]✓ Available protocols/ports:[/green]")
            for proto in protocols:
                console.print(f"  • {proto}")
        else:
            console.print("[red]✗ No working protocols detected![/red]")
            
        # Step 6: Show SSH payload if tunable
        if is_tunable:
            console.print("\n[bold green]" + "="*70 + "[/bold green]")
            console.print("[bold yellow]⚡ SSH PAYLOAD FOR TUNNELING ⚡[/bold yellow]")
            console.print("[bold green]" + "="*70 + "[/bold green]")
            
            payload = self.get_ssh_payload(domain, server_type)
            if payload:
                console.print(Panel(payload, title=f"[bold cyan]Payload for {matched_server}[/bold cyan]", border_style="green", width=100))
                
            console.print("\n[bold cyan]💡 Usage Tips:[/bold cyan]")
            console.print("  1. Use with tools like: httpx-tunnel, proxychains, stunnel, or custom scripts")
            console.print("  2. Test different payload methods (CONNECT, WebSocket, HTTP/2)")
            console.print("  3. Try both ports 443 and 8080 if available")
            console.print("  4. Some servers may require specific User-Agent or headers")
            console.print(f"  5. Server: {matched_server} | IP: {ip} | Status: TUNNABLE")
            console.print("\n[bold yellow]📌 Quick Commands:[/bold yellow]")
            console.print(f"  # Test with curl:")
            console.print(f"  curl -x http://{domain}:443 https://api.ipify.org -H 'Host: {domain}'")
            console.print(f"\n  # Test with httpx-tunnel:")
            console.print(f"  httpx-tunnel -s {domain}:443 -p 8888")
        else:
            console.print("\n[yellow]⚠️ Target is non-tunable. No SSH payload generated.[/yellow]")
            console.print(f"[dim]Why? {reason}[/dim]")
            
        # Step 7: Save results
        result_line = f"{domain} | {ip} | {server_type} | {'TUNNABLE' if is_tunable else 'NON-TUNNABLE'} | {reason}\n"
        with open("tunable_results.txt", "a") as f:
            f.write(result_line)
            
        console.print(f"\n[green]✓ Results saved to tunable_results.txt[/green]")
        input("\n[?] Press Enter to return to menu...")

# ================= TOOL 5: SUBDOMAIN FINDER =================
class SubdomainFinder:
    def __init__(self):
        self.threads = 100
        self.timeout = 3
        self.q = Queue()
        self.lock = threading.Lock()
        self.found_subdomains = []
        
    def resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP address"""
        try:
            ip = socket.gethostbyname(subdomain)
            return ip
        except:
            return None
            
    def check_subdomain(self, subdomain, domain, output_file, progress, task):
        """Check if subdomain is valid"""
        full_domain = f"{subdomain}.{domain}"
        ip = self.resolve_subdomain(full_domain)
        
        if ip:
            result = f"{full_domain} -> {ip}"
            with self.lock:
                self.found_subdomains.append(full_domain)
                console.print(f"[green]✓[/green] [cyan]{full_domain}[/cyan] [yellow]->[/yellow] [magenta]{ip}[/magenta]")
                output_file.write(result + "\n")
                output_file.flush()
        
        progress.update(task, advance=1)
        
    def worker(self, domain, output_file, progress, task):
        while True:
            subdomain = self.q.get()
            if subdomain is None:
                break
            self.check_subdomain(subdomain, domain, output_file, progress, task)
            self.q.task_done()
            
    def scan_single_domain(self):
        """Scan subdomains for a single domain"""
        clear()
        console.print(Panel.fit("[bold cyan]SUBDOMAIN FINDER - Single Domain[/bold cyan]", style="bold cyan"))
        
        domain = console.input("\n[bold yellow]Enter target domain (e.g., example.com): [/bold yellow]").strip()
        
        if not domain:
            console.print("[red]✗ No domain provided![/red]")
            input("\nPress Enter to return...")
            return
            
        wordlist_file = console.input("[bold yellow]Enter wordlist file path: [/bold yellow]").strip()
        
        if not os.path.isfile(wordlist_file):
            console.print(f"[red]✗ Wordlist file '{wordlist_file}' not found![/red]")
            input("\nPress Enter to return...")
            return
            
        output_file = console.input("[bold yellow]Output file name (default: subdomains.txt): [/bold yellow]").strip()
        if not output_file:
            output_file = "subdomains.txt"
            
        threads_input = console.input("[bold yellow]Threads (default 100): [/bold yellow]").strip()
        if threads_input:
            try:
                self.threads = int(threads_input)
            except:
                pass
                
        # Load wordlist
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
            
        total = len(wordlist)
        console.print(f"\n[green]✓ Loaded {total} subdomain entries[/green]")
        console.print(f"[green]✓ Checking subdomains for: {domain}[/green]")
        console.print(f"[green]✓ Using {self.threads} threads[/green]\n")
        
        # Create output file with header
        with open(output_file, 'w') as f:
            f.write(f"# Subdomain scan results for {domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" + "="*50 + "\n\n")
            
        # Start scanning
        with open(output_file, 'a') as outfile:
            with Progress(
                TextColumn("[bold cyan]SCANNING SUBDOMAINS"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {domain}", total=total)
                
                # Start worker threads
                threads = []
                for _ in range(self.threads):
                    t = threading.Thread(
                        target=self.worker,
                        args=(domain, outfile, progress, task),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)
                    
                # Add subdomains to queue
                for sub in wordlist:
                    if shutdown:
                        break
                    self.q.put(sub)
                    
                # Wait for all tasks to complete
                self.q.join()
                
                # Stop workers
                for _ in range(self.threads):
                    self.q.put(None)
                    
                for t in threads:
                    t.join()
                    
        console.print(f"\n[bold green]✓ Scan completed![/bold green]")
        console.print(f"[green]✓ Found {len(self.found_subdomains)} valid subdomains[/green]")
        console.print(f"[green]✓ Results saved to {output_file}[/green]")
        
        if self.found_subdomains:
            console.print("\n[bold yellow]📋 Found Subdomains:[/bold yellow]")
            for sub in self.found_subdomains[:20]:  # Show first 20
                console.print(f"  • {sub}")
            if len(self.found_subdomains) > 20:
                console.print(f"  ... and {len(self.found_subdomains) - 20} more")
                
        input("\n[?] Press Enter to return to menu...")
        
    def scan_bulk_domains(self):
        """Scan subdomains for multiple domains from a file"""
        clear()
        console.print(Panel.fit("[bold cyan]SUBDOMAIN FINDER - Bulk Domains[/bold cyan]", style="bold cyan"))
        
        domain_file = console.input("[bold yellow]Enter domain list file: [/bold yellow]").strip()
        
        if not os.path.isfile(domain_file):
            console.print(f"[red]✗ Domain file '{domain_file}' not found![/red]")
            input("\nPress Enter to return...")
            return
            
        wordlist_file = console.input("[bold yellow]Enter wordlist file path: [/bold yellow]").strip()
        
        if not os.path.isfile(wordlist_file):
            console.print(f"[red]✗ Wordlist file '{wordlist_file}' not found![/red]")
            input("\nPress Enter to return...")
            return
            
        output_file = console.input("[bold yellow]Output file name (default: bulk_subdomains.txt): [/bold yellow]").strip()
        if not output_file:
            output_file = "bulk_subdomains.txt"
            
        threads_input = console.input("[bold yellow]Threads per domain (default 100): [/bold yellow]").strip()
        if threads_input:
            try:
                self.threads = int(threads_input)
            except:
                pass
                
        # Load domains
        with open(domain_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            
        # Load wordlist
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
            
        total_checks = len(domains) * len(wordlist)
        console.print(f"\n[green]✓ Loaded {len(domains)} domains[/green]")
        console.print(f"[green]✓ Loaded {len(wordlist)} subdomain entries[/green]")
        console.print(f"[green]✓ Total checks: {total_checks:,}[/green]")
        console.print(f"[green]✓ Using {self.threads} threads per domain[/green]\n")
        
        # Create output file with header
        with open(output_file, 'w') as f:
            f.write(f"# Bulk subdomain scan results\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Domains: {len(domains)} | Wordlist: {len(wordlist)}\n")
            f.write("#" + "="*50 + "\n\n")
            
        total_found = 0
        
        # Scan each domain
        for idx, domain in enumerate(domains, 1):
            if shutdown:
                break
                
            console.print(f"\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
            console.print(f"[bold yellow]Scanning domain {idx}/{len(domains)}: {domain}[/bold yellow]")
            console.print(f"[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
            
            self.found_subdomains = []
            
            with open(output_file, 'a') as outfile:
                outfile.write(f"\n# Results for {domain}\n")
                outfile.write("#" + "-"*40 + "\n")
                
                with Progress(
                    TextColumn(f"[cyan]Scanning {domain}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(f"[cyan]{domain}", total=len(wordlist))
                    
                    # Reset queue
                    self.q = Queue()
                    
                    # Start worker threads
                    threads = []
                    for _ in range(self.threads):
                        t = threading.Thread(
                            target=self.worker,
                            args=(domain, outfile, progress, task),
                            daemon=True
                        )
                        t.start()
                        threads.append(t)
                        
                    # Add subdomains to queue
                    for sub in wordlist:
                        if shutdown:
                            break
                        self.q.put(sub)
                        
                    # Wait for all tasks to complete
                    self.q.join()
                    
                    # Stop workers
                    for _ in range(self.threads):
                        self.q.put(None)
                        
                    for t in threads:
                        t.join()
                        
            console.print(f"[green]✓ Found {len(self.found_subdomains)} subdomains for {domain}[/green]")
            total_found += len(self.found_subdomains)
            
            with open(output_file, 'a') as outfile:
                outfile.write(f"\nTotal found for {domain}: {len(self.found_subdomains)}\n")
                outfile.write("#" + "-"*40 + "\n")
                
        console.print(f"\n[bold green]╔════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║     ✓ BULK SCAN COMPLETED ✓            ║[/bold green]")
        console.print(f"[bold green]╚════════════════════════════════════════╝[/bold green]")
        console.print(f"\n[green]✓ Total domains scanned: {len(domains)}[/green]")
        console.print(f"[green]✓ Total subdomains found: {total_found}[/green]")
        console.print(f"[green]✓ Results saved to {output_file}[/green]")
        
        input("\n[?] Press Enter to return to menu...")
        
    def run(self):
        """Main subdomain finder menu"""
        while True:
            clear()
            banner()
            console.print(Panel.fit(
                "[bold cyan]SUBDOMAIN FINDER[/bold cyan]\n[dim]Discover subdomains using wordlist[/dim]",
                style="bold cyan"
            ))
            
            console.print("\n[bold yellow]╔════════════════════════════════════╗[/bold yellow]")
            console.print("[bold yellow]║     SUBDOMAIN SCAN OPTIONS         ║[/bold yellow]")
            console.print("[bold yellow]╠════════════════════════════════════╣[/bold yellow]")
            console.print("[bold yellow]║  [1] Single Domain Scan            ║[/bold yellow]")
            console.print("[bold yellow]║  [2] Bulk Domains Scan             ║[/bold yellow]")
            console.print("[bold yellow]║  [3] Back to Main Menu             ║[/bold yellow]")
            console.print("[bold yellow]╚════════════════════════════════════╝[/bold yellow]")
            
            choice = console.input("[bold cyan]➤ Choose option: [/bold cyan]").strip()
            
            if choice == "1":
                self.scan_single_domain()
            elif choice == "2":
                self.scan_bulk_domains()
            elif choice == "3":
                break
            else:
                console.print("[red]Invalid option![/red]")
                input("\nPress Enter to continue...")

# ================= MAIN =================
def main():
    while True:
        clear()
        banner()
        choice = main_menu()
        
        if choice == "1":
            scanner1 = DomainScanner()
            scanner1.run()
        elif choice == "2":
            scanner2 = AdvancedScanner()
            asyncio.run(scanner2.run_async())
        elif choice == "3":
            cdn_finder = CDNFinder()
            cdn_finder.run()
        elif choice == "4":
            tunable_checker = TunableChecker()
            tunable_checker.run()
        elif choice == "5":
            subdomain_finder = SubdomainFinder()
            subdomain_finder.run()
        elif choice == "6":
            clear()
            console.print("\n[red]Exiting... Goodbye![/red]")
            break
        else:
            console.print("\n[red]Invalid option! Please choose 1, 2, 3, 4, 5, or 6[/red]")
            input("\n[?] Press Enter to continue...")

if __name__ == "__main__":
    main()
