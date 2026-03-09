#!/usr/bin/env python3

import subprocess
import argparse
import random
import concurrent.futures
import requests
import os
import dns.resolver

PORTS="80,81,443,3000,8000,8001,8080,8081,8443,8888,9000"

banners=[

"""
===== Domínio Checker =====
""",

"""
### Analisador de Domínios ###
""",

"""
--- Verificação de Domínios ---
"""
]


def banner():

    print(random.choice(banners))


def run(cmd):

    result=subprocess.run(cmd,shell=True,capture_output=True,text=True)

    return result.stdout.strip()


# -------------------------
# SUBDOMAIN ENUM
# -------------------------

def enum_subdomains(domain):

    print("[+] Enumerando subdomínios")

    subs=run(f"subfinder -d {domain} -silent")

    open("subdomains.txt","w").write(subs)


# -------------------------
# HTTP DISCOVERY
# -------------------------

def http_discovery():

    print("[+] Descobrindo hosts HTTP")

    alive=run(
        f"cat subdomains.txt | httpx -silent -title -tech-detect -status-code -ports {PORTS}"
    )

    open("alive.txt","w").write(alive)


# -------------------------
# PORTSCAN
# -------------------------

def portscan():

    print("[+] Scan de portas")

    run(f"nmap -p {PORTS} -iL subdomains.txt --open -oN ports.txt")


# -------------------------
# HTTP METHODS
# -------------------------

def check_method(url,method):

    try:

        r=requests.request(method,url,timeout=5)

        if r.status_code not in [403,405,501]:

            return f"{url} -> {method} ENABLED ({r.status_code})"

    except:
        pass


def test_methods():

    print("[+] Testando TRACE PUT DELETE")

    urls=[l.split()[0] for l in open("alive.txt")]

    results=[]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as exe:

        futures=[]

        for u in urls:

            for m in ["TRACE","PUT","DELETE"]:

                futures.append(exe.submit(check_method,u,m))

        for f in concurrent.futures.as_completed(futures):

            r=f.result()

            if r:
                results.append(r)

    open("methods.txt","w").write("\n".join(results))


# -------------------------
# CORS
# -------------------------

def detect_cors():

    print("[+] Detectando CORS")

    urls=[l.split()[0] for l in open("alive.txt")]

    results=[]

    for u in urls:

        try:

            r=requests.get(u,headers={"Origin":"evil.com"},timeout=5)

            if "Access-Control-Allow-Origin" in r.headers:

                if r.headers["Access-Control-Allow-Origin"]=="*" or "evil.com" in r.headers["Access-Control-Allow-Origin"]:

                    results.append(f"CORS POSSIVEL -> {u}")

        except:
            pass

    if not results:

        results.append("Nenhum CORS detectado")

    open("cors.txt","w").write("\n".join(results))


# -------------------------
# CLICKJACKING
# -------------------------

def check_clickjacking():

    print("[+] Testando Clickjacking")

    urls=[l.split()[0] for l in open("alive.txt")]

    vulns=[]

    for u in urls:

        try:

            r=requests.get(u,timeout=5)

            if "X-Frame-Options" not in r.headers and "Content-Security-Policy" not in r.headers:

                vulns.append(f"Clickjacking possível -> {u}")

        except:
            pass

    if not vulns:

        vulns.append("Nenhum clickjacking detectado")

    open("clickjacking.txt","w").write("\n".join(vulns))


# -------------------------
# EXPOSED FILES
# -------------------------

def detect_exposed():

    print("[+] Detectando .git e .env")

    urls=[l.split()[0] for l in open("alive.txt")]

    vulns=[]

    for u in urls:

        for f in ["/.git/config","/.env"]:

            try:

                r=requests.get(u+f,timeout=5)

                if r.status_code==200:

                    vulns.append(u+f)

            except:
                pass

    if not vulns:

        vulns.append("Nenhum arquivo exposto")

    open("exposed.txt","w").write("\n".join(vulns))


# -------------------------
# TAKEOVER
# -------------------------

def detect_takeover():

    print("[+] Detectando takeover")

    run("subjack -w subdomains.txt -t 50 -timeout 30 -ssl -o takeover.txt")

    if not os.path.exists("takeover.txt") or os.stat("takeover.txt").st_size==0:

        open("takeover.txt","w").write("Nenhum takeover encontrado\n")


# -------------------------
# MAIL SPOOFING
# -------------------------

def check_mail_spoof(domain):

    print("[+] Verificando Mail Spoofing")

    results=[]

    try:

        spf=dns.resolver.resolve(domain,'TXT')

        found=False

        for r in spf:

            if "spf1" in str(r):

                found=True

        if not found:

            results.append("SPF não encontrado")

    except:

        results.append("SPF não encontrado")

    try:

        dns.resolver.resolve("_dmarc."+domain,'TXT')

    except:

        results.append("DMARC não encontrado")

    if not results:

        results.append("Proteção de email configurada")

    open("mail_spoof.txt","w").write("\n".join(results))


# -------------------------
# NUCLEI
# -------------------------

def run_nuclei():

    print("[+] Rodando nuclei")

    run("cat alive.txt | nuclei -severity critical,high,medium -o nuclei.txt")

    if not os.path.exists("nuclei.txt") or os.stat("nuclei.txt").st_size==0:

        open("nuclei.txt","w").write("Nenhuma vulnerabilidade encontrada\n")


# -------------------------
# MAIN
# -------------------------

def main():

    banner()

    parser=argparse.ArgumentParser(
        description="Recon Framework - Automação de análise de vulnerabilidade"
    )

    parser.add_argument(
        "-d","--domain",
        required=True,
        help="Domínio alvo"
    )

    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="Não executar nuclei"
    )

    parser.add_argument(
        "--no-portscan",
        action="store_true",
        help="Não executar scan de portas"
    )

    args=parser.parse_args()

    enum_subdomains(args.domain)

    http_discovery()

    if not args.no_portscan:

        portscan()

    test_methods()

    detect_cors()

    check_clickjacking()

    detect_exposed()

    detect_takeover()

    check_mail_spoof(args.domain)

    if not args.no_nuclei:

        run_nuclei()

    print("\n[+] Scan finalizado")


if __name__=="__main__":

    main()
