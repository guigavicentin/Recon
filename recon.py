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

"===== Domínio Checker =====",
"### Analisador de Domínios ###",
"--- Verificação de Domínios ---",

    """
@@@@@%+..........................................................................+%@@@@@@
@@@@#-...............................:-=+*##*+==:.................................-#@@@@@
@@%=................................+@@@@@@@@@@@@#..................................+%@@@
@#:................................-%@@@@@@@@@@@@@=..................................-#@@
*..................................%@@@@@@@@@@@@@@%....................................#@
..................................=%@@@@@@@@@@@@@@@+....................................#
..........................:-==+**+=---=+*#%%#*+=---=+**+==--.............................
...........................:=*#%@@@@@%%#*+=-+*#%@@@@@@@%*=-..............................
................................-+%@@@@@@@@@@@@@@@@%+-:..................................
..................................:%@@@@@@@@@@@@@@@-.....................................
...................................=@@@@@@@@@@@@@@*......................................
....................................*@@@@@@@@@@@@%.......................................
:-=++=-..............................+%@@@@@@@@%+:...............................-=++=-:.
@@@@@@@%*-.............................-+%@@%*-...............................-*%@@@@@@@#
.......=@@*...............................==................................:#@@@:....%@@
..@@@..=@@@+........................:-...-@@*...--:.........................*@@@@*+:..%@@
..@@@..=@@@#..................:-+*%@@@*...*%...+@@@%#+=-....................%@@@@@@-..%@@
..@@@..=@@@*..............=*#%@@@@@@@@@=..+%..:%@@@@@@@@@%#*=:..............*@@@@@@-..%@@
.......=@@#..............*@@@@@@@@@@@@@%:.#@-.%@@@@@@@@@@@@@@%:.............:%@@@@@-..%@@
%%%%%%%%#=..............*@@@@@@@@@@@@@@@#:%@+#@@@@@@@@@@@@@@@@%:..............=#@@@%%%@@%
-=+**+=:...............=@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@*................:=+**+=-.
....:-................:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.................-......
.+-.:%+..............:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=..............=%+.:+:..
.#@%#%@%-............#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-...........:#@@#%@@:..
.+%@@@@@@#+=-:......*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.......-=+*%@@@@@%*...
...:=#%@@@@@@@@%#*+*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+*##%@@@@@@@@%+-.....
.......=@@@@@@@@@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@*:........
.......-@@@@@@@@@@@@@@@@@%+.-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.=%@@@@@@@@@@@@@@@@@+.........
........:-+*#%@@@@@@@@@@%-...%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%..:*@@@@@@@@@@%%*+=-.........:
..............:-=+*#%%@+.....#@@@@@@@@@@@@@@@@@@@@@@@@@@@@*....=%@%#*+=-:..............:%
%-....................:......+%%%%%%%%%%%%%%%%%%%%%%%%%%%%=...........................-%@
@%+..................................................................................*%@@
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

    subs1=run(f"subfinder -d {domain} -silent")

    subs2=run(f"assetfinder --subs-only {domain}")

    subs=set((subs1+"\n"+subs2).splitlines())

    open("subdomains.txt","w").write("\n".join(subs))


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
# WHATWEB
# -------------------------

def run_whatweb():

    print("[+] Fingerprint com WhatWeb")

    urls=[l.split()[0].strip() for l in open("alive.txt").readlines()]

    results=[]

    for u in urls:

        try:

            r=run(f"whatweb --color=never {u}")

            if r:
                results.append(r)

        except:
            pass

    if not results:
        results.append("Nenhuma tecnologia identificada")

    open("whatweb.txt","w").write("\n".join(results))


# -------------------------
# PORTSCAN
# -------------------------

def portscan():

    print("[+] Scan de portas")

    run(f"nmap -p {PORTS} -iL subdomains.txt --open -oN ports.txt")


# -------------------------
# HTTP METHODS (PASSIVE)
# -------------------------

def check_methods(url):

    try:

        r=requests.options(url,timeout=5)

        findings=[]

        if "Allow" in r.headers:

            allow=r.headers["Allow"]

            interesting=[]

            for m in ["PUT","DELETE","TRACE","CONNECT","PATCH","PROPFIND"]:

                if m in allow:

                    interesting.append(m)

            if interesting:

                findings.append(f"{url} -> {', '.join(interesting)} (via OPTIONS)")

        if "DAV" in r.headers or "MS-Author-Via" in r.headers:

            findings.append(f"{url} -> WebDAV possivelmente habilitado")

        return findings

    except:
        pass


def test_methods():

    print("[+] Identificando métodos HTTP via OPTIONS")

    urls=[l.split()[0].strip() for l in open("alive.txt").readlines()]

    results=[]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as exe:

        futures=[exe.submit(check_methods,u) for u in urls]

        for f in concurrent.futures.as_completed(futures):

            r=f.result()

            if r:

                results.extend(r)

    if not results:

        results.append("Nenhum método interessante identificado")

    open("methods.txt","w").write("\n".join(results))


# -------------------------
# CORS
# -------------------------

def detect_cors():

    print("[+] Detectando CORS")

    urls=[l.split()[0].strip() for l in open("alive.txt").readlines()]

    results=[]

    for u in urls:

        try:

            r=requests.get(

                u,

                headers={"Origin":"https://evil.com"},

                timeout=5

            )

            origin=r.headers.get("Access-Control-Allow-Origin","")

            creds=r.headers.get("Access-Control-Allow-Credentials","")

            if origin:

                if origin=="*":

                    results.append(f"CORS WILDCARD -> {u}")

                elif "evil.com" in origin:

                    if creds.lower()=="true":

                        results.append(f"CORS CRITICAL (Credentials Enabled) -> {u}")

                    else:

                        results.append(f"CORS REFLECTION -> {u}")

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

    urls=[l.split()[0].strip() for l in open("alive.txt").readlines()]

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

    urls=[l.split()[0].strip() for l in open("alive.txt").readlines()]

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

    results = []

    # SPF
    spf_found = False
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")

        for record in txt_records:
            record_text = str(record).replace('"', '').lower()

            if record_text.startswith("v=spf1"):
                spf_found = True

                if "+all" in record_text:
                    results.append("SPF vulnerável: '+all' permite qualquer servidor enviar e-mails.")
                elif "?all" in record_text:
                    results.append("SPF fraco: '?all' é permissivo.")
                elif "~all" in record_text:
                    results.append("SPF configurado com '~all' (softfail).")
                elif "-all" in record_text:
                    results.append("SPF configurado com '-all' (mais rígido).")
                else:
                    results.append("SPF encontrado, mas sem mecanismo final claro.")
                break

        if not spf_found:
            results.append("SPF não encontrado.")

    except dns.resolver.NoAnswer:
        results.append("SPF não encontrado (NoAnswer).")
    except dns.resolver.NXDOMAIN:
        results.append("Domínio não encontrado ao consultar SPF.")
    except dns.resolver.Timeout:
        results.append("Timeout ao consultar SPF.")
    except Exception as e:
        results.append(f"Erro ao consultar SPF: {e}")

    # DMARC
    dmarc_found = False
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")

        for record in dmarc_records:
            record_text = str(record).replace('"', '').lower()

            if record_text.startswith("v=dmarc1"):
                dmarc_found = True

                if "p=reject" in record_text:
                    results.append("DMARC configurado com 'p=reject' (política forte).")
                elif "p=quarantine" in record_text:
                    results.append("DMARC configurado com 'p=quarantine' (política intermediária).")
                elif "p=none" in record_text:
                    results.append("DMARC configurado com 'p=none' (somente monitoramento).")
                else:
                    results.append("DMARC encontrado, mas política não identificada claramente.")
                break

        if not dmarc_found:
            results.append("DMARC não encontrado.")

    except dns.resolver.NoAnswer:
        results.append("DMARC não encontrado (NoAnswer).")
    except dns.resolver.NXDOMAIN:
        results.append("DMARC não encontrado (NXDOMAIN).")
    except dns.resolver.Timeout:
        results.append("Timeout ao consultar DMARC.")
    except Exception as e:
        results.append(f"Erro ao consultar DMARC: {e}")

    if spf_found and dmarc_found:
        results.append("O domínio possui SPF e DMARC configurados, mas isso não garante proteção total contra spoofing.")
    else:
        results.append("O domínio possui proteção parcial ou ausente contra spoofing de e-mail.")

    # Salva resultado
    with open("mail_spoof.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(results))

    return results


# -------------------------
# NUCLEI
# -------------------------

def run_nuclei():

    print("[+] Rodando nuclei")

    run("cat alive.txt | awk '{print $1}' | nuclei -severity critical,high,medium -o nuclei.txt")

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

    run_whatweb()

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
