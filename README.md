# 🔎 Recon & Vulnerability Automation Tool

Uma ferramenta em **Python** para **automação de reconhecimento e análise inicial de vulnerabilidades em domínios**.

O objetivo do projeto é agilizar tarefas comuns de **recon e pentest**, integrando diversas ferramentas conhecidas em um único fluxo automatizado.

A ferramenta realiza:

* Enumeração de subdomínios
* Descoberta de serviços HTTP
* Portscan de portas web comuns
* Teste de métodos HTTP perigosos
* Detecção de CORS mal configurado
* Teste de Clickjacking
* Detecção de arquivos sensíveis expostos
* Verificação de Subdomain Takeover
* Análise de configuração de e-mail (SPF / DMARC)
* Scan automático de vulnerabilidades

---

# ⚙️ Ferramentas utilizadas

Este projeto integra várias ferramentas amplamente utilizadas na área de segurança:

* Subfinder
* httpx
* Nmap
* Nuclei
* Subjack

Essas ferramentas precisam estar instaladas no sistema para o funcionamento correto.

---

# 📦 Instalação

Clone o repositório:

```bash
git clone https://github.com/seuusuario/recon-framework.git
cd recon-framework
```

Instale as dependências Python:

```bash
pip install requests dnspython
```

Instale também as ferramentas externas necessárias:

### Subfinder

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### httpx

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Nuclei

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Atualizar templates do nuclei:

```bash
nuclei -update-templates
```

### Subjack

```bash
go install github.com/haccer/subjack@latest
```

### Nmap

Instalação via gerenciador de pacotes do sistema.

Exemplo (Debian / Ubuntu):

```bash
sudo apt install nmap
```

---

# 🚀 Como usar

### Mostrar ajuda

```bash
python3 recon.py -h
```

### Scan completo

```bash
python3 recon.py -d empresa.com
```

### Scan sem executar o Nuclei

```bash
python3 recon.py -d empresa.com --no-nuclei
```

### Scan sem portscan

```bash
python3 recon.py -d empresa.com --no-portscan
```

---

# 📁 Arquivos gerados

Após o scan, os seguintes arquivos serão criados:

```
subdomains.txt
alive.txt
ports.txt
methods.txt
cors.txt
clickjacking.txt
exposed.txt
takeover.txt
mail_spoof.txt
nuclei.txt
```

Cada arquivo contém resultados específicos da análise.

---

# 🔎 Testes realizados pela ferramenta

### Enumeração de Subdomínios

Descobre subdomínios ativos do domínio alvo.

### Descoberta de Hosts HTTP

Identifica serviços web ativos.

### Portscan

Verifica portas HTTP comuns abertas.

### Métodos HTTP Perigosos

Testa:

```
TRACE
PUT
DELETE
```

### CORS Misconfiguration

Detecta configurações de CORS inseguras.

### Clickjacking

Verifica ausência de proteções como:

```
X-Frame-Options
Content-Security-Policy
```

### Arquivos Sensíveis

Procura arquivos expostos como:

```
.git/config
.env
```

### Subdomain Takeover

Verifica possíveis domínios vulneráveis a takeover.

### Mail Spoofing

Analisa presença de registros:

```
SPF
DMARC
```

### Vulnerability Scan

Executa templates do Nuclei em hosts detectados.

---

# ⚠️ Aviso Legal

Esta ferramenta foi criada **exclusivamente para fins educacionais e testes autorizados de segurança**.

O uso desta ferramenta contra sistemas **sem autorização explícita** pode ser considerado atividade ilegal.

O autor **não se responsabiliza por qualquer uso indevido da ferramenta**.

Sempre utilize esta ferramenta **apenas em ambientes próprios ou com autorização formal do proprietário do sistema**.

---

# 🛡️ Uso Responsável

Antes de executar qualquer tipo de teste de segurança:

* Obtenha autorização formal do proprietário do sistema
* Respeite políticas de bug bounty
* Não cause interrupção de serviços
* Não exfiltre dados sensíveis

---

# 📌 Objetivo do projeto

Este projeto foi desenvolvido para:

* aprendizado em segurança ofensiva
* automação de tarefas de recon
* facilitar análises iniciais em pentests

---

# 🤝 Contribuição

Pull requests são bem-vindos.

Sugestões de melhorias, correções ou novas funcionalidades podem ser abertas na seção de **Issues**.

---

# 📜 Licença

Este projeto está licenciado sob a **MIT License**.
