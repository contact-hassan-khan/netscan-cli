<!-- filepath: d:\project\netscan-cli\README.md -->
# NetScan CLI 🕵️‍♂️

![MIT License](https://img.shields.io/github/license/contact-hassan-khan/netscan-cli)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![PyPI](https://img.shields.io/pypi/v/netscan-cli)

> **Lightning-fast local-network reconnaissance**  
> Discover hosts, open ports, banners and CVEs – in one command.

---

## ✨ Features

- Fast host discovery (ARP or ICMP)
- TCP/UDP port scanning
- Banner grabbing & CVE matching
- Rich console and HTML/JSON output
- Docker & PyPI support
- Cross-platform (Linux, macOS, Windows)

---

## 🚀 Cross-Platform Quick Start

### 1. Clone & enter directory
```bash
git clone https://github.com/contact-hassan-khan/netscan-cli.git
cd netscan-cli
```

### 2. Create & activate virtual environment

| OS                  | Command                                               |
|---------------------|-------------------------------------------------------|
| **Linux / macOS**   | `python3 -m venv venv && source venv/bin/activate`    |
| **Windows PowerShell** | `python -m venv venv && .\venv\Scripts\Activate.ps1` |
| **Windows CMD**     | `python -m venv venv && venv\Scripts\activate.bat`    |

### 3. Install dependencies
```bash
pip install -r [requirements.txt](http://_vscodecontentref_/1)
```

### 4. Run the scanner

| OS                | Command                                                                 |
|-------------------|-------------------------------------------------------------------------|
| **Linux / macOS** | `sudo venv/bin/python netscan.py -t 192.168.1.0/24 -v -o json`          |
| **Windows**       | `python netscan.py -t 192.168.1.0/24 -s icmp -v -o json` *(ICMP mode)*  |

---

## 🐳 Docker (identical on all OS)

```bash
docker build -t netscan .
docker run --rm --net=host -it --cap-add NET_RAW \
           netscan -t 192.168.1.0/24 -v -o html
```
> On **Windows Docker Desktop**, replace `--net=host` with `-p 127.0.0.1:8000:8000` if port mapping is required.

---

## 📦 PyPI install (global binary, isolated venv)

```bash
pipx install netscan-cli        # auto-isolated venv
netscan -t 10.0.0.0/24 -o json
```

---

## ⚙️ CLI Flags

| Flag                | Description                | Example                  |
|---------------------|---------------------------|--------------------------|
| `-t, --target`      | CIDR or single IP         | `-t 192.168.0.0/24`      |
| `-p, --ports`       | comma-separated TCP ports | `-p 22,80,443`           |
| `-o, --output`      | json \| html              | `-o html`                |
| `-s, --scan-type`   | arp \| icmp \| both       | `-s icmp`                |
| `-v, --verbose`     | debug logs                | `-v`                     |

---

## 📊 Output Formats

| File           | Purpose                |
|----------------|-----------------------|
| `report.json`  | Machine-readable      |
| `report.html`  | Bootstrap-styled HTML |
| console table  | Live preview via Rich |

---

## ⚠️ Requirements

- **Linux / macOS / Windows**
- **Python 3.11+**
- **Raw-socket privileges**  
  - Linux/macOS: `sudo`  
  - Windows: **administrator cmd** or use **ICMP-only mode**
- **Optional:** Docker (no host dependencies)
- **For ARP scan on Windows:** [Npcap](https://nmap.org/npcap/) (install in WinPcap compatibility mode)

---

## 🧪 Build from source

```bash
python -m build
pip install dist/netscan_cli-*.whl
```

---

## 🛠️ Troubleshooting

- **No hosts found?**
  - Make sure you are scanning your local network, not a public IP range.
  - Many devices block ICMP (ping) by default—try ARP scan on local networks.
  - On Windows, install [Npcap](https://nmap.org/npcap/) for ARP support, or use `-s icmp`.
  - Check your firewall settings.

- **"No libpcap provider available" warning?**
  - This is normal if you don't have Npcap/WinPcap. ARP scan won't work on Windows without it.

- **"ValueError: ... has host bits set"**
  - Use the network address (e.g., `192.168.1.0/24`), not a host address (e.g., `192.168.1.5/24`).

---

## 📄 License

MIT © 2024 – contact-hassan-khan  
Feel free to fork, PR, and star!