# NetScan CLI

![MIT](https://img.shields.io/badge/license-MIT-green)

A lightweight, pure-Python network scanner that discovers live hosts, open TCP/UDP ports, banners, and known CVEs.

![Demo](https://images.unsplash.com/photo-1607246749107-a1b2e5e5e3e3?ixlib=rb-4.0.3&q=80&w=400)

## Features

- Fast network scanning (IPv4/IPv6)
- Detects live hosts and open TCP/UDP ports
- Banner grabbing
- CVE detection for known vulnerabilities
- Multiple output formats: HTML, JSON, plain text
- Docker support

## Requirements

- Python 3.7+
- pip

## Install

```bash
pip install netscan-cli
```

## Usage

```bash
netscan -t 192.168.1.0/24 -o html -v
```

- `-t` : Target subnet or IP (e.g., 192.168.1.0/24)
- `-o` : Output format (`html`, `json`, `txt`)
- `-v` : Verbose mode

## Docker

Build the Docker image:

```bash
docker build -t netscan .
```

Run NetScan in a container:

```bash
docker run --rm -it netscan -t 10.0.0.0/24 -o json
```