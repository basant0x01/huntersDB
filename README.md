# HuntersDB

> **The Data Layer for Bug Bounty Hunting**
> A continuously updated recon intelligence database designed for **mass-scale bug bounty hunting**.

---

## 🚀 Overview

**HuntersDB** is a high-performance, distributed reconnaissance platform that aggregates, scans, and enriches subdomain data across multiple bug bounty platforms.

Instead of running recon repeatedly, HuntersDB provides **ready-to-use, continuously updated intelligence** that hunters can query and integrate into their own tools.

> ![HuntersDB Hero](static/screenshots/hero.png)

---

## 🖥️ Dashboard & Interface

HuntersDB provides a modern, fast UI to visualize active targets, view recon pipelines, and manage automated scanning.

**Login Panel:**
> ![Login Panel](static/screenshots/login.png)

**Main Dashboard:**
> ![Main Dashboard](static/screenshots/dashboard.png)

---

## 🔥 Key Features

### 🌐 Global Recon Dataset
* Aggregates subdomains from:
  * HackerOne
  * Bugcrowd
  * YesWeHack
  * Chaos datasets
* Maintains a **centralized database of all discovered assets**

---

### ⚡ Continuous Scanning (24/7)
* Automated scanning pipeline:
  * Alive detection (`httpx`)
  * Deep scanning
  * Vulnerability scanning (`nuclei`)
* Data refreshed every **24 hours (or configurable)**

> ![Recon Pipeline](static/screenshots/features.png)

---

### 🧠 Recon Intelligence Engine
Enriched data per subdomain:
* Open ports (naabu)
* Crawled endpoints (katana, gau, wayback)
* Hidden parameters (arjun)
* JS secrets (trufflehog, linkfinder)
* Directory fuzzing (ffuf)
* WAF detection
* HTTP security headers
* Email security (SPF, DKIM, DMARC)

> ![Intelligence Modules](static/screenshots/modules.png)

---

### 🧬 Leak Intelligence
* Integrates breach intelligence (HackedList + others)
* Maps compromised subdomains
* Tracks exposure history

---

### 🧹 Garbage Filtering Engine
* Removes low-value / ISP / noise subdomains
* Uses entropy + pattern detection
* Keeps dataset **clean and high-signal**

---

### ⚙️ Adaptive Scanning Engine
* Dynamically adjusts:
  * Threads
  * Rate limits
* Based on:
  * CPU usage
  * Scan throughput
* Maximizes speed without overload

---

### 🔁 Autonomous Monitoring
* Periodic re-scanning of assets
* Detects:
  * New subdomains
  * Changes in attack surface
  * Newly exposed vulnerabilities

---

### 📡 Webhook Notifications
Supports:
* Discord
* Slack
* Telegram

---

## 🏗️ Architecture

HuntersDB follows a **distributed, async-first architecture**:

```text
                ┌────────────────────┐
                │   FastAPI Server   │
                │  (API + UI Layer)  │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │      Redis Queue   │
                │ (Job Dispatcher)   │
                └─────────┬──────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌──────────────────┐              ┌──────────────────┐
│ Worker Process 1 │              │ Worker Process N │
│  (Scanning)      │              │  (Recon/Sync)    │
└──────────────────┘              └──────────────────┘

                ▼
        ┌──────────────────┐
        │   PostgreSQL DB  │
        │ (Recon Database) │
        └──────────────────┘
```

---

## 🧩 Core Components

| Component | Description |
|---|---|
| **API Server** | FastAPI backend serving API + UI |
| **Worker System** | Executes scanning, recon, sync jobs |
| **Redis Queue** | Priority job queue with retry support |
| **PostgreSQL** | Stores all recon & intelligence data |
| **Process Manager** | Controls subprocess execution safely |

---

## 📊 Data Model (Simplified)

* `projects` → bug bounty programs
* `subdomains` → discovered assets
* `recon_results` → enriched recon data
* `leak_intel` → breach intelligence
* `vulnerabilities` → nuclei findings
* `alerts` → triggered events

---

## ⚡ Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/huntersdb.git
cd huntersdb
```

### 2. Setup environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Install dependencies
* PostgreSQL
* Redis
* Go tools: `httpx`, `subfinder`, `nuclei`, `naabu`, `ffuf`, etc.

Run the installer:
```bash
bash install_tools.sh
```

### 4. Configure environment
Create `.env`:
```env
DATABASE_URL=postgresql://user:pass@localhost:5432/huntersdb
REDIS_URL=redis://localhost:6379/0
SUBMIND_USER=admin
SUBMIND_PASS=admin
```

### 5. Run the system
**Start API server:**
```bash
uvicorn main:app --host 0.0.0.0 --port 5000
```
**Start worker:**
```bash
python -m workers.queue_consumer
```
**Or run both automatically:**
```bash
bash run.sh
```

---

## 📡 API (Recommended Usage)

HuntersDB is designed to be **API-first**. Example endpoints:

```http
GET /api/intel/subdomains?program=tesla
GET /api/intel/high-risk
GET /api/intel/recon?subdomain=api.example.com
GET /api/intel/changes?last=24h
```

> ![Live Database Query Demo](static/screenshots/query.png)

---

## 🎯 Use Cases
* Mass bug bounty hunting
* Recon automation pipelines
* Custom vulnerability scanners
* Target prioritization systems
* Security research datasets

---

## 🚨 Scaling Strategy
HuntersDB is built for horizontal scaling:
* **Add more workers** → increase throughput
* **Redis** handles distributed job queue
* **PostgreSQL** handles centralized data
* **Stateless** API server

---

## 🔐 Security Notes
* Uses session-based authentication (initial version)
* Recommended future improvements:
  * API keys
  * Rate limiting
  * RBAC
  * Audit logging

---

## 🛣️ Roadmap
- [ ] Public API layer for hunters
- [ ] Advanced risk scoring system
- [ ] Real-time data streaming
- [ ] Distributed worker orchestration
- [ ] SaaS deployment
- [ ] CLI client for hunters

---

## 🤝 Contributing
Contributions are welcome. Please:
1. Fork the repo
2. Create a feature branch
3. Submit a pull request

---

## 📄 License
MIT License

---

## 🧠 Vision
> HuntersDB aims to eliminate redundant recon work and provide a unified, continuously updated intelligence layer for bug bounty hunters worldwide.

---

## ⭐ Support
If you find this project useful:
* Star the repository ⭐
* Share with the community
* Contribute ideas & improvements

---
**Built for hackers. Scaled for the future.**
