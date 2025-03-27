Perfeito! Aqui está o `README.md` atualizado com os dados da sua organização e repositório GitHub:

---

## 📄 `README.md`

```markdown
# 🦅 EdgeHawk - Attack Surface Management Platform

**EdgeHawk** is a powerful and extensible platform for **Attack Surface Management (ASM)**, allowing security teams to discover, monitor, and analyze exposed assets across the internet in real time.

---

## 🚀 Features

- 🔐 User authentication (Admin and Operator roles)
- 🌐 Subdomain enumeration with Subfinder and Assetfinder
- 📡 Port scanning with Naabu
- 📜 TLS analysis (v1.0, 1.1, 1.2, 1.3 and weak cipher detection via SSLScan)
- 🕵️ Technology fingerprinting with WhatWeb and HTTPX
- 🧠 Vulnerability scanning with Nuclei (supports full template sets)
- 📊 Dashboard with real-time charts
- 📁 Export findings to CSV
- 🖥️ Dark-mode web interface
- ⚙️ API Key management + user management panel
- 🧪 Real-time scan output via WebSocket
- 🛑 Stop button for interrupting scans like Nuclei

---

## 🐳 Quickstart (Docker Compose)

```bash
git clone https://github.com/CyberSecurityUP/EdgeHawk-ASM.git
cd EdgeHawk-ASM
docker-compose up --build
```

Then access it via: [http://localhost:8000](http://localhost:8000)

---

## 🔐 First-time Access

Register your admin or operator account:  
[http://localhost:8000/register](http://localhost:8000/register)

---

## 📁 Project Structure

```
EdgeHawk-ASM/
├── backend/
│   ├── api.py
│   ├── auth_module.py
│   └── users/
├── frontend/
│   ├── index.html
│   └── css/
├── findings/
├── main.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## ✍️ API Summary

| Method | Path           | Description                            |
|--------|----------------|----------------------------------------|
| GET    | /login         | Login page                             |
| POST   | /login         | Login form handler                     |
| GET    | /register      | Register page                          |
| POST   | /register      | Register form handler                  |
| GET    | /logout        | Logout user                            |
| POST   | /scan/basic    | Basic subdomain + IP scan              |
| POST   | /scan/full     | Subdomain + ports + tech fingerprint   |
| POST   | /scan/vuln     | Direct vulnerability scan with Nuclei  |
| GET    | /api/me        | Fetch authenticated user info          |

---

## 📜 License

MIT © 2025 — [CyberSecurityUP](https://github.com/CyberSecurityUP)

---

## 🤝 Contributing

Pull requests and ideas are welcome!  
Please fork the repo and open an issue or PR:

**GitHub:** [https://github.com/CyberSecurityUP/EdgeHawk-ASM](https://github.com/CyberSecurityUP/EdgeHawk-ASM)
