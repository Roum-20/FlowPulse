# FlowPulse- Emphasizes traffic flow and monitoring.


A real-time, interactive dashboard built with **Python**, **Scapy**, and **Streamlit** to monitor and analyze network traffic on a Windows machine.

---

## 🚀 Features

- 🔎 Live packet sniffing (IP, TCP, UDP, ICMP)
- 📈 Real-time bandwidth usage and protocol distribution
- 🌍 GeoIP lookup and country-based traffic mapping (requires GeoLite2 database)
- 🌐 Interactive network map (source ➜ destination)
- 📊 Time-series heatmaps
- 🧠 DNS packet detection
- 🎯 Target port filter
- 🔤 Full-text payload search
- 🎛️ Sidebar filters (IP, protocol, port, payload)
- 🎨 Light/Dark mode toggle
- 🛢️ SQLite logging
- 📥 Export traffic as CSV
- 🔄 Auto-refresh with customizable interval

---

## 🖥️ Requirements

Ensure the following are installed:

- Python 3.9 or higher
- Npcap (for raw packet capture on Windows):  
  👉 [https://nmap.org/npcap/](https://nmap.org/npcap/)

---

## 📦 Installation

1. **Clone or extract** this repository.

2. Open **Command Prompt as Administrator** (important for raw packet access).

3. Install required Python packages:
   ```bash
   pip install -r requirements.txt
    ```
## ▶️ Usage
   Run the Streamlit dashboard (with admin privileges):
   ```bash
   streamlit run dashboard.py
   ```
## ⚠️ Note
  1.Some firewall or antivirus software may block raw packet access.
  
  2.Use responsibly on networks you are authorized to monitor.
## 📌 License
  This project is for educational and research purposes only. Use at your own risk.
