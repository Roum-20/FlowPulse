# FlowPulse- Emphasizes traffic flow and monitoring.


A real-time, interactive dashboard built with **Python**, **Scapy**, and **Streamlit** to monitor and analyze network traffic on a Windows machine.

---

## 🚀 Features

- 📡 **Live packet capture** using `scapy`
- 📊 **Traffic visualizations**:
  - Bandwidth usage
  - Protocol distribution
  - Heatmap (Time vs Protocol)
- 🔍 **Live filtering** by protocol and IP address
- 🔐 **Port scan detection** (alerts on suspicious TCP traffic)
- 🧵 **Multi-threaded packet capture**
- 🧠 **Packet payload viewer** (hex-encoded)
- 💾 **SQLite logging** of captured packets
- 📥 **CSV download** of traffic data

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
