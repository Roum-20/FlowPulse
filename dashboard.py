
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import threading
import logging
import time
import socket
import sqlite3
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketProcessor:
    def __init__(self):
        self.packet_data = []
        self.lock = threading.Lock()
        self.start_time = datetime.now()
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def get_protocol(self, proto):
        return self.protocol_map.get(proto, f"OTHER({proto})")

    def resolve_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip

    def process_packet(self, packet):
        if IP in packet:
            with self.lock:
                data = {
                    "timestamp": datetime.now(),
                    "source": packet[IP].src,
                    "destination": packet[IP].dst,
                    "protocol": self.get_protocol(packet[IP].proto),
                    "size": len(packet),
                    "payload": str(bytes(packet[Raw])) if Raw in packet else ""
                }

                if TCP in packet:
                    data.update({
                        "src_port": packet[TCP].sport,
                        "dst_port": packet[TCP].dport,
                        "tcp_flags": str(packet[TCP].flags)
                    })
                elif UDP in packet:
                    data.update({
                        "src_port": packet[UDP].sport,
                        "dst_port": packet[UDP].dport
                    })

                self.packet_data.append(data)
                if len(self.packet_data) > 5000:
                    self.packet_data.pop(0)

    def get_dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data)

def start_capture():
    processor = PacketProcessor()
    thread = threading.Thread(target=lambda: sniff(prn=processor.process_packet, store=False), daemon=True)
    thread.start()
    return processor

def log_to_db(df):
    try:
        conn = sqlite3.connect("packets_windows.db")
        df.to_sql("packets", conn, if_exists="append", index=False)
        conn.close()
    except Exception as e:
        st.error(f"SQLite Error: {e}")

def main():
    st.set_page_config("Windows Network Dashboard", layout="wide")
    st.title("📡 Windows Network Traffic Dashboard")

    if "processor" not in st.session_state:
        st.session_state.processor = start_capture()
        st.session_state.start_time = time.time()

    df = st.session_state.processor.get_dataframe()

    refresh_rate = st.sidebar.slider("Refresh Rate (s)", 1, 10, 2)

    protocols = ["All"]
    if not df.empty and "protocol" in df.columns:
        protocols += df["protocol"].dropna().unique().tolist()

    proto_filter = st.sidebar.selectbox("Protocol", protocols)
    ip_filter = st.sidebar.text_input("Filter by IP")

    if proto_filter != "All" and not df.empty and "protocol" in df.columns:
        df = df[df["protocol"] == proto_filter]
    if ip_filter and not df.empty:
        df = df[df["source"].str.contains(ip_filter) | df["destination"].str.contains(ip_filter)]

    st.metric("Total Packets", len(df))
    st.metric("Duration", f"{time.time() - st.session_state.start_time:.2f}s")

    if len(df):
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hostname"] = df["source"].apply(lambda ip: socket.getfqdn(ip))

        bytes_over_time = df.groupby(df["timestamp"].dt.floor("S"))["size"].sum()
        st.plotly_chart(px.line(x=bytes_over_time.index, y=bytes_over_time.values, title="Bandwidth Usage"), use_container_width=True)

        proto_dist = df["protocol"].value_counts()
        st.plotly_chart(px.pie(values=proto_dist.values, names=proto_dist.index, title="Protocol Distribution"), use_container_width=True)

        heatmap = df.groupby([df["timestamp"].dt.floor("S"), "protocol"]).size().unstack(fill_value=0)
        st.plotly_chart(px.imshow(heatmap.T, title="Heatmap: Time vs Protocol"), use_container_width=True)

        suspicious = df[df["protocol"] == "TCP"].groupby("source")["dst_port"].nunique()
        alert_ips = suspicious[suspicious > 10]
        if not alert_ips.empty:
            st.warning(f"⚠️ Port scan suspected from: {', '.join(alert_ips.index)}")

        st.subheader("Recent Packets")
        st.dataframe(df.tail(10)[["timestamp", "source", "destination", "protocol", "size"]])

        if st.checkbox("Show Last Packet Payload"):
            st.code(df.iloc[-1]["payload"], language="text")

        if st.button("Export CSV"):
            st.download_button("Download", df.to_csv(index=False).encode(), "windows_traffic_log.csv", "text/csv")

        log_to_db(df)

    time.sleep(refresh_rate)
    st.rerun()

if __name__ == "__main__":
    main()
