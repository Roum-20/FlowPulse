import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS
from datetime import datetime
import threading
import logging
import time
import socket
import sqlite3
import os
import geoip2.database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketProcessor:
    def __init__(self):
        self.packet_data = []
        self.lock = threading.Lock()
        self.start_time = datetime.now()
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def get_protocol(self, proto):
        return self.protocol_map.get(proto, f"OTHER({proto})")

    def process_packet(self, packet):
        if IP in packet:
            with self.lock:
                data = {
                    "timestamp": datetime.now(),
                    "source": packet[IP].src,
                    "destination": packet[IP].dst,
                    "protocol": self.get_protocol(packet[IP].proto),
                    "size": len(packet),
                    "payload": str(bytes(packet[Raw])) if Raw in packet else "",
                    "is_dns": False
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
                    if packet[UDP].sport == 53 or packet[UDP].dport == 53 or DNS in packet:
                        data["is_dns"] = True

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

@st.cache_data
def get_geo_location(ip, reader):
    try:
        response = reader.city(ip)
        return response.country.name
    except:
        return "Unknown"

def set_theme(dark_mode):
    if dark_mode:
        st.markdown("""
            <style>
                body, .css-1d391kg, .stApp {
                    background-color: #0E1117;
                    color: white;
                }
                .css-ffhzg2 { background-color: #1E222A !important; }
                .css-1cpxqw2 { color: white !important; }
            </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <style>
                body, .stApp {
                    background-color: white;
                    color: black;
                }
            </style>
        """, unsafe_allow_html=True)

def draw_network_map(df):
    if df.empty:
        return

    edges = df.groupby(["source", "destination"]).size().reset_index(name="count")
    nodes = list(set(edges["source"]) | set(edges["destination"]))
    node_indices = {ip: i for i, ip in enumerate(nodes)}

    df["src_color"] = df["protocol"].map({"TCP": "#636EFA", "UDP": "#EF553B", "ICMP": "#00CC96"}).fillna("#AB63FA")
    node_colors = {ip: df[df["source"] == ip]["src_color"].iloc[0] if not df[df["source"] == ip].empty else "#AB63FA" for ip in nodes}

    edge_x = []
    edge_y = []
    for _, row in edges.iterrows():
        x0, x1 = node_indices[row["source"]], node_indices[row["destination"]]
        edge_x += [x0, x1, None]
        edge_y += [x0, x1, None]

    node_trace = go.Scatter(
        x=list(range(len(nodes))),
        y=list(range(len(nodes))),
        text=nodes,
        mode='markers+text',
        textposition="bottom center",
        hoverinfo='text',
        marker=dict(color=[node_colors[ip] for ip in nodes], size=10)
    )

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(title='\U0001F5FA Network Map: Source → Destination',
                                     showlegend=False,
                                     hovermode='closest',
                                     margin=dict(b=20,l=5,r=5,t=40)))
    st.plotly_chart(fig, use_container_width=True)

def main():
    st.set_page_config("FlowPulse Dashboard", layout="wide")

    st.sidebar.title("Settings")
    dark_mode = st.sidebar.checkbox("🌙 Dark Mode", value=False)
    set_theme(dark_mode)

    st.title("\U0001F4E1 Windows Network Traffic Dashboard")

    if "processor" not in st.session_state:
        st.session_state.processor = start_capture()
        st.session_state.start_time = time.time()
        st.session_state.selected_ip = ""
        st.session_state.selected_proto = "All"
        st.session_state.payload_keyword = ""
        st.session_state.target_port = ""

    df = st.session_state.processor.get_dataframe()
    refresh_rate = st.sidebar.slider("Refresh Rate (s)", 1, 10, 2)

    protocols = ["All"]
    if not df.empty and "protocol" in df.columns:
        protocols += df["protocol"].dropna().unique().tolist()

    st.session_state.selected_proto = st.sidebar.selectbox(
        "Protocol",
        protocols,
        index=protocols.index(st.session_state.selected_proto) if st.session_state.selected_proto in protocols else 0
    )

    top_ips = []
    if not df.empty and "source" in df.columns and "destination" in df.columns:
        all_ips = pd.concat([df["source"], df["destination"]]).dropna().tolist()
        top_ips = pd.Series(all_ips).value_counts().head(20).index.tolist()

    st.session_state.selected_ip = st.sidebar.selectbox(
        "\U0001F50E Filter by IP",
        [""] + top_ips,
        index=([""] + top_ips).index(st.session_state.selected_ip) if st.session_state.selected_ip in top_ips else 0
    )

    st.session_state.payload_keyword = st.sidebar.text_input("🔍 Search Payload", st.session_state.payload_keyword)
    st.session_state.target_port = st.sidebar.text_input("🎯 Target Port")

    if st.session_state.selected_proto != "All" and not df.empty:
        df = df[df["protocol"] == st.session_state.selected_proto]
    if st.session_state.selected_ip and not df.empty:
        df = df[
            df["source"].str.contains(st.session_state.selected_ip, na=False) |
            df["destination"].str.contains(st.session_state.selected_ip, na=False)
        ]
    if st.session_state.payload_keyword and not df.empty:
        df = df[df["payload"].str.contains(st.session_state.payload_keyword, na=False)]
    if st.session_state.target_port and not df.empty:
        df = df[df["dst_port"].astype(str).str.contains(st.session_state.target_port, na=False)]

    st.metric("Total Packets", len(df))
    st.metric("Duration", f"{time.time() - st.session_state.start_time:.2f}s")

    if len(df):
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        if os.path.exists("GeoLite2-City.mmdb"):
            reader = geoip2.database.Reader("GeoLite2-City.mmdb")
            df["src_country"] = df["source"].apply(lambda ip: get_geo_location(ip, reader))
            df["dst_country"] = df["destination"].apply(lambda ip: get_geo_location(ip, reader))

            geo_counts = df.groupby(["src_country", "dst_country"]).size().reset_index(name="count")
            fig_geo = px.sunburst(geo_counts, path=["src_country", "dst_country"], values="count", title="\U0001F30D GeoIP: Traffic Source → Destination")
            st.plotly_chart(fig_geo, use_container_width=True)

        draw_network_map(df)

        bytes_over_time = df.groupby(df["timestamp"].dt.floor("S"))["size"].sum()
        st.plotly_chart(px.line(x=bytes_over_time.index, y=bytes_over_time.values, title="Bandwidth Usage"), use_container_width=True)

        proto_dist = df["protocol"].value_counts()
        st.plotly_chart(px.pie(values=proto_dist.values, names=proto_dist.index, title="Protocol Distribution"), use_container_width=True)

        heatmap = df.groupby([df["timestamp"].dt.floor("S"), "protocol"]).size().unstack(fill_value=0)
        st.plotly_chart(px.imshow(heatmap.T, title="Heatmap: Time vs Protocol"), use_container_width=True)

        suspicious = df[df["protocol"] == "TCP"].groupby("source")["dst_port"].nunique()
        alert_ips = suspicious[suspicious > 10]
        if not alert_ips.empty:
            st.warning(f"\u26A0\uFE0F Port scan suspected from: {', '.join(alert_ips.index)}")

        dns_df = df[df["is_dns"] == True]
        if not dns_df.empty:
            st.subheader("\U0001F50D Detected DNS Packets")
            st.dataframe(dns_df[["timestamp", "source", "destination", "size"]].tail(10))

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
