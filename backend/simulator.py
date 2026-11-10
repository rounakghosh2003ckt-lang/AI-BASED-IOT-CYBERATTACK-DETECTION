import random
import time
from datetime import datetime
from backend.ml_engine import IoTModelEngine
from backend.database import add_detection

IOT_DEVICES = [
    {"name": "Smart Thermostat Hub", "ip": "192.168.1.101", "type": "Environment Sensor"},
    {"name": "IP Security Camera #1", "ip": "192.168.1.102", "type": "Surveillance"},
    {"name": "Smart Door Lock Gateway", "ip": "192.168.1.103", "type": "Access Control"},
    {"name": "Industrial PLC Controller", "ip": "192.168.1.104", "type": "SCADA / Automation"},
    {"name": "Smart Power Meter", "ip": "192.168.1.105", "type": "Smart Grid"},
    {"name": "IoT Medical Heart Monitor", "ip": "192.168.1.106", "type": "Healthcare IoT"},
    {"name": "External Unknown Device", "ip": "45.133.1.88", "type": "Remote Node"},
    {"name": "Suspicious WAN Host", "ip": "185.220.101.5", "type": "Tor Exit Node"},
    {"name": "Internal Infiltrated Node", "ip": "192.168.1.250", "type": "Rogue Device"}
]

GATEWAY_IP = "10.0.0.1"

class IoTSimulator:
    def __init__(self):
        self.engine = IoTModelEngine.get_instance()
        self.active_mode = "Normal Traffic"
        self.is_running = True

    def set_scenario(self, scenario_name):
        valid = ["Normal Traffic", "DDoS Attack", "DoS Attack", "Port Scanning", "Brute Force", "Botnet"]
        if scenario_name in valid:
            self.active_mode = scenario_name
            return True
        return False

    def generate_flow_packet(self, scenario_override=None, record_to_db=False):
        scenario = scenario_override or self.active_mode

        # Device selection
        if scenario == "Normal Traffic":
            src = random.choice(IOT_DEVICES[:6])
            dst_ip = GATEWAY_IP
            proto = random.choice([6, 17]) # TCP or UDP
            proto_name = "MQTT (TCP)" if proto == 6 else "CoAP (UDP)"
            src_port = random.randint(1024, 65000)
            dst_port = random.choice([1883, 5683, 80, 443])
            flow_duration = round(random.uniform(50, 8000), 2)
            total_fwd_packets = random.randint(3, 15)
            total_bwd_packets = random.randint(2, 12)
            packet_length_mean = round(random.uniform(70, 160), 2)
            packet_length_std = round(random.uniform(10, 30), 2)
            packet_length_max = round(packet_length_mean + random.uniform(20, 100), 2)
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * packet_length_mean * 0.9, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0), 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0), 2)
            syn_flag_count = random.choice([0, 1])
            ack_flag_count = random.choice([1, 2])
            fin_flag_count = random.choice([0, 1])
            rst_flag_count = 0
            header_length = (total_fwd_packets + total_bwd_packets) * 20

        elif scenario == "DDoS Attack":
            src = random.choice(IOT_DEVICES[6:])
            dst_ip = GATEWAY_IP
            proto = random.choice([6, 17])
            proto_name = "TCP SYN Flood" if proto == 6 else "UDP Flood"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53])
            flow_duration = round(random.uniform(25000, 60000), 2)
            total_fwd_packets = random.randint(120, 400)
            total_bwd_packets = random.randint(0, 5)
            packet_length_mean = round(random.uniform(500, 950), 2)
            packet_length_std = round(random.uniform(80, 200), 2)
            packet_length_max = round(random.uniform(1200, 1500), 2)
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * 64, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0) * 8.0, 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0) * 8.0, 2)
            syn_flag_count = random.randint(15, 60)
            ack_flag_count = random.choice([0, 1])
            fin_flag_count = 0
            rst_flag_count = random.choice([0, 1])
            header_length = total_fwd_packets * 32

        elif scenario == "DoS Attack":
            src = random.choice(IOT_DEVICES[6:])
            dst_ip = GATEWAY_IP
            proto = 6
            proto_name = "TCP Slowloris"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443])
            flow_duration = round(random.uniform(40000, 80000), 2)
            total_fwd_packets = random.randint(35, 90)
            total_bwd_packets = random.randint(1, 6)
            packet_length_mean = round(random.uniform(180, 320), 2)
            packet_length_std = round(random.uniform(30, 60), 2)
            packet_length_max = round(packet_length_mean + 200, 2)
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * 64, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0) * 2.0, 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0) * 2.0, 2)
            syn_flag_count = random.randint(8, 25)
            ack_flag_count = random.choice([0, 1])
            fin_flag_count = random.choice([0, 1])
            rst_flag_count = random.choice([1, 2])
            header_length = total_fwd_packets * 24

        elif scenario == "Port Scanning":
            src = random.choice(IOT_DEVICES[6:])
            dst_ip = random.choice(IOT_DEVICES[:5])["ip"]
            proto = 6
            proto_name = "TCP SYN Scan"
            src_port = random.randint(35000, 65000)
            dst_port = random.choice([21, 22, 23, 80, 443, 8080, 1883, 502])
            flow_duration = round(random.uniform(10, 450), 2)
            total_fwd_packets = random.choice([1, 2])
            total_bwd_packets = random.choice([0, 1])
            packet_length_mean = round(random.uniform(40, 60), 2)
            packet_length_std = round(random.uniform(0, 5), 2)
            packet_length_max = 60
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * 40, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0), 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0), 2)
            syn_flag_count = random.choice([1, 2])
            ack_flag_count = 0
            fin_flag_count = 0
            rst_flag_count = random.choice([0, 1])
            header_length = total_fwd_packets * 20

        elif scenario == "Brute Force":
            src = random.choice(IOT_DEVICES[6:])
            dst_ip = IOT_DEVICES[3]["ip"] # PLC or Hub
            proto = 6
            proto_name = "SSH/Telnet (TCP)"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([22, 23, 80])
            flow_duration = round(random.uniform(3000, 12000), 2)
            total_fwd_packets = random.randint(12, 30)
            total_bwd_packets = random.randint(8, 20)
            packet_length_mean = round(random.uniform(80, 140), 2)
            packet_length_std = round(random.uniform(20, 50), 2)
            packet_length_max = round(random.uniform(250, 450), 2)
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * 80, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0), 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0), 2)
            syn_flag_count = random.choice([1, 2])
            ack_flag_count = random.randint(2, 6)
            fin_flag_count = random.choice([1, 2])
            rst_flag_count = random.choice([1, 2, 3])
            header_length = total_fwd_packets * 24

        elif scenario == "Botnet":
            src = IOT_DEVICES[1] # IP Camera infected
            dst_ip = "185.190.140.23" # C2 server
            proto = 6
            proto_name = "Mirai C2 Beacon"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([6667, 2323, 4444])
            flow_duration = round(random.uniform(8000, 25000), 2)
            total_fwd_packets = random.randint(20, 45)
            total_bwd_packets = random.randint(6, 18)
            packet_length_mean = round(random.uniform(65, 110), 2)
            packet_length_std = round(random.uniform(15, 35), 2)
            packet_length_max = round(random.uniform(150, 280), 2)
            total_fwd_bytes = round(total_fwd_packets * packet_length_mean, 2)
            total_bwd_bytes = round(total_bwd_packets * 60, 2)
            flow_bytes_per_sec = round((total_fwd_bytes + total_bwd_bytes) / (flow_duration / 1000.0), 2)
            flow_packets_per_sec = round((total_fwd_packets + total_bwd_packets) / (flow_duration / 1000.0), 2)
            syn_flag_count = random.randint(3, 8)
            ack_flag_count = random.choice([1, 2])
            fin_flag_count = random.choice([0, 1])
            rst_flag_count = random.choice([0, 1])
            header_length = total_fwd_packets * 24

        features = {
            "flow_duration": flow_duration,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "total_fwd_packets": total_fwd_packets,
            "total_bwd_packets": total_bwd_packets,
            "total_fwd_bytes": total_fwd_bytes,
            "total_bwd_bytes": total_bwd_bytes,
            "packet_length_mean": packet_length_mean,
            "packet_length_std": packet_length_std,
            "packet_length_max": packet_length_max,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "syn_flag_count": syn_flag_count,
            "ack_flag_count": ack_flag_count,
            "fin_flag_count": fin_flag_count,
            "rst_flag_count": rst_flag_count,
            "header_length": header_length
        }

        # Run REAL prediction with ML Engine
        prediction = self.engine.predict_single(features, src_ip=src["ip"], dst_ip=dst_ip)

        packet_info = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "device_name": src["name"],
            "device_type": src["type"],
            "source_ip": src["ip"],
            "destination_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "packets": total_fwd_packets + total_bwd_packets,
            "bytes": round(total_fwd_bytes + total_bwd_bytes, 2),
            "flow_duration_ms": flow_duration,
            "predicted_attack": prediction["attack_type"],
            "confidence": prediction["confidence"],
            "severity": prediction["severity"],
            "badge": prediction["badge"],
            "color": prediction["color"],
            "mitre_id": prediction["mitre_id"],
            "recommendation": prediction["recommendation"],
            "is_simulated": True,
            "features": features
        }

        if record_to_db:
            add_detection(
                source_ip=src["ip"],
                destination_ip=dst_ip,
                attack_type=prediction["attack_type"],
                confidence=prediction["confidence"],
                severity=prediction["severity"],
                protocol=proto_name,
                flow_duration=flow_duration,
                total_packets=total_fwd_packets + total_bwd_packets,
                total_bytes=round(total_fwd_bytes + total_bwd_bytes, 2),
                is_simulated=1
            )

        return packet_info

_simulator_instance = None

def get_simulator():
    global _simulator_instance
    if _simulator_instance is None:
        _simulator_instance = IoTSimulator()
    return _simulator_instance
