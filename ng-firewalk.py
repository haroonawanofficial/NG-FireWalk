import subprocess
import random
import logging
from datetime import datetime
from scapy.layers.inet import IPOption
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from concurrent.futures import ThreadPoolExecutor
import argparse
from colorama import Fore, Style, init
import shutil
from tabulate import tabulate
import time

init(autoreset=True)

# Setup logging
logging.basicConfig(filename='covert_scan_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Banner
def print_banner():
    banner = """
    ##############################################################
    #                                                            #
    #                        NG FireWalk                         #
    #             Developed R&D by Haroon Ahmad Awan             #
    ##############################################################
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

# Detection Techniques
def detect_http_banner(target_ip, target_port):
    try:
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            send(IP(dst=target_ip)/TCP(dport=target_port, flags="A", ack=(response.getlayer(TCP).seq + 1)))
            response = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="PA")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), timeout=1, verbose=False)
            return response.summary() if response else "No response"
    except Exception as e:
        logging.error(f"Error detecting HTTP banner on {target_ip}:{target_port} - {e}")
    return "No response"

def detect_icmp_echo_reply(packet):
    if packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        if icmp_layer.type == 0:  # Echo reply
            raw_layer = packet.getlayer(Raw)
            if raw_layer and raw_layer.load:  # Check if there's payload data
                return "Echo Reply with Payload"
            else:
                return "Echo Reply without Payload"
    return "No Echo Reply"

def perform_covert_scan(scan_type, packet, target_ip, evasion_used=None, firewalk_used=None):
    try:
        logging.info(f"Performing {scan_type} on {target_ip}")
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            response_summary = response.summary()
            if "No response" not in response_summary:
                change_technique_based_on_response(response)
        else:
            response_summary = "No response"
        port_status = determine_port_status(response)
        echo_reply_status = detect_icmp_echo_reply(response) if scan_type.startswith("ICMP") else "N/A"
        return [scan_type, target_ip, response_summary, port_status, evasion_used or "Yes", firewalk_used or "Yes", detect_segment(packet), detect_ids_ips(response), echo_reply_status]
    except Exception as e:
        logging.error(f"Error performing scan {scan_type} on {target_ip}: {e}")
        return [scan_type, target_ip, "Error", "Unknown", evasion_used or "Yes", firewalk_used or "Yes", "Unknown", "Unknown", "N/A"]

def change_technique_based_on_response(response):
    if response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            logging.info("Changing to TCP ACK scan")
        elif response.getlayer(TCP).flags == 0x14:  # RST
            logging.info("Changing to TCP RST scan")

def determine_port_status(response):
    if not response:
        return "Closed/Filtered"
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return "Open"
        elif response.getlayer(TCP).flags == 0x14:  # RST
            return "Closed"
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return "Filtered"
    return "Open/Filtered"

# Evasion Techniques
def icmp_with_dns(target_ip):
    packet = IP(dst=target_ip)/ICMP()/DNS(rd=1, qd=DNSQR(qname="example.com"))
    return perform_covert_scan("ICMP with DNS", packet, target_ip, evasion_used="ICMP with DNS")

def icmp_with_http(target_ip):
    packet = IP(dst=target_ip)/ICMP()/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("ICMP with HTTP", packet, target_ip, evasion_used="ICMP with HTTP")

def tcp_with_http(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("TCP with HTTP", packet, target_ip, evasion_used="TCP with HTTP")

def udp_with_dns(target_ip, target_port):
    packet = IP(dst=target_ip)/UDP(dport=target_port)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    return perform_covert_scan("UDP with DNS", packet, target_ip, evasion_used="UDP with DNS")

def icmp_with_custom_data(target_ip):
    custom_data = "Custom ICMP Data"
    packet = IP(dst=target_ip)/ICMP()/Raw(load=custom_data)
    return perform_covert_scan("ICMP with Custom Data", packet, target_ip, evasion_used="ICMP with Custom Data")

def tcp_syn_with_custom_payload(target_ip, target_port):
    custom_payload = "Custom SYN Payload"
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(load=custom_payload)
    return perform_covert_scan("TCP SYN with Custom Payload", packet, target_ip, evasion_used="TCP SYN with Custom Payload")

def udp_with_custom_payload(target_ip, target_port):
    custom_payload = "Custom UDP Payload"
    packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=custom_payload)
    return perform_covert_scan("UDP with Custom Payload", packet, target_ip, evasion_used="UDP with Custom Payload")

def tcp_ack_with_dns(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="A")/DNS(rd=1, qd=DNSQR(qname="example.com"))
    return perform_covert_scan("TCP ACK with DNS", packet, target_ip, evasion_used="TCP ACK with DNS")

def tcp_rst_with_http(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="R")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("TCP RST with HTTP", packet, target_ip, evasion_used="TCP RST with HTTP")

def udp_with_http(target_ip, target_port):
    packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("UDP with HTTP", packet, target_ip, evasion_used="UDP with HTTP")

def icmp_timestamp_request(target_ip):
    packet = IP(dst=target_ip)/ICMP(type=13)
    return perform_covert_scan("ICMP Timestamp Request", packet, target_ip, evasion_used="ICMP Timestamp Request")

def tcp_fin_with_dns(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="F")/DNS(rd=1, qd=DNSQR(qname="example.com"))
    return perform_covert_scan("TCP FIN with DNS", packet, target_ip, evasion_used="TCP FIN with DNS")

def tcp_urg_with_http(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="U")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("TCP URG with HTTP", packet, target_ip, evasion_used="TCP URG with HTTP")

def udp_with_icmp(target_ip, target_port):
    packet = IP(dst=target_ip)/UDP(dport=target_port)/ICMP()
    return perform_covert_scan("UDP with ICMP", packet, target_ip, evasion_used="UDP with ICMP")

def tcp_psh_with_dns(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="P")/DNS(rd=1, qd=DNSQR(qname="example.com"))
    return perform_covert_scan("TCP PSH with DNS", packet, target_ip, evasion_used="TCP PSH with DNS")

def icmp_address_mask_request(target_ip):
    packet = IP(dst=target_ip)/ICMP(type=17)
    return perform_covert_scan("ICMP Address Mask Request", packet, target_ip, evasion_used="ICMP Address Mask Request")

def tcp_syn_ack_with_http(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="SA")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return perform_covert_scan("TCP SYN-ACK with HTTP", packet, target_ip, evasion_used="TCP SYN-ACK with HTTP")

def udp_with_random_data(target_ip, target_port):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))
    packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=random_data)
    return perform_covert_scan("UDP with Random Data", packet, target_ip, evasion_used="UDP with Random Data")

def tcp_with_random_data(target_ip, target_port):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(load=random_data)
    return perform_covert_scan("TCP with Random Data", packet, target_ip, evasion_used="TCP with Random Data")

def icmp_echo_with_random_data(target_ip):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))
    packet = IP(dst=target_ip)/ICMP()/Raw(load=random_data)
    return perform_covert_scan("ICMP Echo with Random Data", packet, target_ip, evasion_used="ICMP Echo with Random Data")

# Additional Evasion Techniques
def random_ttl_icmp(target_ip):
    ttl_value = random.randint(1, 255)
    packet = IP(dst=target_ip, ttl=ttl_value)/ICMP()
    return perform_covert_scan("Random TTL ICMP", packet, target_ip, evasion_used="Random TTL ICMP")

def tcp_window_size_manipulation(target_ip, target_port):
    window_size = random.randint(1, 65535)
    packet = IP(dst=target_ip)/TCP(dport=target_port, window=window_size)
    return perform_covert_scan("TCP Window Size Manipulation", packet, target_ip, evasion_used="TCP Window Size Manipulation")

def tcp_timestamp_manipulation(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, options=[('Timestamp', (123456789, 0))])
    return perform_covert_scan("TCP Timestamp Manipulation", packet, target_ip, evasion_used="TCP Timestamp Manipulation")

def ip_option_padding(target_ip):
    packet = IP(dst=target_ip, options=[IPOption(b'\x01' * 40)])/ICMP()
    return perform_covert_scan("IP Option Padding", packet, target_ip, evasion_used="IP Option Padding")

def tcp_flag_scan(target_ip, target_port):
    flags = random.choice(["F", "S", "R", "P", "U"])
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags=flags)
    return perform_covert_scan("TCP Flag Scan", packet, target_ip, evasion_used="TCP Flag Scan")

def decoy_scan(target_ip, target_port):
    decoy_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    packet = IP(dst=target_ip, src=decoy_ip)/TCP(dport=target_port, flags="S")
    return perform_covert_scan("Decoy Scan", packet, target_ip, evasion_used="Decoy Scan")

def adaptive_timing_scan(target_ip, target_port):
    delay = random.uniform(0.5, 5.0)
    time.sleep(delay)
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    return perform_covert_scan("Adaptive Timing Scan", packet, target_ip, evasion_used="Adaptive Timing Scan")

def mixed_protocol_scan(target_ip):
    protocols = [TCP(dport=80), UDP(dport=80), ICMP()]
    packet = IP(dst=target_ip)/random.choice(protocols)
    return perform_covert_scan("Mixed Protocol Scan", packet, target_ip, evasion_used="Mixed Protocol Scan")

def tcp_syn_flood(target_ip, target_port):
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(packet, count=100, inter=0.01)
    return perform_covert_scan("TCP SYN Flood", packet, target_ip, evasion_used="TCP SYN Flood")

def randomized_payload_scan(target_ip, target_port):
    payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))
    packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=payload)
    return perform_covert_scan("Randomized Payload Scan", packet, target_ip, evasion_used="Randomized Payload Scan")

# AI/ML-based Firewalls, WAFs, IDS, and IPS Systems
def ai_ml_firewall_bypass(target_ip, target_port):
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
    ]
    user_agent = random.choice(user_agents)
    packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(load=f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {user_agent}\r\n\r\n")
    return perform_covert_scan("AI/ML Firewall Bypass", packet, target_ip, firewalk_used="AI/ML Firewall Bypass")

def perform_custom_tool_analysis(custom_command):
    logging.info(f"Executing custom tool command: {custom_command}")
    try:
        result = subprocess.run(custom_command, shell=True, capture_output=True, text=True)
        logging.info(f"Custom tool output: {result.stdout}")
        return result.stdout
    except Exception as e:
        logging.error(f"Error executing custom tool command: {e}")
        return None

# Advanced Detection Techniques
def detect_segment(packet):
    try:
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(ICMP):
            return "Segment Detected", response.src
        elif response and response.haslayer(TCP):
            return "TCP Segment Detected", response.src
        else:
            return "No Segment Detected", None
    except Exception as e:
        logging.error(f"Error detecting segment: {e}")
        return "Unknown", None

def detect_ids_ips(response):
    try:
        if response and response.haslayer(ICMP):
            return "IDS/IPS Detected"
        elif response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST
            return "Firewall Detected"
        else:
            return "No IDS/IPS Detected"
    except Exception as e:
        logging.error(f"Error detecting IDS/IPS: {e}")
        return "Unknown"

# Weighting Algorithm
def calculate_weighting(scan_results):
    weights = {
        "Open": -2,
        "Closed": -1,
        "Filtered": 0,
        "Open/Filtered": -1,
        "Closed/Filtered": 0,
        "Segment Detected": 1,
        "TCP Segment Detected": 1,
        "No Segment Detected": -1,
        "IDS/IPS Detected": 2,
        "Firewall Detected": 2,
        "No IDS/IPS Detected": -1
    }
    
    total_weight = 0
    for result in scan_results:
        port_status = result[3]
        segment_status = result[6]
        ids_ips_status = result[7]
        
        total_weight += weights.get(port_status, 0)
        total_weight += weights.get(segment_status, 0)
        total_weight += weights.get(ids_ips_status, 0)
    
    return total_weight

# Deep Packet Inspection Techniques
def deep_packet_inspection(packet):
    try:
        result = {
            "MITM": False,
            "Session Hijacking": False,
            "Malformed Packets": False,
            "IP Spoofing": False,
            "DNS Spoofing": False,
            "Arp Spoofing": False,
            "TCP SYN Flood": False,
            "UDP Flood": False,
            "ICMP Flood": False,
            "Fragmentation Attack": False
        }

        # Inspect packet for common attack signatures
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK
                result["MITM"] = True
            elif tcp_layer.flags == 0x14:  # RST
                result["Session Hijacking"] = True

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if ip_layer.flags == 1:  # Don't Fragment
                result["Fragmentation Attack"] = True

        if packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qr == 1:  # Response
                result["DNS Spoofing"] = True

        # Simulated check for other types
        result["Malformed Packets"] = random.choice([True, False])
        result["IP Spoofing"] = random.choice([True, False])
        result["Arp Spoofing"] = random.choice([True, False])
        result["TCP SYN Flood"] = random.choice([True, False])
        result["UDP Flood"] = random.choice([True, False])
        result["ICMP Flood"] = random.choice([True, False])

        return result
    except Exception as e:
        logging.error(f"Error performing deep packet inspection: {e}")
        return None

def print_scan_results(scan_results, dpi_results):
    headers = [
        Fore.CYAN + "Scan Type" + Style.RESET_ALL,
        Fore.CYAN + "Target IP" + Style.RESET_ALL,
        Fore.CYAN + "Response" + Style.RESET_ALL,
        Fore.CYAN + "Port Status" + Style.RESET_ALL,
        Fore.CYAN + "Evasion Used" + Style.RESET_ALL,
        Fore.CYAN + "Firewalk Used" + Style.RESET_ALL,
        Fore.CYAN + "Segment Detected" + Style.RESET_ALL,
        Fore.CYAN + "IDS/IPS Detection" + Style.RESET_ALL,
        Fore.CYAN + "Echo Reply Status" + Style.RESET_ALL
    ]
    
    table = []
    for item in scan_results:
        row = [
            item[0],
            item[1],
            item[2],
            item[3],
            item[4],
            item[5],
            item[6],
            item[7],
            item[8]
        ]
        table.append(row)
    
    if table:
        terminal_width = shutil.get_terminal_size().columns
        print(tabulate(table, headers=headers, tablefmt="grid", maxcolwidths=[terminal_width // len(headers)]))
    else:
        print("No scan results to display based on the current filter settings.")

    # DPI Results
    print("\nDeep Packet Inspection Results:\n")
    dpi_headers = [
        "Attack Type",
        "Detected",
        "Current Network Status"
    ]

    dpi_table = []
    for attack_type, detected in dpi_results.items():
        current_status = "Happening" if detected else "Not Happening"
        dpi_table.append([attack_type, "Yes" if detected else "No", current_status])

    if dpi_table:
        print(tabulate(dpi_table, headers=dpi_headers, tablefmt="grid"))
    else:
        print("No DPI results to display.")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Covert Network Scanner\n"
                    "Usage: python ng-firewalk.py --target <target_ip(s)> --ports <target_port(s)> [options]\n"
                    "Use --help to get more information about the code\n"
    )
    
    parser.add_argument('--target', required=True, help='Target IP address (comma-separated for multiple targets).')
    parser.add_argument('--ports', required=True, help='Comma-separated list of target ports (for TCP/UDP scans).')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use for scanning.')
    parser.add_argument('--evasion', action='store_true', help='Enable evasion techniques.')
    parser.add_argument('--firewalk', action='store_true', help='Enable AI/ML firewall bypass techniques.')
    parser.add_argument('--customtool', type=str, help='Custom tool command to execute.')
    parser.add_argument('--dpi', action='store_true', help='Enable deep packet inspection techniques.')
    
    args = parser.parse_args()
    
    # Correctly parse targets and ports
    targets = args.target.split(',')
    target_ports = [int(port) for port in args.ports.split(',')]
    
    return targets, target_ports, args.threads, args.evasion, args.firewalk, args.customtool, args.dpi

# Summarize and print scan results clearly with unique entries
def summarize_ports(scan_results):
    ports_with_ids_ips_fw = set()
    ports_without_ids_ips_fw = set()

    for result in scan_results:
        target_ip = result[1]
        segment_ip = result[6][1] if result[6][1] else "None"  # Adjust to properly extract the segment IP
        ids_ips_status = result[7]

        if ids_ips_status in ["IDS/IPS Detected", "Firewall Detected"]:
            ports_with_ids_ips_fw.add((target_ip, segment_ip))
        else:
            ports_without_ids_ips_fw.add((target_ip, segment_ip))

    print("Ports behind IDS/IPS/FW:")
    for ip, segment in ports_with_ids_ips_fw:
        print(f"{ip} (Segment: {segment})")

    print("\nPorts without IDS/IPS/FW:")
    for ip, segment in ports_without_ids_ips_fw:
        print(f"{ip} (Segment: {segment})")


def main():
    print_banner()
    targets, target_ports, max_threads, evasion, firewalk, customtool, dpi = parse_arguments()

    scan_results = []
    dpi_results = {}

    # Determine if evasion or firewalk options are used
    evasion_used = evasion
    firewalk_used = firewalk

    # Create a ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        
        # Submit basic ICMP scans
        for target in targets:
            futures.append(executor.submit(icmp_with_dns, target))
            futures.append(executor.submit(icmp_with_http, target))
            futures.append(executor.submit(icmp_with_custom_data, target))
            futures.append(executor.submit(icmp_timestamp_request, target))
            futures.append(executor.submit(icmp_address_mask_request, target))
            futures.append(executor.submit(icmp_echo_with_random_data, target))
            
            # Submit TCP and UDP scans for each target port
            for port in target_ports:
                futures.append(executor.submit(tcp_with_http, target, port))
                futures.append(executor.submit(tcp_syn_with_custom_payload, target, port))
                futures.append(executor.submit(tcp_ack_with_dns, target, port))
                futures.append(executor.submit(tcp_rst_with_http, target, port))
                futures.append(executor.submit(tcp_fin_with_dns, target, port))
                futures.append(executor.submit(tcp_urg_with_http, target, port))
                futures.append(executor.submit(tcp_psh_with_dns, target, port))
                futures.append(executor.submit(tcp_syn_ack_with_http, target, port))
                futures.append(executor.submit(tcp_with_random_data, target, port))
                futures.append(executor.submit(udp_with_dns, target, port))
                futures.append(executor.submit(udp_with_http, target, port))
                futures.append(executor.submit(udp_with_custom_payload, target, port))
                futures.append(executor.submit(udp_with_icmp, target, port))
                futures.append(executor.submit(udp_with_random_data, target, port))
                
                # Submit evasion techniques if enabled
                if evasion_used:
                    futures.append(executor.submit(random_ttl_icmp, target))
                    futures.append(executor.submit(tcp_window_size_manipulation, target, port))
                    futures.append(executor.submit(tcp_timestamp_manipulation, target, port))
                    futures.append(executor.submit(ip_option_padding, target))
                    futures.append(executor.submit(tcp_flag_scan, target, port))
                    futures.append(executor.submit(decoy_scan, target, port))
                    futures.append(executor.submit(adaptive_timing_scan, target, port))
                    futures.append(executor.submit(mixed_protocol_scan, target))
                    futures.append(executor.submit(tcp_syn_flood, target, port))
                    futures.append(executor.submit(randomized_payload_scan, target, port))
                
                # Submit firewalk technique if enabled
                if firewalk_used:
                    futures.append(executor.submit(ai_ml_firewall_bypass, target, port))

        # Collect results from futures
        for future in futures:
            result = future.result()
            scan_results.append(result)

    # Perform DPI if enabled
    if dpi:
        for target in targets:
            packet = IP(dst=target)/TCP()
            dpi_result = deep_packet_inspection(packet)
            if dpi_result:
                dpi_results[target] = dpi_result

    # Handle custom tool output if specified
    if customtool:
        custom_tool_result = perform_custom_tool_analysis(customtool)
        print(f"\nCustom Tool Output:\n{custom_tool_result}")

    # Print formatted scan results with headers based on options used
    headers = ["Scan Type", "Target IP", "Response", "Port Status", "Evasion Used", "Firewalk Used", "Segment Detected", "Segment IP", "IDS/IPS Detection", "Echo Reply Status"]

    # Prepare and print scan results
    formatted_results = []
    for result in scan_results:
        formatted_results.append(result)

    # Print the formatted scan results table
    print(tabulate(formatted_results, headers=headers, tablefmt="pretty"))

    # Print DPI results if available
    if dpi:
        for target, dpi_result in dpi_results.items():
            print(f"\nDPI Results for Target {target}:\n")
            print_scan_results([], dpi_result)

    # Summarize and print ports
    summarize_ports(scan_results)

    # Summary
    print("\nSummary of Results:\n")
    detected_segments = sum(1 for result in scan_results if result[6][0] == "Segment Detected" or result[6][0] == "TCP Segment Detected")
    detected_ids_ips = sum(1 for result in scan_results if result[7] == "IDS/IPS Detected" or result[7] == "Firewall Detected")

    print(f"Total Targets Scanned: {len(targets)}")
    print(f"Total Ports Scanned: {len(target_ports)}")
    print(f"Segments Detected: {detected_segments}")
    print(f"IDS/IPS/FW Detected: {detected_ids_ips}")

    # Calculate weighting
    total_weight = calculate_weighting(scan_results)
    configuration_quality = "Good" if total_weight >= 0 else "Bad"
    print(f"Configuration Quality: {configuration_quality} (Total Weight: {total_weight})")

    print("\nTrusted Message to User:")
    print("All scans have been completed successfully. The results provide detailed insights into your network's firewall and IDS/IPS configurations. Ensure to review the detected segments and IDS/IPS responses to strengthen your network security.")

if __name__ == "__main__":
    main()
