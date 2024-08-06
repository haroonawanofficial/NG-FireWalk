# Overview

Next Generation Firewalk is a comprehensive tool designed for advanced network reconnaissance and penetration testing. It employs various evasion techniques to bypass AI-ML-based firewalls, IDS, and IPS systems, making it an effective tool for security professionals and ethical hackers.

# Features of NG-FireWalk
- Evasion Techniques: Multiple methods to avoid detection by AI/ML-based security systems.
- Support for Various Protocols: ICMP, TCP, UDP, DNS, HTTP, etc.
- Custom Payloads: Ability to use custom payloads for more sophisticated scanning.
- Multi-threading: Utilizes ThreadPoolExecutor for efficient scanning.
- Logging: Detailed logging of all scan activities.
- Custom Tool Integration: Ability to run custom tools and include their results in the analysis.
- Deep Packet Inspection: Analyzes the packets sent and received for better understanding and logging.

Here's the text without any formatting that you can copy and paste:

## Evasion Techniques
| Techniques                    | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| icmp_with_dns                 | ICMP packets with DNS payloads to blend in with normal DNS traffic.                                |
| icmp_with_http                | ICMP packets with HTTP payloads to confuse detection algorithms.                                   |
| tcp_with_http                 | TCP packets with HTTP payloads to mimic legitimate web traffic.                                    |
| udp_with_dns                  | UDP packets with DNS queries to blend in with normal DNS traffic.                                  |
| icmp_with_custom_data         | ICMP packets with custom payloads to evade detection.                                              |
| tcp_syn_with_custom_payload   | TCP SYN packets with custom payloads for advanced evasion.                                         |
| udp_with_custom_payload       | UDP packets with custom payloads for advanced evasion.                                             |
| tcp_ack_with_dns              | TCP ACK packets with DNS queries to bypass firewalls.                                              |
| tcp_rst_with_http             | TCP RST packets with HTTP payloads to confuse AI/ML models.                                        |
| udp_with_http                 | UDP packets with HTTP payloads to blend in with web traffic.                                       |
| icmp_timestamp_request        | ICMP timestamp requests to evade simple ICMP detection.                                            |
| tcp_fin_with_dns              | TCP FIN packets with DNS queries to bypass detection.                                              |
| tcp_urg_with_http             | TCP URG packets with HTTP payloads for evasion.                                                    |
| udp_with_icmp                 | UDP packets with embedded ICMP messages to evade detection.                                        |
| tcp_psh_with_dns              | TCP PSH packets with DNS queries to bypass AI/ML-based defenses.                                    |
| icmp_address_mask_request     | ICMP address mask requests for evasion.                                                            |
| tcp_syn_ack_with_http         | TCP SYN-ACK packets with HTTP payloads to confuse detection.                                       |
| udp_with_random_data          | UDP packets with random data to evade detection.                                                   |
| tcp_with_random_data          | TCP packets with random data to evade detection.                                                   |
| icmp_echo_with_random_data    | ICMP echo requests with random data for evasion.                                                   |
| random_ttl_icmp               | ICMP packets with random TTL values to evade detection.                                            |
| tcp_window_size_manipulation  | TCP packets with manipulated window sizes for evasion.                                             |
| tcp_timestamp_manipulation    | TCP packets with manipulated timestamps to evade detection.                                        |
| ip_option_padding             | IP packets with padding options to bypass firewalls.                                               |
| tcp_flag_scan                 | TCP packets with random flags for evasion.                                                         |
| decoy_scan                    | TCP packets with decoy IP addresses to confuse detection.                                          |
| adaptive_timing_scan          | Scans with random delays to evade timing-based detection.                                          |
| mixed_protocol_scan           | Use of mixed protocols (TCP, UDP, ICMP) to evade detection.                                        |
| tcp_syn_flood                 | High volume TCP SYN packets to overwhelm and evade detection.                                      |
| randomized_payload_scan       | TCP/UDP packets with random payloads for evasion.                                                  |
| ai_ml_firewall_bypass         | Specific technique to evade AI/ML-based firewalls using randomized user agents.                    |

## AI/ML-based Firewalls, IDS, and IPS Bypassed
The following table lists the AI/ML-based security systems that the Ng FireWalk can bypass, along with the corresponding techniques:

| Security System                | Bypassing Technique                                                                             |
|--------------------------------|-------------------------------------------------------------------------------------------------|
| Palo Alto Networks             | tcp_with_http, icmp_with_http                                                                    |
| Cisco Firepower                | udp_with_dns, tcp_syn_with_custom_payload                                                        |
| Fortinet FortiGate             | icmp_with_dns, tcp_ack_with_dns                                                                  |
| Check Point Firewall           | tcp_rst_with_http, udp_with_http                                                                 |
| Juniper SRX                    | icmp_timestamp_request, tcp_fin_with_dns                                                         |
| McAfee NSP                     | tcp_urg_with_http, udp_with_icmp                                                                 |
| IBM QRadar                     | tcp_psh_with_dns, icmp_address_mask_request                                                      |
| Symantec Blue Coat             | tcp_syn_ack_with_http, udp_with_random_data                                                      |
| Trend Micro TippingPoint       | tcp_with_random_data, icmp_echo_with_random_data                                                 |
| Barracuda NextGen              | random_ttl_icmp, tcp_window_size_manipulation                                                    |
| Forcepoint NGFW                | tcp_timestamp_manipulation, ip_option_padding                                                    |
| Sophos XG Firewall             | tcp_flag_scan, decoy_scan                                                                        |
| WatchGuard Firebox             | adaptive_timing_scan, mixed_protocol_scan                                                        |
| F5 Networks                    | tcp_syn_flood, randomized_payload_scan                                                           |
| Imperva SecureSphere           | ai_ml_firewall_bypass                                                                           |

# Usage
```bash
python ng-firewalk.py --target <target_ip(s)> --ports <target_port(s)> [options]
Options
--target: Target IP address (comma-separated for multiple targets).
--ports: Comma-separated list of target ports (for TCP/UDP scans).
--threads: Number of threads to use for scanning (default: 10).
--evasion: Enable evasion techniques.
--firewalk: Enable AI/ML firewall bypass techniques.
--customtool: Custom tool command to execute.
```
Example
```bash
python ng-firewalk.py --target 192.168.1.1 --ports 80,443 --evasion --firewalk
```
# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Screenshot
![Firewalk](https://i.ibb.co/r77WGZ4/firewalk1.png)

# Contact
- Haroon Ahmad Awan
- haroon@cyberzeus.pk


