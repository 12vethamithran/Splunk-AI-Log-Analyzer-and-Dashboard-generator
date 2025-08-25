"""
Log Processing Module
Detects log types and extracts fields using regex patterns
"""

import re
import json
from typing import Dict, List

class LogProcessor:
    def __init__(self):
        self.log_patterns = {
            'firewall_custom': {
                # Matches various firewall log formats:
                # 2025-08-22 09:15:23 [ALLOW] TCP 192.168.1.45:3421 -> 203.0.113.15:80 HTTP GET request - User browsing
                # 2025-08-22 09:15:48 [BLOCK] ICMP 101.202.33.44:0 -> 192.168.1.1:0 Ping flood attack detected
                'pattern': r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\w+)\s+([^\s:]+):(\d+)\s+->\s+([^\s:]+):(\d+)\s+(.*)',
                'fields': ['timestamp', 'action', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'description'],
                'description': 'Custom firewall logs with timestamp, action, IPs, ports, and description'
            },
            'dns': {
                # Matches: client 192.168.1.55#12345: query: google.com IN A + (192.168.1.1)
                'pattern': r'client\s+(\d+\.\d+\.\d+\.\d+).*query:\s+(\S+)\s+IN\s+(\w+)',
                'fields': ['client_ip', 'domain', 'query_type'],
                'description': 'DNS query logs with domains, query types, and client IPs'
            },
            'firewall': {
                # Matches: action=allow src=192.168.1.10 dst=8.8.8.8 protocol=udp dport=53
                'pattern': r'action=(\w+)\s+src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+protocol=(\w+)\s+dport=(\d+)',
                'fields': ['action', 'src_ip', 'dst_ip', 'protocol', 'dst_port'],
                'description': 'Standard firewall logs with actions, IPs, and ports'
            },
            'apache': {
                # Matches: 192.168.1.101 - - [19/Jan/2025:10:30:01 +0000] "GET /index.html HTTP/1.1" 200 4523
                'pattern': r'(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+([^\s]+).*"\s+(\d{3})\s+(\d+)',
                'fields': ['client_ip', 'timestamp', 'method', 'url', 'status_code', 'response_size'],
                'description': 'Apache web server access logs'
            },
            'syslog': {
                # Matches: Jan 19 10:15:32 localhost sshd[1024]: message...
                'pattern': r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)',
                'fields': ['timestamp', 'hostname', 'process', 'message'],
                'description': 'System logs with process information and messages'
            },
            'json': {
                'pattern': r'^\s*\{.*\}\s*$',
                'fields': ['json_data'],
                'description': 'JSON formatted logs'
            }
        }

    def detect_log_type(self, log_lines: List[str], sample_size: int = 10) -> str:
        """Detect the type of log based on regex matches"""
        print("🔍 Detecting log type...")
        test_lines = log_lines[:min(sample_size, len(log_lines))]
        scores = {}

        for log_type, config in self.log_patterns.items():
            pattern = config['pattern']
            matches = 0
            for line in test_lines:
                line = line.strip()  # Strip whitespace
                if line and re.search(pattern, line):
                    matches += 1
            scores[log_type] = matches / len([l for l in test_lines if l.strip()]) if test_lines else 0

        # Best match
        best_match = max(scores.items(), key=lambda x: x[1])
        detected_type = best_match[0] if best_match[1] > 0.1 else 'unknown'

        print(f"📊 Detection scores:")
        for log_type, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
            print(f"   {log_type}: {score:.2%}")

        print(f"✅ Detected log type: {detected_type}")
        if detected_type != 'unknown':
            print(f"📋 Description: {self.log_patterns[detected_type]['description']}")
        else:
            print("❌ No matching log pattern found. Consider adding a new pattern.")
            print("📝 Sample lines for debugging:")
            for i, line in enumerate(test_lines[:3]):
                if line.strip():
                    print(f"   Line {i+1}: {line.strip()}")
        return detected_type

    def extract_fields(self, log_lines: List[str], log_type: str) -> List[Dict]:
        """Extract fields from logs"""
        print(f"🔧 Extracting fields for {log_type} logs...")

        if log_type not in self.log_patterns:
            print(f"❌ Unknown log type: {log_type}")
            return []

        pattern = self.log_patterns[log_type]['pattern']
        field_names = self.log_patterns[log_type]['fields']
        extracted_data = []
        successful_extractions = 0
        failed_lines = []

        for line_num, line in enumerate(log_lines, 1):
            line = line.strip()
            if not line:  # Skip empty lines
                continue
                
            if log_type == 'json':
                try:
                    json_data = json.loads(line)
                    record = {'_raw': line, 'json_data': json_data}
                    extracted_data.append(record)
                    successful_extractions += 1
                except json.JSONDecodeError:
                    failed_lines.append((line_num, line))
                    continue
            else:
                match = re.search(pattern, line)
                if match:
                    record = {'_raw': line, 'line_number': line_num}
                    for i, field_name in enumerate(field_names):
                        try:
                            record[field_name] = match.group(i + 1)
                        except IndexError:
                            record[field_name] = ''
                    extracted_data.append(record)
                    successful_extractions += 1
                else:
                    failed_lines.append((line_num, line))

        non_empty_lines = len([l for l in log_lines if l.strip()])
        success_rate = (successful_extractions / non_empty_lines) * 100 if non_empty_lines > 0 else 0
        print(f"✅ Extracted {successful_extractions} records from {non_empty_lines} non-empty lines ({success_rate:.1f}% success rate)")
        
        if failed_lines and successful_extractions == 0:
            print("❌ No successful extractions. Sample failed lines:")
            for line_num, line in failed_lines[:3]:
                print(f"   Line {line_num}: {line}")
        elif failed_lines:
            print(f"⚠️  {len(failed_lines)} lines failed to parse")
            
        return extracted_data
