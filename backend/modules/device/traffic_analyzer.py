import sys
import os
sys.path.append(os.path.dirname(__file__))
from adb_interface import ADBInterface

class TrafficAnalyzer:
    def __init__(self):
        self.adb = ADBInterface()
        self.findings = []

    def get_network_stats(self):
        """ADB Stats Se Traffic Data"""
        result = self.adb.run_command(
            "cat /proc/net/tcp"
        )
        return result

    def get_netstats(self):
        """Dumpsys Netstats"""
        result = self.adb.run_command(
            "dumpsys netstats | head -50"
        )
        return result

    def check_dns_queries(self):
        """DNS Query Analysis"""
        result = self.adb.run_command(
            "cat /proc/net/udp"
        )
        suspicious = []
        suspicious_domains = [
            'evil', 'malware', 'hack',
            'phish', 'trojan'
        ]
        for domain in suspicious_domains:
            if domain in result.lower():
                suspicious.append(domain)
        return suspicious

    def check_open_connections(self):
        """Open TCP Connections"""
        result = self.adb.run_command(
            "cat /proc/net/tcp"
        )
        connections = []
        lines = result.split('\n')[1:]
        for line in lines[:20]:
            parts = line.strip().split()
            if len(parts) > 3:
                state = parts[3]
                if state == '01':
                    connections.append({
                        'local': parts[1],
                        'remote': parts[2],
                        'state': 'ESTABLISHED'
                    })
        return connections

    def check_wifi_stats(self):
        """WiFi Traffic Stats"""
        result = self.adb.run_command(
            "dumpsys wifi | grep -E 'rssi|freq|speed'"
        )
        return result

    def check_http_traffic(self):
        """HTTP Traffic Detection Without Proxy"""
        result = self.adb.run_command(
            "logcat -d | grep -i 'http://'"
        )
        if 'http://' in result.lower():
            self.findings.append({
                'id': 'TRF001',
                'name': 'HTTP Traffic Detected',
                'severity': 'HIGH',
                'description': (
                    'Unencrypted HTTP Traffic Found'
                ),
                'remediation': 'Use HTTPS Instead'
            })

    def check_ssl_errors(self):
        """SSL Error Detection"""
        result = self.adb.run_command(
            "logcat -d | grep -i 'ssl error'"
        )
        if result:
            self.findings.append({
                'id': 'TRF002',
                'name': 'SSL Errors Detected',
                'severity': 'HIGH',
                'description': 'SSL Certificate Errors',
                'remediation': 'Fix SSL Implementation'
            })

    def run_analysis(self):
        print("\n=============================")
        print("  PROXYLESS TRAFFIC ANALYSIS")
        print("  (Using ADB Stats - No Proxy)")
        print("=============================\n")

        # Network Stats
        print("📊 Getting Network Stats...")
        netstats = self.get_netstats()
        if netstats:
            print("✅ Network Stats Retrieved!")

        # Open Connections
        print("\n🔌 Checking Connections...")
        connections = self.check_open_connections()
        print(f"Active Connections: {len(connections)}")

        # HTTP Traffic
        print("\n🔍 Checking HTTP Traffic...")
        self.check_http_traffic()

        # SSL Errors
        print("🔍 Checking SSL Errors...")
        self.check_ssl_errors()

        # DNS
        print("🔍 Checking DNS...")
        dns = self.check_dns_queries()
        if dns:
            self.findings.append({
                'id': 'TRF003',
                'name': 'Suspicious DNS Queries',
                'severity': 'HIGH',
                'description': f'Found: {dns}',
                'remediation': 'Check DNS Configurations'
            })

        # Results
        print("\n=============================")
        print("  TRAFFIC ANALYSIS RESULTS")
        print("=============================")

        if not self.findings:
            print("✅ No Traffic Issues Found!")
        else:
            for finding in self.findings:
                print(f"\n🔴 {finding['name']}")
                print(f"   Severity: {finding['severity']}")
                print(f"   Fix: {finding['remediation']}")

        print(f"\nTotal Issues: {len(self.findings)}")
        return {
            'findings': self.findings,
            'connections': len(connections),
            'method': 'ADB Stats - No Proxy Used'
        }


if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    results = analyzer.run_analysis()