import sys
import os
import subprocess

sys.path.append(os.path.dirname(__file__))
from adb_interface import ADBInterface

ADB_PATH = r"C:\platform-tools\adb.exe"

class TrafficAnalyzer:
    def __init__(self):
        self.adb = ADBInterface()
        self.findings = []

    def get_netstats(self):
        """dumpsys netstats - No Proxy"""
        try:
            result = subprocess.run(
                f'"{ADB_PATH}" shell dumpsys netstats',
                capture_output=True,
                shell=True,
                timeout=15
            )
            return result.stdout.decode(
                'utf-8', errors='replace'
            )
        except Exception as e:
            return ""

    def parse_netstats(self, netstats_data):
        """Netstats Parse Karo"""
        stats = {
            'wifi_rx': 0,
            'wifi_tx': 0,
            'mobile_rx': 0,
            'mobile_tx': 0,
            'apps': []
        }
        
        lines = netstats_data.split('\n')
        for line in lines:
            try:
                if 'rxBytes' in line:
                    parts = line.strip().split()
                    for part in parts:
                        if 'rxBytes' in part:
                            val = part.split('=')[1]
                            stats['wifi_rx'] += int(val)
                if 'txBytes' in line:
                    parts = line.strip().split()
                    for part in parts:
                        if 'txBytes' in part:
                            val = part.split('=')[1]
                            stats['wifi_tx'] += int(val)
            except Exception:
                continue
        return stats

    def get_proc_net_tcp(self):
        """TCP Connections - No Proxy"""
        try:
            result = subprocess.run(
                f'"{ADB_PATH}" shell cat /proc/net/tcp',
                capture_output=True,
                shell=True,
                timeout=10
            )
            data = result.stdout.decode(
                'utf-8', errors='replace'
            )
            
            connections = []
            lines = data.split('\n')[1:]
            
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    state = parts[3]
                    local = self.hex_to_ip(parts[1])
                    remote = self.hex_to_ip(parts[2])
                    
                    state_map = {
                        '01': 'ESTABLISHED',
                        '02': 'SYN_SENT',
                        '0A': 'LISTEN',
                        '06': 'TIME_WAIT'
                    }
                    
                    state_name = state_map.get(
                        state, 'UNKNOWN'
                    )
                    
                    if state_name == 'ESTABLISHED':
                        connections.append({
                            'local': local,
                            'remote': remote,
                            'state': state_name
                        })
            
            return connections
        except Exception as e:
            return []

    def hex_to_ip(self, hex_addr):
        """Hex IP Convert"""
        try:
            addr, port = hex_addr.split(':')
            ip = '.'.join([
                str(int(addr[i:i+2], 16))
                for i in range(6, -2, -2)
            ])
            port_num = int(port, 16)
            return f"{ip}:{port_num}"
        except Exception:
            return hex_addr

    def check_http_in_logs(self):
        """HTTP Traffic In Logs"""
        try:
            result = subprocess.run(
                f'"{ADB_PATH}" shell logcat -d -t 200',
                capture_output=True,
                shell=True,
                timeout=15
            )
            logs = result.stdout.decode(
                'utf-8', errors='replace'
            )
            
            http_found = False
            ssl_errors = False
            
            for line in logs.split('\n'):
                line_lower = line.lower()
                if 'http://' in line_lower:
                    http_found = True
                if 'ssl error' in line_lower or \
                   'certificate' in line_lower:
                    ssl_errors = True
            
            return http_found, ssl_errors
        except Exception:
            return False, False

    def check_app_network_usage(self, package):
        """App Ki Network Usage"""
        try:
            result = self.adb.run_command(
                f"dumpsys netstats | grep {package}"
            )
            if result:
                return {
                    'package': package,
                    'has_network_activity': True,
                    'data': result[:200]
                }
            return {
                'package': package,
                'has_network_activity': False
            }
        except Exception:
            return {}

    def check_suspicious_connections(self, connections):
        """Suspicious IPs Check"""
        suspicious_ports = [
            4444, 5555, 31337, 1337,
            8080, 9090, 3333
        ]
        
        suspicious = []
        for conn in connections:
            try:
                port = int(
                    conn['remote'].split(':')[1]
                )
                if port in suspicious_ports:
                    suspicious.append({
                        'connection': conn,
                        'reason': f'Suspicious Port {port}'
                    })
            except Exception:
                continue
        return suspicious

    def run_analysis(self, package=None):
        print("\n=============================")
        print("  PROXYLESS TRAFFIC ANALYSIS")
        print("  Method: ADB + dumpsys netstats")
        print("  No Proxy Used!")
        print("=============================\n")

        results = {
            'method': 'ADB Stats - No Proxy',
            'findings': [],
            'stats': {},
            'connections': [],
            'suspicious': []
        }

        # 1. Netstats
        print("📊 [1/5] Getting Network Stats...")
        netstats = self.get_netstats()
        if netstats:
            stats = self.parse_netstats(netstats)
            results['stats'] = stats
            print(f"✅ RX: {stats['wifi_rx']} bytes")
            print(f"✅ TX: {stats['wifi_tx']} bytes")
        else:
            print("⚠️ Netstats unavailable")

        # 2. TCP Connections
        print("\n🔌 [2/5] TCP Connections...")
        connections = self.get_proc_net_tcp()
        results['connections'] = connections
        print(f"Active Connections: {len(connections)}")
        
        for conn in connections[:5]:
            print(f"  → {conn['remote']} ({conn['state']})")

        # 3. Suspicious Connections
        print("\n🔍 [3/5] Suspicious Port Check...")
        suspicious = self.check_suspicious_connections(
            connections
        )
        if suspicious:
            results['findings'].append({
                'id': 'TRF001',
                'name': 'Suspicious Ports Detected',
                'severity': 'HIGH',
                'description': (
                    f'{len(suspicious)} Suspicious '
                    f'Connections Found'
                ),
                'remediation': 'Investigate connections'
            })
            print(f"⚠️ {len(suspicious)} Suspicious!")
        else:
            print("✅ No Suspicious Ports!")

        # 4. HTTP Traffic
        print("\n🔍 [4/5] HTTP Traffic Check...")
        http_found, ssl_errors = self.check_http_in_logs()
        
        if http_found:
            results['findings'].append({
                'id': 'TRF002',
                'name': 'HTTP Traffic Detected',
                'severity': 'HIGH',
                'description': 'Unencrypted HTTP Found',
                'remediation': 'Use HTTPS Only'
            })
            print("⚠️ HTTP Traffic Found!")
        else:
            print("✅ No HTTP Traffic!")

        if ssl_errors:
            results['findings'].append({
                'id': 'TRF003',
                'name': 'SSL Errors Detected',
                'severity': 'HIGH',
                'description': 'SSL Certificate Issues',
                'remediation': 'Fix SSL Implementation'
            })
            print("⚠️ SSL Errors Found!")
        else:
            print("✅ No SSL Errors!")

        # 5. App Network Usage
        if package:
            print(f"\n📱 [5/5] App Network Usage...")
            app_usage = self.check_app_network_usage(
                package
            )
            results['app_usage'] = app_usage
            if app_usage.get('has_network_activity'):
                print(f"✅ {package} Network Active!")
            else:
                print(f"ℹ️ No Data For {package}")

        # Summary
        print("\n=============================")
        print("  TRAFFIC ANALYSIS COMPLETE")
        print("=============================")
        print(f"Total Issues: {len(results['findings'])}")
        print(f"Connections: {len(connections)}")
        print(f"Method: No Proxy - ADB Stats")

        for finding in results['findings']:
            print(f"\n🔴 {finding['name']}")
            print(f"   Severity: {finding['severity']}")
            print(f"   Fix: {finding['remediation']}")

        return results


if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    results = analyzer.run_analysis(
        'com.snapchat.android'
    )