import subprocess
import sys
import os

sys.path.append(os.path.dirname(__file__))
from adb_interface import ADBInterface

ADB_PATH = r"C:\platform-tools\adb.exe"

class DynamicAnalyzer:
    def __init__(self):
        self.adb = ADBInterface()
        self.findings = []
        self.package_name = None

    def get_installed_apps(self):
        result = self.adb.run_command(
            "pm list packages -3"
        )
        apps = []
        for line in result.split('\n'):
            if 'package:' in line:
                apps.append(
                    line.replace('package:', '').strip()
                )
        return apps

    def get_logcat_output(self, package):
        try:
            # Encoding Fix
            result = subprocess.run(
                f'"{ADB_PATH}" logcat -d '
                f'-v brief *:W',
                capture_output=True,
                shell=True,
                timeout=15
            )
            # Force UTF-8 Ignore Errors
            logs = result.stdout.decode(
                'utf-8', errors='replace'
            )

            sensitive_keywords = [
                'password', 'token', 'secret',
                'api_key', 'credential', 'auth',
                'private', 'key', 'username'
            ]

            findings = []
            seen = set()

            for line in logs.split('\n'):
                try:
                    line_lower = line.lower()
                    for keyword in sensitive_keywords:
                        if (keyword in line_lower and
                                keyword not in seen):
                            seen.add(keyword)
                            findings.append({
                                'type': 'Sensitive Log',
                                'keyword': keyword,
                                'line': line[:100]
                            })
                            break
                except Exception:
                    continue

            return findings
        except Exception as e:
            print(f"Log Error: {str(e)[:50]}")
            return []

    def check_runtime_permissions(self, package):
        try:
            result = self.adb.run_command(
                f"dumpsys package {package}"
            )
            dangerous = []
            dangerous_perms = [
                'CAMERA', 'ACCESS_FINE_LOCATION',
                'READ_CONTACTS', 'RECORD_AUDIO',
                'READ_SMS', 'CALL_PHONE',
                'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS'
            ]
            for perm in dangerous_perms:
                if perm in result:
                    dangerous.append(perm)
            return dangerous
        except Exception:
            return []

    def check_network_connections(self):
        try:
            result = self.adb.run_command(
                "netstat -an 2>/dev/null"
            )
            connections = []
            for line in result.split('\n'):
                if 'ESTABLISHED' in line:
                    connections.append(
                        line.strip()[:80]
                    )
            return connections
        except Exception:
            return []

    def check_open_ports(self):
        try:
            result = self.adb.run_command(
                "netstat -tuln 2>/dev/null"
            )
            ports = []
            for line in result.split('\n'):
                if 'LISTEN' in line:
                    ports.append(line.strip()[:80])
            return ports
        except Exception:
            return []

    def check_cleartext_traffic(self, package):
        try:
            result = self.adb.run_command(
                f"dumpsys package {package} | grep cleartextTrafficPermitted"
            )
            if 'true' in result.lower():
                return True
            return False
        except Exception:
            return False

    def check_backup_enabled(self, package):
        try:
            result = self.adb.run_command(
                f"dumpsys package {package} | grep allowBackup"
            )
            if 'true' in result.lower():
                return True
            return False
        except Exception:
            return False

    def check_debuggable(self, package):
        try:
            result = self.adb.run_command(
                f"dumpsys package {package} | grep FLAG_DEBUGGABLE"
            )
            return bool(result.strip())
        except Exception:
            return False

    def check_ssl_pinning(self, package):
        try:
            result = self.adb.run_command(
                f"dumpsys package {package} | grep networkSecurityConfig"
            )
            if result.strip():
                return True
            return False
        except Exception:
            return False

    def run_dynamic_analysis(self, package=None):
        print("\n=============================")
        print("  DYNAMIC ANALYSIS SCAN")
        print("=============================\n")

        apps = self.get_installed_apps()
        print(f"📱 Total Apps: {len(apps)}")

        if not package and apps:
            package = apps[0]

        print(f"📦 Target: {package}")
        self.package_name = package

        results = {
            'package': package,
            'vulnerabilities': [],
            'safe': [],
            'runtime_info': {}
        }

        # 1. Log Analysis
        print("\n🔍 [1/6] Log Analysis...")
        log_findings = self.get_logcat_output(package)
        if log_findings:
            results['vulnerabilities'].append({
                'id': 'DYN001',
                'name': 'Sensitive Data In Logs',
                'severity': 'HIGH',
                'description': (
                    f'{len(log_findings)} Sensitive '
                    f'Keywords Found In Logs'
                ),
                'remediation': (
                    'Production Mein Logging Disable Karo'
                )
            })
            print(f"⚠️ {len(log_findings)} Issues!")
        else:
            results['safe'].append({
                'name': 'Log Analysis',
                'status': 'No Sensitive Data Found'
            })
            print("✅ Logs Clean!")

        # 2. Network Connections
        print("\n🔍 [2/6] Network Analysis...")
        connections = self.check_network_connections()
        results['runtime_info']['connections'] = (
            len(connections)
        )
        print(f"🌐 Active Connections: {len(connections)}")

        # 3. Open Ports
        print("\n🔍 [3/6] Port Analysis...")
        ports = self.check_open_ports()
        if ports:
            results['vulnerabilities'].append({
                'id': 'DYN002',
                'name': 'Open Network Ports',
                'severity': 'MEDIUM',
                'description': (
                    f'{len(ports)} Open Ports Found'
                ),
                'remediation': (
                    'Unnecessary Ports Band Karo'
                )
            })
            print(f"⚠️ {len(ports)} Open Ports!")
        else:
            results['safe'].append({
                'name': 'Port Analysis',
                'status': 'No Dangerous Ports'
            })
            print("✅ No Dangerous Ports!")

        # 4. Permissions
        print("\n🔍 [4/6] Permission Analysis...")
        perms = self.check_runtime_permissions(package)
        if perms:
            results['vulnerabilities'].append({
                'id': 'DYN003',
                'name': 'Dangerous Permissions',
                'severity': 'HIGH',
                'description': (
                    f'Permissions: {", ".join(perms)}'
                ),
                'remediation': (
                    'Sirf Zarori Permissions Lo'
                )
            })
            print(f"⚠️ Dangerous Perms: {', '.join(perms)}")
        else:
            results['safe'].append({
                'name': 'Permissions',
                'status': 'No Dangerous Permissions'
            })
            print("✅ Permissions Safe!")

        # 5. Cleartext Traffic
        print("\n🔍 [5/6] Traffic Analysis...")
        cleartext = self.check_cleartext_traffic(package)
        if cleartext:
            results['vulnerabilities'].append({
                'id': 'DYN004',
                'name': 'Cleartext Traffic Allowed',
                'severity': 'HIGH',
                'description': (
                    'App HTTP Traffic Allow Karta Hai'
                ),
                'remediation': (
                    'HTTPS Use Karo, HTTP Band Karo'
                )
            })
            print("⚠️ Cleartext Traffic Allowed!")
        else:
            results['safe'].append({
                'name': 'Traffic',
                'status': 'HTTPS Enforced'
            })
            print("✅ Traffic Secure!")

        # 6. Debuggable Check
        print("\n🔍 [6/6] Debug Analysis...")
        debuggable = self.check_debuggable(package)
        if debuggable:
            results['vulnerabilities'].append({
                'id': 'DYN005',
                'name': 'App Is Debuggable',
                'severity': 'HIGH',
                'description': (
                    'Production App Debug Mode Mein Hai'
                ),
                'remediation': (
                    'android:debuggable=false Karo'
                )
            })
            print("⚠️ App Is Debuggable!")
        else:
            results['safe'].append({
                'name': 'Debug Mode',
                'status': 'Not Debuggable'
            })
            print("✅ Not Debuggable!")

        # Final Summary
        print("\n=============================")
        print("  DYNAMIC SCAN COMPLETE")
        print("=============================")
        
        critical = sum(
            1 for v in results['vulnerabilities']
            if v['severity'] == 'CRITICAL'
        )
        high = sum(
            1 for v in results['vulnerabilities']
            if v['severity'] == 'HIGH'
        )
        medium = sum(
            1 for v in results['vulnerabilities']
            if v['severity'] == 'MEDIUM'
        )

        print(f"🔴 Critical: {critical}")
        print(f"🟠 High: {high}")
        print(f"🟡 Medium: {medium}")
        print(f"✅ Safe: {len(results['safe'])}")
        print(f"Total Issues: {len(results['vulnerabilities'])}")
        print("=============================\n")

        for vuln in results['vulnerabilities']:
            print(f"🔴 {vuln['name']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Fix: {vuln['remediation']}\n")

        return results


if __name__ == "__main__":
    analyzer = DynamicAnalyzer()

    apps = analyzer.get_installed_apps()
    print(f"Total Installed Apps: {len(apps)}")
    print("\nTop 10 Apps:")
    for app in apps[:10]:
        print(f"  → {app}")

    targets = [
        'jakhar.aseem.diva',
        'com.snapchat.android',
        'com.instagram.android',
        'com.facebook.orca',
        'com.zhiliaoapp.musically'
    ]

    target = None
    for t in targets:
        if t in apps:
            target = t
            print(f"\n✅ Analyzing: {target}")
            break

    if not target and apps:
        target = apps[0]
        print(f"\n📦 Analyzing: {target}")

    if target:
        results = analyzer.run_dynamic_analysis(target)