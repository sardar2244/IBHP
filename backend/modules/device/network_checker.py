from adb_interface import ADBInterface

class NetworkChecker:
    def __init__(self):
        self.adb = ADBInterface()
        self.vulnerabilities = []
        self.safe = []

    def check_wifi_state(self):
        result = self.adb.run_command(
            "dumpsys wifi | grep 'Wi-Fi is'"
        )
        if result:
            self.safe.append({
                'name': 'WiFi State',
                'status': result
            })

    def check_bluetooth(self):
        result = self.adb.run_command(
            "settings get global bluetooth_on"
        )
        if result == '1':
            self.vulnerabilities.append({
                'id': 'NET001',
                'name': 'Bluetooth ON',
                'severity': 'LOW',
                'description': 'Bluetooth Enabled Hai',
                'remediation': 'Jab Use Na Ho Bluetooth Off Karo'
            })
        else:
            self.safe.append({
                'name': 'Bluetooth',
                'status': 'SECURE - Disabled'
            })

    def check_nfc(self):
        result = self.adb.run_command(
            "settings get global nfc_on"
        )
        if result == '1':
            self.vulnerabilities.append({
                'id': 'NET002',
                'name': 'NFC ON',
                'severity': 'LOW',
                'description': 'NFC Enabled Hai',
                'remediation': 'Jab Use Na Ho NFC Off Karo'
            })
        else:
            self.safe.append({
                'name': 'NFC',
                'status': 'SECURE - Disabled'
            })

    def check_airplane_mode(self):
        result = self.adb.run_command(
            "settings get global airplane_mode_on"
        )
        if result == '0':
            self.safe.append({
                'name': 'Airplane Mode',
                'status': 'Normal - OFF'
            })

    def check_vpn(self):
        result = self.adb.run_command(
            "dumpsys connectivity | grep VPN"
        )
        if result:
            self.safe.append({
                'name': 'VPN',
                'status': result
            })

    def run_all_checks(self):
        print("\n=============================")
        print("  NETWORK SECURITY SCAN")
        print("=============================\n")

        self.check_wifi_state()
        self.check_bluetooth()
        self.check_nfc()
        self.check_airplane_mode()
        self.check_vpn()

        print("✅ SECURE ITEMS:")
        print("------------------------")
        for item in self.safe:
            print(f"✅ {item['name']}: {item['status']}")

        print("\n⚠️ VULNERABILITIES FOUND:")
        print("------------------------")
        if len(self.vulnerabilities) == 0:
            print("🎉 No Vulnerabilities Found!")
        else:
            for vuln in self.vulnerabilities:
                print(f"\n🔴 ID: {vuln['id']}")
                print(f"   Name: {vuln['name']}")
                print(f"   Severity: {vuln['severity']}")
                print(f"   Issue: {vuln['description']}")
                print(f"   Fix: {vuln['remediation']}")

        print("\n=============================")
        print(f"Total Secure: {len(self.safe)}")
        print(f"Total Issues: {len(self.vulnerabilities)}")
        print("=============================\n")

if __name__ == "__main__":
    checker = NetworkChecker()
    checker.run_all_checks()