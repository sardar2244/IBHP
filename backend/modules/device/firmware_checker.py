import sys
import os
sys.path.append(
    os.path.join(os.path.dirname(__file__))
)
from adb_interface import ADBInterface

class FirmwareChecker:
    def __init__(self):
        self.adb = ADBInterface()
        self.vulnerabilities = []
        self.safe = []

    def check_bootloader(self):
        result = self.adb.check_bootloader()
        if 'orange' in result or 'unlocked' in result:
            self.vulnerabilities.append({
                'id': 'FW001',
                'name': 'Unlocked Bootloader',
                'severity': 'CRITICAL',
                'description': 'Bootloader Unlocked Hai',
                'remediation': 'Bootloader Lock Karo'
            })
        else:
            self.safe.append({
                'name': 'Bootloader',
                'status': 'SECURE - Locked'
            })

    def check_selinux(self):
        result = self.adb.check_selinux()
        if 'Permissive' in result:
            self.vulnerabilities.append({
                'id': 'FW002',
                'name': 'SELinux Permissive',
                'severity': 'HIGH',
                'description': 'SELinux Permissive Mode Mein Hai',
                'remediation': 'SELinux Enforcing Mode Karo'
            })
        else:
            self.safe.append({
                'name': 'SELinux',
                'status': 'SECURE - Enforcing'
            })

    def check_encryption(self):
        result = self.adb.check_encryption()
        if 'unencrypted' in result:
            self.vulnerabilities.append({
                'id': 'FW003',
                'name': 'No Encryption',
                'severity': 'CRITICAL',
                'description': 'Phone Encrypted Nahi Hai',
                'remediation': 'Phone Encryption Enable Karo'
            })
        else:
            self.safe.append({
                'name': 'Encryption',
                'status': 'SECURE - Encrypted'
            })

    def check_security_patch(self):
        result = self.adb.check_security_patch()
        self.safe.append({
            'name': 'Security Patch',
            'status': f'Patch Level: {result}'
        })

    def check_usb_debug(self):
        result = self.adb.check_usb_debug()
        if result == '1':
            self.vulnerabilities.append({
                'id': 'FW004',
                'name': 'USB Debugging ON',
                'severity': 'MEDIUM',
                'description': 'USB Debugging Enabled Hai',
                'remediation': 'USB Debugging Disable Karo'
            })
        else:
            self.safe.append({
                'name': 'USB Debugging',
                'status': 'SECURE - Disabled'
            })

    def run_all_checks(self):
        print("\n=============================")
        print("  DEVICE SECURITY SCAN")
        print("=============================\n")

        self.check_bootloader()
        self.check_selinux()
        self.check_encryption()
        self.check_security_patch()
        self.check_usb_debug()

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
    checker = FirmwareChecker()
    checker.run_all_checks()