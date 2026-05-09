from androguard.misc import AnalyzeAPK
import os

class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.vulnerabilities = []
        self.safe = []
        self.app, self.d, self.dx = AnalyzeAPK(apk_path)

    def get_basic_info(self):
        print("\n=============================")
        print("  APP BASIC INFO")
        print("=============================\n")
        print(f"📱 App Name: {self.app.get_app_name()}")
        print(f"📦 Package: {self.app.get_package()}")
        print(f"🔢 Version: {self.app.get_androidversion_name()}")
        print(f"🤖 Min SDK: {self.app.get_min_sdk_version()}")
        print(f"🤖 Target SDK: {self.app.get_target_sdk_version()}")

    def check_debuggable(self):
        if self.app.get_attribute_value(
            'application', 'debuggable'
        ) == 'true':
            self.vulnerabilities.append({
                'id': 'APP001',
                'name': 'Debuggable App',
                'severity': 'HIGH',
                'description': 'App Debug Mode Mein Hai',
                'remediation': 'Production Mein Debug OFF Karo'
            })
        else:
            self.safe.append({
                'name': 'Debug Mode',
                'status': 'SECURE - Not Debuggable'
            })

    def check_backup(self):
        if self.app.get_attribute_value(
            'application', 'allowBackup'
        ) == 'true':
            self.vulnerabilities.append({
                'id': 'APP002',
                'name': 'Backup Allowed',
                'severity': 'MEDIUM',
                'description': 'App Ka Backup Allow Hai',
                'remediation': 'allowBackup=false Karo'
            })
        else:
            self.safe.append({
                'name': 'Backup',
                'status': 'SECURE - Backup Disabled'
            })

    def check_permissions(self):
        print("\n📋 PERMISSIONS:")
        print("------------------------")
        dangerous_permissions = [
            'READ_SMS', 'SEND_SMS',
            'READ_CONTACTS', 'CAMERA',
            'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
            'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS'
        ]
        permissions = self.app.get_permissions()
        dangerous_found = []
        for perm in permissions:
            is_dangerous = False
            for dangerous in dangerous_permissions:
                if dangerous in perm:
                    if dangerous not in dangerous_found:
                        dangerous_found.append(dangerous)
                        self.vulnerabilities.append({
                            'id': 'APP003',
                            'name': f'Dangerous Permission',
                            'severity': 'MEDIUM',
                            'description': f'{dangerous} Permission Hai',
                            'remediation': 'Sirf Zarori Permissions Lo'
                        })
                    print(f"⚠️ Dangerous: {perm}")
                    is_dangerous = True
                    break
            if not is_dangerous:
                print(f"✅ Normal: {perm}")

    def check_exported_components(self):
        activities = self.app.get_activities()
        services = self.app.get_services()
        receivers = self.app.get_receivers()
        providers = self.app.get_providers()

        exported_count = 0
        
        for activity in activities:
            if self.app.get_attribute_value(
                'activity', 'exported',
                name=activity
            ) == 'true':
                exported_count += 1

        if exported_count > 0:
            self.vulnerabilities.append({
                'id': 'APP005',
                'name': 'Exported Components',
                'severity': 'HIGH',
                'description': f'{exported_count} Components Export Hain',
                'remediation': 'exported=false Karo'
            })
        else:
            self.safe.append({
                'name': 'Exported Components',
                'status': 'SECURE'
            })

        print(f"\n📦 COMPONENTS:")
        print(f"   Activities: {len(activities)}")
        print(f"   Services: {len(services)}")
        print(f"   Receivers: {len(receivers)}")
        print(f"   Providers: {len(providers)}")

    def check_min_sdk(self):
        min_sdk = int(self.app.get_min_sdk_version())
        if min_sdk < 21:
            self.vulnerabilities.append({
                'id': 'APP006',
                'name': 'Low Min SDK',
                'severity': 'MEDIUM',
                'description': f'Min SDK {min_sdk} Bohat Purana Hai',
                'remediation': 'Min SDK 21+ Rakhein'
            })

    def check_target_sdk(self):
        target_sdk = int(self.app.get_target_sdk_version())
        if target_sdk < 30:
            self.vulnerabilities.append({
                'id': 'APP007',
                'name': 'Old Target SDK',
                'severity': 'MEDIUM',
                'description': f'Target SDK {target_sdk} Purana Hai',
                'remediation': 'Target SDK 33+ Rakhein'
            })

    def check_hardcoded_secrets(self):
        strings = self.dx.get_strings()
        secret_keywords = [
            'password', 'secret', 'api_key',
            'apikey', 'token', 'private_key'
        ]
        
        # Count unique secrets
        found_secrets = {
            'password': 0,
            'secret': 0,
            'api_key': 0,
            'apikey': 0,
            'token': 0,
            'private_key': 0
        }

        for string in strings:
            str_val = str(string).lower()
            for keyword in secret_keywords:
                if keyword in str_val:
                    found_secrets[keyword] += 1
                    break

        # Add only unique vulnerabilities
        for keyword, count in found_secrets.items():
            if count > 0:
                self.vulnerabilities.append({
                    'id': 'APP004',
                    'name': f'Hardcoded {keyword.upper()}',
                    'severity': 'CRITICAL',
                    'description': f'{count} Hardcoded {keyword} Mile',
                    'remediation': 'Secrets Ko Code Mein Mat Rakho'
                })

    def run_all_checks(self):
        self.get_basic_info()
        self.check_debuggable()
        self.check_backup()
        self.check_permissions()
        self.check_exported_components()
        self.check_min_sdk()
        self.check_target_sdk()
        self.check_hardcoded_secrets()

        print("\n=============================")
        print("  SCAN RESULTS")
        print("=============================\n")

        print("✅ SECURE ITEMS:")
        print("------------------------")
        if len(self.safe) == 0:
            print("❌ No Secure Items!")
        for item in self.safe:
            print(f"✅ {item['name']}: {item['status']}")

        print("\n⚠️ VULNERABILITIES:")
        print("------------------------")
        if len(self.vulnerabilities) == 0:
            print("🎉 No Vulnerabilities Found!")
        else:
            critical = 0
            high = 0
            medium = 0
            low = 0
            for vuln in self.vulnerabilities:
                if vuln['severity'] == 'CRITICAL':
                    critical += 1
                elif vuln['severity'] == 'HIGH':
                    high += 1
                elif vuln['severity'] == 'MEDIUM':
                    medium += 1
                else:
                    low += 1

                print(f"\n🔴 ID: {vuln['id']}")
                print(f"   Name: {vuln['name']}")
                print(f"   Severity: {vuln['severity']}")
                print(f"   Issue: {vuln['description']}")
                print(f"   Fix: {vuln['remediation']}")

        print("\n=============================")
        print("  SUMMARY")
        print("=============================")
        print(f"🔴 Critical: {critical}")
        print(f"🟠 High: {high}")
        print(f"🟡 Medium: {medium}")
        print(f"🟢 Low: {low}")
        print(f"✅ Secure: {len(self.safe)}")
        print(f"Total Issues: {len(self.vulnerabilities)}")
        print("=============================\n")

if __name__ == "__main__":
    apk_path = "test.apk"
    if os.path.exists(apk_path):
        analyzer = APKAnalyzer(apk_path)
        analyzer.run_all_checks()
    else:
        print("❌ APK File Nahi Mili!")
        print("test.apk File Is Folder Mein Rakho!")