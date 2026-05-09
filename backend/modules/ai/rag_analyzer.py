import json
import os

class RAGAnalyzer:
    def __init__(self):
        self.knowledge_base = {
            'debuggable': {
                'cve': 'CVE-2021-0600',
                'owasp': 'M1: Improper Platform Usage',
                'description': (
                    'Debuggable apps expose sensitive '
                    'data and allow runtime manipulation'
                ),
                'cvss': 7.8,
                'attack': (
                    'Attacker can attach debugger, '
                    'extract memory, bypass auth'
                ),
                'fix': (
                    'Set android:debuggable="false" '
                    'in production builds'
                ),
                'references': [
                    'https://owasp.org/www-project-mobile-top-10/',
                    'https://developer.android.com/guide/topics/manifest/application-element'
                ]
            },
            'backup': {
                'cve': 'CVE-2018-9493',
                'owasp': 'M2: Insecure Data Storage',
                'description': (
                    'Backup enabled apps allow '
                    'data extraction without root'
                ),
                'cvss': 6.5,
                'attack': (
                    'adb backup command se '
                    'app data extract ho sakta hai'
                ),
                'fix': (
                    'Set android:allowBackup="false" '
                    'in AndroidManifest.xml'
                ),
                'references': [
                    'https://developer.android.com/guide/topics/manifest/application-element#allowBackup'
                ]
            },
            'hardcoded_password': {
                'cve': 'CVE-2019-5765',
                'owasp': 'M9: Reverse Engineering',
                'description': (
                    'Hardcoded credentials in APK '
                    'can be extracted by decompilation'
                ),
                'cvss': 9.8,
                'attack': (
                    'apktool/jadx se APK decompile '
                    'karke credentials nikal sakte hain'
                ),
                'fix': (
                    'Use encrypted secure storage, '
                    'never hardcode credentials'
                ),
                'references': [
                    'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials'
                ]
            },
            'hardcoded_token': {
                'cve': 'CVE-2019-5765',
                'owasp': 'M9: Reverse Engineering',
                'description': (
                    'Hardcoded tokens exposed in APK'
                ),
                'cvss': 8.5,
                'attack': (
                    'Token extract karke API '
                    'access mil sakta hai'
                ),
                'fix': (
                    'Tokens server-side generate karo, '
                    'APK mein mat rakho'
                ),
                'references': [
                    'https://owasp.org/www-project-mobile-top-10/'
                ]
            },
            'usb_debugging': {
                'cve': 'CVE-2020-0069',
                'owasp': 'M6: Insecure Authorization',
                'description': (
                    'USB Debugging allows ADB access '
                    'to device data'
                ),
                'cvss': 7.2,
                'attack': (
                    'Physical access se ADB commands '
                    'run ho sakte hain'
                ),
                'fix': (
                    'Disable USB Debugging in '
                    'production devices'
                ),
                'references': [
                    'https://developer.android.com/studio/debug'
                ]
            },
            'cleartext_traffic': {
                'cve': 'CVE-2021-0600',
                'owasp': 'M3: Insecure Communication',
                'description': (
                    'HTTP traffic can be intercepted '
                    'by MITM attacks'
                ),
                'cvss': 7.5,
                'attack': (
                    'Network sniffing se '
                    'data capture ho sakta hai'
                ),
                'fix': (
                    'Use HTTPS only, '
                    'add network security config'
                ),
                'references': [
                    'https://developer.android.com/training/articles/security-config'
                ]
            },
            'dangerous_permissions': {
                'cve': 'N/A',
                'owasp': 'M1: Improper Platform Usage',
                'description': (
                    'Excessive permissions increase '
                    'attack surface'
                ),
                'cvss': 6.0,
                'attack': (
                    'Malicious app se permission '
                    'abuse ho sakta hai'
                ),
                'fix': (
                    'Request only necessary permissions, '
                    'use runtime permissions'
                ),
                'references': [
                    'https://developer.android.com/guide/topics/permissions/overview'
                ]
            },
            'exported_activity': {
                'cve': 'CVE-2020-0096',
                'owasp': 'M1: Improper Platform Usage',
                'description': (
                    'Exported activities can be '
                    'launched by any app'
                ),
                'cvss': 8.0,
                'attack': (
                    'Malicious app directly '
                    'activity launch kar sakta hai'
                ),
                'fix': (
                    'Set exported="false" or '
                    'add permission requirement'
                ),
                'references': [
                    'https://developer.android.com/guide/topics/manifest/activity-element'
                ]
            },
            'deeplink': {
                'cve': 'CVE-2020-0096',
                'owasp': 'M1: Improper Platform Usage',
                'description': (
                    'Deep links can be exploited '
                    'to bypass app security'
                ),
                'cvss': 7.5,
                'attack': (
                    'Malicious deep link se '
                    'unauthorized access mil sakta hai'
                ),
                'fix': (
                    'Validate all deep link data, '
                    'add verification checks'
                ),
                'references': [
                    'https://developer.android.com/training/app-links/verify-android-applinks'
                ]
            },
            'sensitive_logs': {
                'cve': 'CVE-2021-0600',
                'owasp': 'M2: Insecure Data Storage',
                'description': (
                    'Sensitive data found in '
                    'application logs'
                ),
                'cvss': 6.5,
                'attack': (
                    'Logs se passwords, tokens '
                    'extract ho sakte hain'
                ),
                'fix': (
                    'Remove all sensitive logging '
                    'in production builds'
                ),
                'references': [
                    'https://owasp.org/www-project-mobile-top-10/'
                ]
            },
            'low_sdk': {
                'cve': 'N/A',
                'owasp': 'M1: Improper Platform Usage',
                'description': (
                    'Low SDK version means missing '
                    'security patches and features'
                ),
                'cvss': 5.5,
                'attack': (
                    'Old SDK vulnerabilities '
                    'exploit ho sakte hain'
                ),
                'fix': (
                    'Update minSdkVersion to 21+ '
                    'and targetSdkVersion to 33+'
                ),
                'references': [
                    'https://developer.android.com/about/versions'
                ]
            }
        }

    def get_vulnerability_info(self, vuln_name):
        vuln_lower = vuln_name.lower()

        if any(x in vuln_lower for x in [
            'debug', 'debuggable'
        ]):
            return self.knowledge_base['debuggable']

        elif any(x in vuln_lower for x in [
            'backup', 'allowbackup'
        ]):
            return self.knowledge_base['backup']

        elif any(x in vuln_lower for x in [
            'password', 'passwd', 'hardcoded pass'
        ]):
            return self.knowledge_base['hardcoded_password']

        elif any(x in vuln_lower for x in [
            'token', 'api_key', 'apikey', 'secret'
        ]):
            return self.knowledge_base['hardcoded_token']

        elif any(x in vuln_lower for x in [
            'usb', 'adb'
        ]):
            return self.knowledge_base['usb_debugging']

        elif any(x in vuln_lower for x in [
            'cleartext', 'http', 'traffic', 'ssl'
        ]):
            return self.knowledge_base['cleartext_traffic']

        elif any(x in vuln_lower for x in [
            'permission', 'camera', 'location',
            'contact', 'microphone', 'dangerous'
        ]):
            return self.knowledge_base['dangerous_permissions']

        elif any(x in vuln_lower for x in [
            'exported', 'component'
        ]):
            return self.knowledge_base['exported_activity']

        elif any(x in vuln_lower for x in [
            'deeplink', 'deep link'
        ]):
            return self.knowledge_base['deeplink']

        elif any(x in vuln_lower for x in [
            'log', 'sensitive data in log'
        ]):
            return self.knowledge_base['sensitive_logs']

        elif any(x in vuln_lower for x in [
            'sdk', 'min sdk', 'target sdk', 'low min'
        ]):
            return self.knowledge_base['low_sdk']

        return {
            'cve': 'N/A',
            'owasp': 'OWASP Mobile Top 10',
            'description': 'Security vulnerability detected',
            'cvss': 5.0,
            'attack': 'Manual analysis required',
            'fix': 'Consult security expert',
            'references': [
                'https://owasp.org/www-project-mobile-top-10/'
            ]
        }

    def analyze_vulnerability(self, vuln):
        info = self.get_vulnerability_info(
            vuln.get('name', '')
        )

        severity = vuln.get('severity', 'MEDIUM')
        cvss = info['cvss']

        analysis = (
            f"🔍 VULNERABILITY ANALYSIS\n"
            f"{'='*40}\n"
            f"Name: {vuln.get('name', 'Unknown')}\n"
            f"Severity: {severity}\n"
            f"CVSS Score: {cvss}/10.0\n\n"
            f"📋 OWASP Category:\n"
            f"{info['owasp']}\n\n"
            f"🔎 CVE Reference:\n"
            f"{info['cve']}\n\n"
            f"📖 Description:\n"
            f"{info['description']}\n\n"
            f"⚔️ Attack Scenario:\n"
            f"{info['attack']}\n\n"
            f"🔧 Remediation:\n"
            f"{info['fix']}\n\n"
            f"📚 References:\n"
        )

        for ref in info['references']:
            analysis += f"{ref}\n"

        analysis += f"{'='*40}"
        return analysis

    def analyze_all(self, vulnerabilities):
        results = []
        for vuln in vulnerabilities:
            info = self.get_vulnerability_info(
                vuln.get('name', '')
            )
            analysis = self.analyze_vulnerability(vuln)
            results.append({
                'vulnerability': vuln,
                'ai_analysis': analysis,
                'cve': info['cve'],
                'owasp': info['owasp'],
                'cvss': info['cvss'],
                'references': info['references']
            })
        return results

    def generate_executive_summary(self, all_vulns):
        critical = sum(
            1 for v in all_vulns
            if v.get('severity') == 'CRITICAL'
        )
        high = sum(
            1 for v in all_vulns
            if v.get('severity') == 'HIGH'
        )
        medium = sum(
            1 for v in all_vulns
            if v.get('severity') == 'MEDIUM'
        )

        risk_score = (
            (critical * 10) +
            (high * 7) +
            (medium * 4)
        )

        if risk_score > 50:
            risk_level = "CRITICAL"
        elif risk_score > 30:
            risk_level = "HIGH"
        elif risk_score > 15:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        owasp_found = set()
        for vuln in all_vulns:
            info = self.get_vulnerability_info(
                vuln.get('name', '')
            )
            owasp_found.add(info['owasp'])

        summary = (
            f"🛡️ EXECUTIVE SECURITY SUMMARY\n"
            f"{'='*40}\n"
            f"Overall Risk Level: {risk_level}\n"
            f"Risk Score: {risk_score}/100\n\n"
            f"Vulnerabilities Found:\n"
            f"🔴 Critical: {critical}\n"
            f"🟠 High: {high}\n"
            f"🟡 Medium: {medium}\n\n"
            f"Top OWASP Categories Affected:\n"
        )

        for owasp in owasp_found:
            summary += f"  → {owasp}\n"

        summary += (
            f"\nImmediate Actions Required:\n"
            f"1. Fix all CRITICAL issues immediately\n"
            f"2. Address HIGH issues within 24 hours\n"
            f"3. Plan MEDIUM fixes within 1 week\n"
            f"4. Schedule regular security audits\n"
            f"{'='*40}"
        )
        return summary


if __name__ == "__main__":
    rag = RAGAnalyzer()

    test_vulns = [
        {
            'id': 'APP001',
            'name': 'Debuggable App',
            'severity': 'HIGH',
            'description': 'App is debuggable',
            'remediation': 'Disable debug mode'
        },
        {
            'id': 'APP004',
            'name': 'Hardcoded Password',
            'severity': 'CRITICAL',
            'description': '10 passwords found',
            'remediation': 'Remove hardcoded secrets'
        },
        {
            'id': 'DYN003',
            'name': 'Dangerous Permissions',
            'severity': 'HIGH',
            'description': 'Camera, Location found',
            'remediation': 'Remove unnecessary perms'
        }
    ]

    print("🤖 RAG AI ANALYSIS")
    print("=" * 50)

    summary = rag.generate_executive_summary(test_vulns)
    print(summary)

    results = rag.analyze_all(test_vulns)
    for result in results:
        print(result['ai_analysis'])
        print()