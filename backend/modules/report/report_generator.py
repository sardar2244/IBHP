import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.report_data = {
            'title': 'IBHP Security Report',
            'date': datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            'device_info': {},
            'app_info': {},
            'device_vulnerabilities': [],
            'app_vulnerabilities': [],
            'summary': {}
        }

    def add_device_results(
        self, safe_items, vulnerabilities
    ):
        self.report_data['device_vulnerabilities'] = \
            vulnerabilities
        self.report_data['device_safe'] = safe_items

    def add_app_results(
        self, app_info, vulnerabilities, safe_items
    ):
        self.report_data['app_info'] = app_info
        self.report_data['app_vulnerabilities'] = \
            vulnerabilities
        self.report_data['app_safe'] = safe_items

    def calculate_summary(self):
        all_vulns = (
            self.report_data['device_vulnerabilities'] +
            self.report_data['app_vulnerabilities']
        )
        
        critical = sum(
            1 for v in all_vulns 
            if v['severity'] == 'CRITICAL'
        )
        high = sum(
            1 for v in all_vulns 
            if v['severity'] == 'HIGH'
        )
        medium = sum(
            1 for v in all_vulns 
            if v['severity'] == 'MEDIUM'
        )
        low = sum(
            1 for v in all_vulns 
            if v['severity'] == 'LOW'
        )

        self.report_data['summary'] = {
            'total_issues': len(all_vulns),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'risk_level': self.get_risk_level(
                critical, high
            )
        }

    def get_risk_level(self, critical, high):
        if critical > 0:
            return '🔴 CRITICAL RISK'
        elif high > 0:
            return '🟠 HIGH RISK'
        else:
            return '🟡 MEDIUM RISK'

    def generate_text_report(self):
        self.calculate_summary()
        
        report = []
        report.append("=" * 50)
        report.append("   IBHP SECURITY ASSESSMENT REPORT")
        report.append("=" * 50)
        report.append(
            f"Date: {self.report_data['date']}"
        )
        report.append(
            f"Risk Level: "
            f"{self.report_data['summary']['risk_level']}"
        )
        
        report.append("\n" + "=" * 50)
        report.append("   EXECUTIVE SUMMARY")
        report.append("=" * 50)
        summary = self.report_data['summary']
        report.append(
            f"Total Issues: {summary['total_issues']}"
        )
        report.append(
            f"🔴 Critical: {summary['critical']}"
        )
        report.append(
            f"🟠 High: {summary['high']}"
        )
        report.append(
            f"🟡 Medium: {summary['medium']}"
        )
        report.append(
            f"🟢 Low: {summary['low']}"
        )

        report.append("\n" + "=" * 50)
        report.append("   DEVICE VULNERABILITIES")
        report.append("=" * 50)
        device_vulns = self.report_data[
            'device_vulnerabilities'
        ]
        if not device_vulns:
            report.append("✅ No Device Issues Found!")
        else:
            for vuln in device_vulns:
                report.append(
                    f"\n🔴 {vuln['name']}"
                )
                report.append(
                    f"   Severity: {vuln['severity']}"
                )
                report.append(
                    f"   Issue: {vuln['description']}"
                )
                report.append(
                    f"   Fix: {vuln['remediation']}"
                )

        report.append("\n" + "=" * 50)
        report.append("   APP VULNERABILITIES")
        report.append("=" * 50)
        app_vulns = self.report_data[
            'app_vulnerabilities'
        ]
        if not app_vulns:
            report.append("✅ No App Issues Found!")
        else:
            for vuln in app_vulns:
                report.append(
                    f"\n🔴 {vuln['name']}"
                )
                report.append(
                    f"   Severity: {vuln['severity']}"
                )
                report.append(
                    f"   Issue: {vuln['description']}"
                )
                report.append(
                    f"   Fix: {vuln['remediation']}"
                )

        report.append("\n" + "=" * 50)
        report.append("   RECOMMENDATIONS")
        report.append("=" * 50)
        report.append(
            "1. Critical Issues Pehle Fix Karein"
        )
        report.append(
            "2. High Issues 24 Ghante Mein Fix Karein"
        )
        report.append(
            "3. Medium Issues 1 Hafte Mein Fix Karein"
        )
        report.append(
            "4. Regular Security Audits Karein"
        )
        report.append("=" * 50)

        return "\n".join(report)

    def save_report(self, filename="report"):
        # Text Report Save Karo
        text_report = self.generate_text_report()
        
        txt_file = f"{filename}.txt"
        with open(txt_file, 'w', 
                  encoding='utf-8') as f:
            f.write(text_report)

        # JSON Report Save Karo
        json_file = f"{filename}.json"
        with open(json_file, 'w', 
                  encoding='utf-8') as f:
            json.dump(
                self.report_data, f, 
                indent=4, ensure_ascii=False
            )

        print(text_report)
        print(f"\n✅ Text Report Saved: {txt_file}")
        print(f"✅ JSON Report Saved: {json_file}")


if __name__ == "__main__":
    # Test Report
    report = ReportGenerator()

    # Device Results Add Karo
    report.add_device_results(
        safe_items=[
            {
                'name': 'Bootloader',
                'status': 'SECURE - Locked'
            },
            {
                'name': 'SELinux',
                'status': 'SECURE - Enforcing'
            },
            {
                'name': 'Encryption',
                'status': 'SECURE - Encrypted'
            }
        ],
        vulnerabilities=[
            {
                'id': 'FW004',
                'name': 'USB Debugging ON',
                'severity': 'MEDIUM',
                'description': 'USB Debugging Enabled',
                'remediation': 'Disable USB Debugging'
            }
        ]
    )

    # App Results Add Karo
    report.add_app_results(
        app_info={
            'name': 'DIVA',
            'package': 'jakhar.aseem.diva',
            'version': '1.0'
        },
        vulnerabilities=[
            {
                'id': 'APP001',
                'name': 'Debuggable App',
                'severity': 'HIGH',
                'description': 'App Debug Mode Mein',
                'remediation': 'Debug OFF Karo'
            },
            {
                'id': 'APP004',
                'name': 'Hardcoded PASSWORD',
                'severity': 'CRITICAL',
                'description': '10 Passwords Mile',
                'remediation': 'Secrets Remove Karo'
            }
        ],
        safe_items=[
            {
                'name': 'Permissions',
                'status': 'SECURE'
            }
        ]
    )

    # Report Save Karo
    report.save_report("security_report")