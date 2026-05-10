import re
import json
import os

class RulesEngine:
    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self):
        # YAML Style Rules JSON Mein
        rules_file = os.path.join(
            os.path.dirname(__file__),
            'security_rules.json'
        )
        
        if os.path.exists(rules_file):
            with open(rules_file, 'r') as f:
                return json.load(f)
        
        return self.get_default_rules()

    def get_default_rules(self):
        return {
            'version': '1.0',
            'rules': [
                {
                    'id': 'RULE001',
                    'name': 'Hardcoded API Key',
                    'severity': 'CRITICAL',
                    'pattern': r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
                    'description': 'Hardcoded API Key Found',
                    'owasp': 'M9: Reverse Engineering',
                    'masvs': 'MSTG-STORAGE-14',
                    'cwe': 'CWE-798',
                    'cvss': 9.8,
                    'remediation': 'Use secure key storage'
                },
                {
                    'id': 'RULE002',
                    'name': 'Hardcoded Password',
                    'severity': 'CRITICAL',
                    'pattern': r'password\s*=\s*["\'][^"\']{4,}["\']',
                    'description': 'Hardcoded Password Found',
                    'owasp': 'M9: Reverse Engineering',
                    'masvs': 'MSTG-STORAGE-14',
                    'cwe': 'CWE-259',
                    'cvss': 9.8,
                    'remediation': 'Never hardcode passwords'
                },
                {
                    'id': 'RULE003',
                    'name': 'HTTP URL',
                    'severity': 'HIGH',
                    'pattern': r'http://[a-zA-Z0-9]',
                    'description': 'Insecure HTTP URL',
                    'owasp': 'M3: Insecure Communication',
                    'masvs': 'MSTG-NETWORK-1',
                    'cwe': 'CWE-319',
                    'cvss': 7.5,
                    'remediation': 'Use HTTPS'
                },
                {
                    'id': 'RULE004',
                    'name': 'Weak Crypto MD5',
                    'severity': 'HIGH',
                    'pattern': r'MD5|md5',
                    'description': 'Weak MD5 Algorithm',
                    'owasp': 'M5: Insufficient Crypto',
                    'masvs': 'MSTG-CRYPTO-4',
                    'cwe': 'CWE-327',
                    'cvss': 7.4,
                    'remediation': 'Use SHA-256 or better'
                },
                {
                    'id': 'RULE005',
                    'name': 'Weak Crypto SHA1',
                    'severity': 'MEDIUM',
                    'pattern': r'SHA1|sha1|SHA-1',
                    'description': 'Weak SHA1 Algorithm',
                    'owasp': 'M5: Insufficient Crypto',
                    'masvs': 'MSTG-CRYPTO-4',
                    'cwe': 'CWE-327',
                    'cvss': 5.9,
                    'remediation': 'Use SHA-256 or better'
                },
                {
                    'id': 'RULE006',
                    'name': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'pattern': r'rawQuery\s*\(|execSQL\s*\(',
                    'description': 'SQL Injection Risk',
                    'owasp': 'M7: Poor Code Quality',
                    'masvs': 'MSTG-ARCH-2',
                    'cwe': 'CWE-89',
                    'cvss': 9.8,
                    'remediation': 'Use parameterized queries'
                },
                {
                    'id': 'RULE007',
                    'name': 'Debug Logging',
                    'severity': 'LOW',
                    'pattern': r'Log\.d\s*\(|System\.out\.print',
                    'description': 'Debug Logs In Production',
                    'owasp': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-3',
                    'cwe': 'CWE-532',
                    'cvss': 3.1,
                    'remediation': 'Remove debug logs'
                },
                {
                    'id': 'RULE008',
                    'name': 'SSL Disabled',
                    'severity': 'CRITICAL',
                    'pattern': r'onReceivedSslError|ALLOW_ALL_HOSTNAME',
                    'description': 'SSL Validation Disabled',
                    'owasp': 'M3: Insecure Communication',
                    'masvs': 'MSTG-NETWORK-3',
                    'cwe': 'CWE-295',
                    'cvss': 9.1,
                    'remediation': 'Enable SSL validation'
                },
                {
                    'id': 'RULE009',
                    'name': 'Insecure Random',
                    'severity': 'MEDIUM',
                    'pattern': r'java\.util\.Random\(\)',
                    'description': 'Insecure Random Generator',
                    'owasp': 'M5: Insufficient Crypto',
                    'masvs': 'MSTG-CRYPTO-6',
                    'cwe': 'CWE-330',
                    'cvss': 5.9,
                    'remediation': 'Use SecureRandom'
                },
                {
                    'id': 'RULE010',
                    'name': 'Private Key Exposed',
                    'severity': 'CRITICAL',
                    'pattern': r'PRIVATE KEY|private_key|privateKey',
                    'description': 'Private Key Found In Code',
                    'owasp': 'M9: Reverse Engineering',
                    'masvs': 'MSTG-STORAGE-14',
                    'cwe': 'CWE-321',
                    'cvss': 9.8,
                    'remediation': 'Never store keys in code'
                },
                {
                    'id': 'RULE011',
                    'name': 'Clipboard Access',
                    'severity': 'MEDIUM',
                    'pattern': r'ClipboardManager|CLIPBOARD_SERVICE',
                    'description': 'Clipboard Access Found',
                    'owasp': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-12',
                    'cwe': 'CWE-200',
                    'cvss': 4.3,
                    'remediation': 'Disable clipboard on sensitive screens'
                },
                {
                    'id': 'RULE012',
                    'name': 'World Readable File',
                    'severity': 'HIGH',
                    'pattern': r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
                    'description': 'World Readable/Writable File',
                    'owasp': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-2',
                    'cwe': 'CWE-732',
                    'cvss': 7.5,
                    'remediation': 'Use MODE_PRIVATE'
                }
            ]
        }

    def save_rules(self):
        rules_file = os.path.join(
            os.path.dirname(__file__),
            'security_rules.json'
        )
        with open(rules_file, 'w') as f:
            json.dump(self.rules, f, indent=4)
        print(f"✅ Rules Saved: {rules_file}")

    def scan_code(self, code_content):
        findings = []
        seen_rules = set()

        for rule in self.rules['rules']:
            if rule['id'] in seen_rules:
                continue

            pattern = re.compile(
                rule['pattern'],
                re.IGNORECASE
            )
            matches = pattern.findall(code_content)

            if matches:
                seen_rules.add(rule['id'])
                findings.append({
                    'rule_id': rule['id'],
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'owasp': rule['owasp'],
                    'masvs': rule['masvs'],
                    'cwe': rule['cwe'],
                    'cvss': rule['cvss'],
                    'matches_count': len(matches),
                    'sample': str(matches[0])[:100],
                    'remediation': rule['remediation']
                })

        return findings

    def correlate_vulnerabilities(self, findings):
        """Vulnerability Correlation Engine"""
        risk_score = 0
        risk_factors = []

        critical_count = sum(
            1 for f in findings
            if f['severity'] == 'CRITICAL'
        )
        high_count = sum(
            1 for f in findings
            if f['severity'] == 'HIGH'
        )

        # Risk Score Calculate
        risk_score = (critical_count * 10) + \
                     (high_count * 7)

        # Correlation Rules
        rule_ids = [f['rule_id'] for f in findings]

        if 'RULE001' in rule_ids and \
           'RULE008' in rule_ids:
            risk_factors.append({
                'name': 'API Key + SSL Bypass',
                'severity': 'CRITICAL',
                'description': (
                    'Hardcoded API Key AND '
                    'SSL Disabled = Maximum Risk!'
                )
            })
            risk_score += 15

        if 'RULE002' in rule_ids and \
           'RULE006' in rule_ids:
            risk_factors.append({
                'name': 'Password + SQL Injection',
                'severity': 'CRITICAL',
                'description': (
                    'Hardcoded Password AND '
                    'SQL Injection = Auth Bypass Risk!'
                )
            })
            risk_score += 15

        if 'RULE003' in rule_ids and \
           'RULE008' in rule_ids:
            risk_factors.append({
                'name': 'HTTP + SSL Disabled',
                'severity': 'CRITICAL',
                'description': (
                    'HTTP Traffic AND SSL Disabled '
                    '= Complete MITM Risk!'
                )
            })
            risk_score += 10

        # Final Risk Level
        if risk_score >= 50:
            risk_level = '🔴 CRITICAL'
        elif risk_score >= 30:
            risk_level = '🟠 HIGH'
        elif risk_score >= 15:
            risk_level = '🟡 MEDIUM'
        else:
            risk_level = '🟢 LOW'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'correlated_risks': risk_factors,
            'critical_count': critical_count,
            'high_count': high_count
        }

    def print_results(self, findings):
        print("\n=============================")
        print("  RULES ENGINE RESULTS")
        print("  (CWE + OWASP + MASVS)")
        print("=============================\n")

        if not findings:
            print("✅ No Issues Found!")
            return

        # Counts
        critical = [
            f for f in findings
            if f['severity'] == 'CRITICAL'
        ]
        high = [
            f for f in findings
            if f['severity'] == 'HIGH'
        ]
        medium = [
            f for f in findings
            if f['severity'] == 'MEDIUM'
        ]
        low = [
            f for f in findings
            if f['severity'] == 'LOW'
        ]

        print(f"🔴 Critical: {len(critical)}")
        print(f"🟠 High: {len(high)}")
        print(f"🟡 Medium: {len(medium)}")
        print(f"🟢 Low: {len(low)}")
        print(f"Total: {len(findings)}\n")

        # Correlation
        correlation = self.correlate_vulnerabilities(
            findings
        )
        print(f"Risk Score: {correlation['risk_score']}/100")
        print(f"Risk Level: {correlation['risk_level']}")

        if correlation['correlated_risks']:
            print("\n⚠️ CORRELATED RISKS:")
            for risk in correlation['correlated_risks']:
                print(f"  → {risk['name']}")
                print(f"     {risk['description']}")

        print("\n" + "="*30)
        print("VULNERABILITIES:")
        print("="*30)

        for finding in findings:
            sev = finding['severity']
            icon = '🔴' if sev == 'CRITICAL' else \
                   '🟠' if sev == 'HIGH' else \
                   '🟡' if sev == 'MEDIUM' else '🟢'

            print(f"\n{icon} {finding['name']}")
            print(f"   ID: {finding['rule_id']}")
            print(f"   CWE: {finding['cwe']}")
            print(f"   OWASP: {finding['owasp']}")
            print(f"   MASVS: {finding['masvs']}")
            print(f"   CVSS: {finding['cvss']}/10.0")
            print(f"   Matches: {finding['matches_count']}")
            print(f"   Fix: {finding['remediation']}")


if __name__ == "__main__":
    engine = RulesEngine()

    # Rules JSON Save Karo
    engine.save_rules()

    test_code = """
    String api_key = "abc123secretkey456789";
    String password = "admin123";
    String url = "http://example.com/api";
    MessageDigest md = MessageDigest.getInstance("MD5");
    db.rawQuery("SELECT * FROM users WHERE id=" + id);
    Log.d("TAG", "User password: " + password);
    webView.setOnReceivedSslError(handler);
    Random random = new java.util.Random();
    ClipboardManager cm = getSystemService(CLIPBOARD_SERVICE);
    openFileOutput("data.txt", MODE_WORLD_READABLE);
    """
