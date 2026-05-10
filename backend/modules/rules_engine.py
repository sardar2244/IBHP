import re
import json

class RulesEngine:
    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self):
        return {
            'static_rules': [
                {
                    'id': 'RULE001',
                    'name': 'Hardcoded API Key',
                    'severity': 'CRITICAL',
                    'pattern': r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
                    'description': 'Hardcoded API Key Found',
                    'owasp': 'M9',
                    'cwe': 'CWE-798'
                },
                {
                    'id': 'RULE002',
                    'name': 'Hardcoded Password',
                    'severity': 'CRITICAL',
                    'pattern': r'password\s*=\s*["\'][^"\']{4,}["\']',
                    'description': 'Hardcoded Password Found',
                    'owasp': 'M9',
                    'cwe': 'CWE-259'
                },
                {
                    'id': 'RULE003',
                    'name': 'HTTP URL',
                    'severity': 'HIGH',
                    'pattern': r'http://[a-zA-Z0-9]',
                    'description': 'Insecure HTTP URL Found',
                    'owasp': 'M3',
                    'cwe': 'CWE-319'
                },
                {
                    'id': 'RULE004',
                    'name': 'Weak Crypto - MD5',
                    'severity': 'HIGH',
                    'pattern': r'MD5|md5',
                    'description': 'Weak MD5 Crypto Used',
                    'owasp': 'M5',
                    'cwe': 'CWE-327'
                },
                {
                    'id': 'RULE005',
                    'name': 'Weak Crypto - SHA1',
                    'severity': 'MEDIUM',
                    'pattern': r'SHA1|sha1|SHA-1',
                    'description': 'Weak SHA1 Crypto Used',
                    'owasp': 'M5',
                    'cwe': 'CWE-327'
                },
                {
                    'id': 'RULE006',
                    'name': 'SQL Injection Risk',
                    'severity': 'CRITICAL',
                    'pattern': r'rawQuery\s*\(|execSQL\s*\(',
                    'description': 'Possible SQL Injection',
                    'owasp': 'M7',
                    'cwe': 'CWE-89'
                },
                {
                    'id': 'RULE007',
                    'name': 'Debug Log',
                    'severity': 'LOW',
                    'pattern': r'Log\.d\s*\(|System\.out\.print',
                    'description': 'Debug Logging Found',
                    'owasp': 'M2',
                    'cwe': 'CWE-532'
                },
                {
                    'id': 'RULE008',
                    'name': 'SSL Disabled',
                    'severity': 'CRITICAL',
                    'pattern': r'onReceivedSslError|ALLOW_ALL_HOSTNAME',
                    'description': 'SSL Validation Disabled',
                    'owasp': 'M3',
                    'cwe': 'CWE-295'
                },
                {
                    'id': 'RULE009',
                    'name': 'Insecure Random',
                    'severity': 'MEDIUM',
                    'pattern': r'java\.util\.Random\(\)',
                    'description': 'Insecure Random Used',
                    'owasp': 'M5',
                    'cwe': 'CWE-330'
                },
                {
                    'id': 'RULE010',
                    'name': 'Private Key',
                    'severity': 'CRITICAL',
                    'pattern': r'PRIVATE KEY|private_key|privateKey',
                    'description': 'Private Key Found',
                    'owasp': 'M9',
                    'cwe': 'CWE-321'
                }
            ]
        }

    def scan_code(self, code_content):
        findings = []
        seen_rules = set()

        for rule in self.rules['static_rules']:
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
                    'cwe': rule['cwe'],
                    'matches_count': len(matches),
                    'sample_match': str(matches[0])[:100]
                })

        return findings

    def scan_file(self, file_path):
        try:
            with open(file_path, 'r',
                     encoding='utf-8',
                     errors='ignore') as f:
                content = f.read()
            return self.scan_code(content)
        except Exception as e:
            return []

    def print_results(self, findings):
        print("\n=============================")
        print("  RULES ENGINE RESULTS")
        print("=============================\n")

        if not findings:
            print("✅ No Issues Found!")
            return

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

        for finding in findings:
            sev = finding['severity']
            icon = '🔴' if sev == 'CRITICAL' else \
                   '🟠' if sev == 'HIGH' else \
                   '🟡' if sev == 'MEDIUM' else '🟢'

            print(f"{icon} {finding['name']}")
            print(f"   ID: {finding['rule_id']}")
            print(f"   Severity: {finding['severity']}")
            print(f"   CWE: {finding['cwe']}")
            print(f"   OWASP: {finding['owasp']}")
            print(f"   Matches: {finding['matches_count']}")
            print(f"   Sample: {finding['sample_match']}")
            print()


if __name__ == "__main__":
    engine = RulesEngine()

    # Test Code
    test_code = """
    String api_key = "abc123secretkey456789";
    String password = "admin123";
    String url = "http://example.com/api";
    MessageDigest md = MessageDigest.getInstance("MD5");
    db.rawQuery("SELECT * FROM users WHERE id=" + id);
    Log.d("TAG", "User password: " + password);
    webView.setOnReceivedSslError(handler);
    Random random = new java.util.Random();
    """

    findings = engine.scan_code(test_code)
    engine.print_results(findings)