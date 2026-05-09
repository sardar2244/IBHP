import requests
import json

class AIAnalyzer:
    def __init__(self):
        # Ollama Local AI Use Karein Ge
        self.api_url = "http://localhost:11434/api/generate"
        self.model = "mistral"

    def analyze_vulnerability(self, vuln):
        prompt = f"""
        You are a cybersecurity expert.
        Analyze this vulnerability:
        
        Name: {vuln['name']}
        Severity: {vuln['severity']}
        Description: {vuln['description']}
        
        Provide:
        1. Risk Analysis
        2. Attack Scenario
        3. Fix Recommendation
        
        Be concise and clear.
        """
        
        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()[
                    'response'
                ]
            else:
                return self.get_static_analysis(vuln)
                
        except Exception:
            return self.get_static_analysis(vuln)

    def get_static_analysis(self, vuln):
        # AI Na Ho Toh Static Analysis
        analyses = {
            'CRITICAL': {
                'risk': 'Bohat Zyada Khatarnak!',
                'attack': 'Hacker Seedha Attack Kar Sakta Hai',
                'fix': 'Foran Fix Karo - 24 Ghante Mein'
            },
            'HIGH': {
                'risk': 'Zyada Khatarnak!',
                'attack': 'Hacker Data Chura Sakta Hai',
                'fix': '48 Ghante Mein Fix Karo'
            },
            'MEDIUM': {
                'risk': 'Theek Thak Khatarnak',
                'attack': 'Limited Attack Possible',
                'fix': '1 Hafte Mein Fix Karo'
            },
            'LOW': {
                'risk': 'Kam Khatarnak',
                'attack': 'Minor Issue',
                'fix': '1 Mahine Mein Fix Karo'
            }
        }
        
        severity = vuln.get('severity', 'LOW')
        analysis = analyses.get(
            severity, analyses['LOW']
        )
        
        return f"""
🔍 Risk Analysis:
{analysis['risk']}

⚔️ Attack Scenario:
{analysis['attack']}

🔧 Fix Recommendation:
{analysis['fix']}

📋 Specific Fix for {vuln['name']}:
{vuln.get('remediation', 'Please consult security expert')}
        """

    def analyze_all(self, vulnerabilities):
        results = []
        for vuln in vulnerabilities:
            analysis = self.analyze_vulnerability(vuln)
            results.append({
                'vulnerability': vuln,
                'ai_analysis': analysis
            })
        return results


if __name__ == "__main__":
    ai = AIAnalyzer()
    
    # Test
    test_vuln = {
        'id': 'APP001',
        'name': 'Debuggable App',
        'severity': 'HIGH',
        'description': 'App Debug Mode Mein Hai',
        'remediation': 'Debug OFF Karo'
    }
    
    print("🤖 AI Analysis:")
    print("=" * 40)
    result = ai.analyze_vulnerability(test_vuln)
    print(result)