from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()

class Database:
    def __init__(self):
        self.client = MongoClient(
            os.getenv('MONGODB_URL')
        )
        self.db = self.client['ibhp']

        # Collections
        self.users = self.db['users']
        self.scans = self.db['scans']
        self.devices = self.db['devices']
        self.vulnerabilities = self.db['vulnerabilities']
        self.reports = self.db['reports']
        self.exploits = self.db['exploits']
        self.logs = self.db['logs']

        print("✅ Database Connected!")

    # ==================
    # USER FUNCTIONS
    # ==================
    def save_user(self, user_data):
        return self.users.insert_one(user_data)

    def get_user(self, username):
        return self.users.find_one(
            {'username': username},
            {'_id': 0}
        )

    def get_all_users(self):
        return list(self.users.find(
            {},
            {'_id': 0, 'password': 0}
        ))

    # ==================
    # DEVICE FUNCTIONS
    # ==================
    def save_device(self, device_data):
        device_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.devices.insert_one(device_data)

    def get_all_devices(self):
        return list(self.devices.find(
            {}, {'_id': 0}
        ))

    # ==================
    # SCAN FUNCTIONS
    # ==================
    def save_scan(self, scan_data):
        scan_data['created_at'] = \
            datetime.utcnow().isoformat()
        result = self.scans.insert_one(scan_data)
        return str(result.inserted_id)

    def get_all_scans(self):
        return list(self.scans.find(
            {}, {'_id': 0}
        ))

    def get_scan_by_type(self, scan_type):
        return list(self.scans.find(
            {'scan_type': scan_type},
            {'_id': 0}
        ))

    # ==================
    # VULNERABILITY FUNCTIONS
    # ==================
    def save_vulnerability(self, vuln_data):
        vuln_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.vulnerabilities.insert_one(
            vuln_data
        )

    def get_all_vulnerabilities(self):
        return list(self.vulnerabilities.find(
            {}, {'_id': 0}
        ))

    def get_vulns_by_severity(self, severity):
        return list(self.vulnerabilities.find(
            {'severity': severity},
            {'_id': 0}
        ))

    # ==================
    # REPORT FUNCTIONS
    # ==================
    def save_report(self, report_data):
        report_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.reports.insert_one(report_data)

    def get_all_reports(self):
        return list(self.reports.find(
            {}, {'_id': 0}
        ))

    # ==================
    # EXPLOIT FUNCTIONS
    # ==================
    def save_exploit(self, exploit_data):
        exploit_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.exploits.insert_one(exploit_data)

    def get_all_exploits(self):
        return list(self.exploits.find(
            {}, {'_id': 0}
        ))

    # ==================
    # LOG FUNCTIONS
    # ==================
    def save_log(self, log_data):
        log_data['timestamp'] = \
            datetime.utcnow().isoformat()
        return self.logs.insert_one(log_data)

    def get_logs(self, limit=100):
        return list(self.logs.find(
            {},
            {'_id': 0}
        ).limit(limit))

    # ==================
    # STATS FUNCTIONS
    # ==================
    def get_stats(self):
        return {
            'total_scans': self.scans.count_documents({}),
            'total_vulns': self.vulnerabilities.count_documents({}),
            'critical_vulns': self.vulnerabilities.count_documents(
                {'severity': 'CRITICAL'}
            ),
            'high_vulns': self.vulnerabilities.count_documents(
                {'severity': 'HIGH'}
            ),
            'medium_vulns': self.vulnerabilities.count_documents(
                {'severity': 'MEDIUM'}
            ),
            'total_reports': self.reports.count_documents({}),
            'total_exploits': self.exploits.count_documents({}),
            'total_users': self.users.count_documents({})
        }

db = Database()