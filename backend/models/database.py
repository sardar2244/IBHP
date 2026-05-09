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
        self.reports = self.db['reports']
        
        print("✅ Database Connected!")
    
    # User Functions
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
    
    # Scan Functions
    def save_scan(self, scan_data):
        scan_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.scans.insert_one(scan_data)
    
    def get_all_scans(self):
        return list(self.scans.find(
            {},
            {'_id': 0}
        ))
    
    def get_scan_by_type(self, scan_type):
        return list(self.scans.find(
            {'scan_type': scan_type},
            {'_id': 0}
        ))
    
    # Report Functions
    def save_report(self, report_data):
        report_data['created_at'] = \
            datetime.utcnow().isoformat()
        return self.reports.insert_one(report_data)
    
    def get_all_reports(self):
        return list(self.reports.find(
            {},
            {'_id': 0}
        ))

# Global Database Instance
db = Database()