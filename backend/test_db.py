from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

try:
    client = MongoClient(os.getenv('MONGODB_URL'))
    db = client['ibhp']
    
    # Test Insert
    db.test.insert_one({
        'message': 'IBHP Connected!',
        'status': 'success'
    })
    
    # Test Read
    result = db.test.find_one(
        {'message': 'IBHP Connected!'},
        {'_id': 0}
    )
    
    print("✅ MongoDB Connected!")
    print(f"✅ Test Data: {result}")
    
except Exception as e:
    print(f"❌ Error: {e}")