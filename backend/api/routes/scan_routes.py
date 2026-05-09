from fastapi import APIRouter
import sys
import os

# Path Fix
sys.path.append(
    os.path.join(
        os.path.dirname(__file__), 
        '..', '..', 'modules', 'device'
    )
)
sys.path.append(
    os.path.join(
        os.path.dirname(__file__), 
        '..', '..', 'modules', 'app'
    )
)

from firmware_checker import FirmwareChecker
from network_checker import NetworkChecker

router = APIRouter()

@router.get("/device-scan")
def device_scan():
    try:
        fw = FirmwareChecker()
        fw.run_all_checks()
        
        net = NetworkChecker()
        net.run_all_checks()
        
        return {
            "status": "success",
            "device_vulnerabilities": 
                fw.vulnerabilities,
            "device_safe": fw.safe,
            "network_vulnerabilities": 
                net.vulnerabilities,
            "network_safe": net.safe
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/app-scan")
def app_scan():
    try:
        sys.path.append(
            os.path.join(
                os.path.dirname(__file__), 
                '..', '..', 'modules', 'app'
            )
        )
        from apk_analyzer import APKAnalyzer
        
        apk_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', 'modules', 
            'app', 'test.apk'
        )
        
        if not os.path.exists(apk_path):
            return {
                "status": "error",
                "message": "APK Not Found!"
            }
            
        analyzer = APKAnalyzer(apk_path)
        analyzer.run_all_checks()
        
        return {
            "status": "success",
            "vulnerabilities": 
                analyzer.vulnerabilities,
            "safe": analyzer.safe
        }
    except Exception as e:
        return {
            "status": "error", 
            "message": str(e)
        }

@router.get("/network-scan")
def network_scan():
    try:
        net = NetworkChecker()
        net.run_all_checks()
        return {
            "status": "success",
            "vulnerabilities": 
                net.vulnerabilities,
            "safe": net.safe
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }