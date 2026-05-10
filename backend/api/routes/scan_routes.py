from fastapi import APIRouter, UploadFile, File
import sys
import os
from datetime import datetime

router = APIRouter()

# Paths
BASE = os.path.dirname(__file__)
DEVICE_PATH = os.path.abspath(
    os.path.join(BASE, '..', '..', 'modules', 'device')
)
APP_PATH = os.path.abspath(
    os.path.join(BASE, '..', '..', 'modules', 'app')
)
AI_PATH = os.path.abspath(
    os.path.join(BASE, '..', '..', 'modules', 'ai')
)
REPORT_PATH = os.path.abspath(
    os.path.join(BASE, '..', '..', 'modules', 'report')
)
EXPLOIT_PATH = os.path.abspath(
    os.path.join(BASE, '..', '..', 'modules', 'exploit')
)

for path in [
    DEVICE_PATH, APP_PATH,
    AI_PATH, REPORT_PATH, EXPLOIT_PATH
]:
    if path not in sys.path:
        sys.path.append(path)


def get_summary(vulns):
    return {
        "total_issues": len(vulns),
        "critical": sum(
            1 for v in vulns
            if v.get('severity') == 'CRITICAL'
        ),
        "high": sum(
            1 for v in vulns
            if v.get('severity') == 'HIGH'
        ),
        "medium": sum(
            1 for v in vulns
            if v.get('severity') == 'MEDIUM'
        ),
        "low": sum(
            1 for v in vulns
            if v.get('severity') == 'LOW'
        )
    }


def save_to_db(data):
    try:
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
        from models.database import db
        db.save_scan(data)
    except Exception as e:
        print(f"DB Error: {e}")


# ==================
# CHECK DEVICE
# ==================
@router.get("/check-device")
def check_device():
    try:
        from adb_interface import ADBInterface
        adb = ADBInterface()
        devices = adb.get_devices()

        if 'device' in devices:
            return {
                "status": "success",
                "connected": True,
                "device_info": {
                    "android_version": adb.check_android_version(),
                    "security_patch": adb.check_security_patch(),
                    "selinux": adb.check_selinux(),
                    "bootloader": adb.check_bootloader(),
                    "encryption": adb.check_encryption(),
                    "raw": devices
                }
            }
        else:
            return {
                "status": "success",
                "connected": False,
                "message": "No Device Connected",
                "instructions": [
                    "USB Cable Se Phone Connect Karo",
                    "USB Debugging ON Karo",
                    "Phone Mein Allow Click Karo"
                ]
            }
    except Exception as e:
        return {
            "status": "error",
            "connected": False,
            "message": str(e)
        }


# ==================
# DEVICE SCAN
# ==================
@router.get("/device-scan")
def device_scan():
    try:
        from firmware_checker import FirmwareChecker
        from network_checker import NetworkChecker
        from rag_analyzer import RAGAnalyzer

        fw = FirmwareChecker()
        fw.run_all_checks()

        net = NetworkChecker()
        net.run_all_checks()

        all_vulns = (
            fw.vulnerabilities + net.vulnerabilities
        )

        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(all_vulns)

        save_to_db({
            'scan_type': 'device',
            'vulnerabilities': all_vulns,
            'safe': fw.safe + net.safe,
            'timestamp': datetime.utcnow().isoformat()
        })

        return {
            "status": "success",
            "scan_type": "device",
            "timestamp": datetime.utcnow().isoformat(),
            "device_vulnerabilities": fw.vulnerabilities,
            "device_safe": fw.safe,
            "network_vulnerabilities": net.vulnerabilities,
            "network_safe": net.safe,
            "ai_analysis": ai_results,
            "summary": get_summary(all_vulns)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# APP SCAN
# ==================
@router.get("/app-scan")
def app_scan():
    try:
        from apk_analyzer import APKAnalyzer
        from rag_analyzer import RAGAnalyzer

        apk_path = os.path.join(APP_PATH, 'test.apk')

        if not os.path.exists(apk_path):
            return {
                "status": "error",
                "message": "APK Not Found! Upload Karo"
            }

        analyzer = APKAnalyzer(apk_path)
        analyzer.run_all_checks()

        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(
            analyzer.vulnerabilities
        )

        save_to_db({
            'scan_type': 'app',
            'apk': 'test.apk',
            'vulnerabilities': analyzer.vulnerabilities,
            'safe': analyzer.safe,
            'timestamp': datetime.utcnow().isoformat()
        })

        return {
            "status": "success",
            "scan_type": "app",
            "apk_file": "test.apk",
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerabilities": analyzer.vulnerabilities,
            "safe": analyzer.safe,
            "ai_analysis": ai_results,
            "summary": get_summary(analyzer.vulnerabilities)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# UPLOAD APK
# ==================
@router.post("/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    try:
        apk_path = os.path.join(
            APP_PATH, 'uploaded.apk'
        )

        with open(apk_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        file_size = os.path.getsize(apk_path)

        return {
            "status": "success",
            "message": "APK Uploaded!",
            "filename": file.filename,
            "size": file_size
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# SCAN UPLOADED APK
# ==================
@router.get("/scan-uploaded-apk")
def scan_uploaded_apk():
    try:
        from apk_analyzer import APKAnalyzer
        from rag_analyzer import RAGAnalyzer

        uploaded = os.path.join(APP_PATH, 'uploaded.apk')
        default = os.path.join(APP_PATH, 'test.apk')

        if os.path.exists(uploaded):
            apk_path = uploaded
            apk_name = 'uploaded.apk'
        elif os.path.exists(default):
            apk_path = default
            apk_name = 'test.apk'
        else:
            return {
                "status": "error",
                "message": "Koi APK Nahi Mili!"
            }

        analyzer = APKAnalyzer(apk_path)
        analyzer.run_all_checks()

        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(
            analyzer.vulnerabilities
        )

        save_to_db({
            'scan_type': 'uploaded_apk',
            'apk': apk_name,
            'vulnerabilities': analyzer.vulnerabilities,
            'timestamp': datetime.utcnow().isoformat()
        })

        return {
            "status": "success",
            "apk_file": apk_name,
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerabilities": analyzer.vulnerabilities,
            "safe": analyzer.safe,
            "ai_analysis": ai_results,
            "summary": get_summary(analyzer.vulnerabilities)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# NETWORK SCAN
# ==================
@router.get("/network-scan")
def network_scan():
    try:
        from network_checker import NetworkChecker
        from traffic_analyzer import TrafficAnalyzer
        from rag_analyzer import RAGAnalyzer

        net = NetworkChecker()
        net.run_all_checks()

        traffic = TrafficAnalyzer()
        traffic_results = traffic.run_analysis()

        all_vulns = (
            net.vulnerabilities +
            traffic_results.get('findings', [])
        )

        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(all_vulns)

        return {
            "status": "success",
            "scan_type": "network",
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerabilities": all_vulns,
            "safe": net.safe,
            "ai_analysis": ai_results,
            "method": "ADB Stats - No Proxy",
            "summary": get_summary(all_vulns)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# DYNAMIC SCAN
# ==================
@router.get("/dynamic-scan")
def dynamic_scan():
    try:
        from dynamic_analyzer import DynamicAnalyzer
        from rag_analyzer import RAGAnalyzer

        analyzer = DynamicAnalyzer()
        apps = analyzer.get_installed_apps()

        targets = [
            'jakhar.aseem.diva',
            'com.snapchat.android',
            'com.instagram.android',
            'com.facebook.orca',
            'com.zhiliaoapp.musically'
        ]

        target = None
        for t in targets:
            if t in apps:
                target = t
                break

        if not target and apps:
            target = apps[0]

        results = analyzer.run_dynamic_analysis(target)

        all_vulns = results.get('vulnerabilities', [])
        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(all_vulns)

        save_to_db({
            'scan_type': 'dynamic',
            'package': target,
            'vulnerabilities': all_vulns,
            'timestamp': datetime.utcnow().isoformat()
        })

        return {
            "status": "success",
            "scan_type": "dynamic",
            "timestamp": datetime.utcnow().isoformat(),
            "target_package": target,
            "total_apps": len(apps),
            "dynamic_results": results,
            "ai_analysis": ai_results,
            "summary": {
                "total_issues": len(all_vulns),
                "safe_items": len(
                    results.get('safe', [])
                )
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# EXPLOIT SCAN
# ==================
@router.get("/exploit-scan/{package}")
def exploit_scan(package: str):
    try:
        from exploit_engine import ExploitEngine

        engine = ExploitEngine()
        results = engine.run_all_exploits(package)

        successful = [
            r for r in results
            if r.get('status') in [
                'SUCCESS', 'VULNERABLE'
            ]
        ]

        try:
            sys.path.append(
                os.path.abspath(
                    os.path.join(BASE, '..', '..')
                )
            )
            from models.database import db
            db.save_exploit({
                'package': package,
                'results': results,
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception:
            pass

        return {
            "status": "success",
            "package": package,
            "timestamp": datetime.utcnow().isoformat(),
            "exploit_results": results,
            "summary": {
                "total_tests": len(results),
                "successful": len(successful),
                "failed": len(results) - len(successful)
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# FULL SCAN
# ==================
@router.get("/full-scan")
def full_scan():
    try:
        from firmware_checker import FirmwareChecker
        from network_checker import NetworkChecker
        from apk_analyzer import APKAnalyzer
        from rag_analyzer import RAGAnalyzer
        from report_generator import ReportGenerator

        # Device Scan
        fw = FirmwareChecker()
        fw.run_all_checks()

        # Network Scan
        net = NetworkChecker()
        net.run_all_checks()

        # App Scan
        uploaded = os.path.join(APP_PATH, 'uploaded.apk')
        default = os.path.join(APP_PATH, 'test.apk')

        app_vulns = []
        app_safe = []
        apk_name = "N/A"

        if os.path.exists(uploaded):
            apk_path = uploaded
            apk_name = 'uploaded.apk'
        elif os.path.exists(default):
            apk_path = default
            apk_name = 'test.apk'
        else:
            apk_path = None

        if apk_path:
            analyzer = APKAnalyzer(apk_path)
            analyzer.run_all_checks()
            app_vulns = analyzer.vulnerabilities
            app_safe = analyzer.safe

        # All Vulns
        all_vulns = (
            fw.vulnerabilities +
            net.vulnerabilities +
            app_vulns
        )

        # AI Analysis
        rag = RAGAnalyzer()
        ai_results = rag.analyze_all(all_vulns)
        exec_summary = rag.generate_executive_summary(
            all_vulns
        )

        # Report Save
        report = ReportGenerator()
        report.add_device_results(
            fw.safe + net.safe,
            fw.vulnerabilities + net.vulnerabilities
        )
        report.add_app_results(
            {'name': apk_name},
            app_vulns,
            app_safe
        )
        report.save_report("full_report")

        summary = get_summary(all_vulns)

        save_to_db({
            'scan_type': 'full',
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        })

        return {
            "status": "success",
            "scan_type": "full",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": summary,
            "device_vulnerabilities": fw.vulnerabilities,
            "device_safe": fw.safe,
            "network_vulnerabilities": net.vulnerabilities,
            "network_safe": net.safe,
            "app_vulnerabilities": app_vulns,
            "app_safe": app_safe,
            "ai_analysis": ai_results,
            "executive_summary": exec_summary
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# STATS
# ==================
@router.get("/stats")
def get_stats():
    try:
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
        from models.database import db
        stats = db.get_stats()
        return {
            "status": "success",
            "stats": stats
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }