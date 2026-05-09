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
sys.path.append(
    os.path.join(
        os.path.dirname(__file__),
        '..', '..', 'modules', 'ai'
    )
)
sys.path.append(
    os.path.join(
        os.path.dirname(__file__),
        '..', '..', 'modules', 'report'
    )
)

from firmware_checker import FirmwareChecker
from network_checker import NetworkChecker
from ai_analyzer import AIAnalyzer
from report_generator import ReportGenerator

router = APIRouter()

@router.get("/device-scan")
def device_scan():
    try:
        # Device Scan
        fw = FirmwareChecker()
        fw.run_all_checks()

        # Network Scan
        net = NetworkChecker()
        net.run_all_checks()

        # AI Analysis
        ai = AIAnalyzer()
        all_vulns = (
            fw.vulnerabilities +
            net.vulnerabilities
        )
        ai_results = ai.analyze_all(all_vulns)

        return {
            "status": "success",
            "device_vulnerabilities":
                fw.vulnerabilities,
            "device_safe": fw.safe,
            "network_vulnerabilities":
                net.vulnerabilities,
            "network_safe": net.safe,
            "ai_analysis": ai_results
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

        # App Scan
        analyzer = APKAnalyzer(apk_path)
        analyzer.run_all_checks()

        # AI Analysis
        ai = AIAnalyzer()
        ai_results = ai.analyze_all(
            analyzer.vulnerabilities
        )

        return {
            "status": "success",
            "vulnerabilities":
                analyzer.vulnerabilities,
            "safe": analyzer.safe,
            "ai_analysis": ai_results
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

        ai = AIAnalyzer()
        ai_results = ai.analyze_all(
            net.vulnerabilities
        )

        return {
            "status": "success",
            "vulnerabilities":
                net.vulnerabilities,
            "safe": net.safe,
            "ai_analysis": ai_results
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/full-scan")
def full_scan():
    try:
        # Device Scan
        fw = FirmwareChecker()
        fw.run_all_checks()

        # Network Scan
        net = NetworkChecker()
        net.run_all_checks()

        # App Scan
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

        all_vulns = (
            fw.vulnerabilities +
            net.vulnerabilities
        )

        if os.path.exists(apk_path):
            analyzer = APKAnalyzer(apk_path)
            analyzer.run_all_checks()
            all_vulns += analyzer.vulnerabilities
            app_vulns = analyzer.vulnerabilities
            app_safe = analyzer.safe
        else:
            app_vulns = []
            app_safe = []

        # AI Analysis
        ai = AIAnalyzer()
        ai_results = ai.analyze_all(all_vulns)

        # Report Generate
        report = ReportGenerator()
        report.add_device_results(
            fw.safe + net.safe,
            fw.vulnerabilities + net.vulnerabilities
        )
        report.add_app_results(
            {'name': 'Scanned App'},
            app_vulns,
            app_safe
        )
        report.save_report("full_report")

        # Summary
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

        return {
            "status": "success",
            "summary": {
                "total_issues": len(all_vulns),
                "critical": critical,
                "high": high,
                "medium": medium
            },
            "device_vulnerabilities":
                fw.vulnerabilities,
            "device_safe": fw.safe,
            "network_vulnerabilities":
                net.vulnerabilities,
            "app_vulnerabilities": app_vulns,
            "app_safe": app_safe,
            "ai_analysis": ai_results
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }