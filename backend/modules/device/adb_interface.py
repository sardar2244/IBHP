import subprocess
import sys
import os
import shutil

def get_adb_path():
    """Auto Detect ADB Path - Windows/Linux/Mac"""
    
    # Method 1: System PATH Mein Check Karo
    adb_in_path = shutil.which('adb')
    if adb_in_path:
        return adb_in_path
    
    # Method 2: Windows Common Paths
    if sys.platform == "win32":
        windows_paths = [
            r"C:\platform-tools\adb.exe",
            r"D:\platform-tools\adb.exe",
            r"E:\platform-tools\adb.exe",
            r"F:\platform-tools\adb.exe",
            os.path.expanduser(
                r"~\AppData\Local\Android\Sdk\platform-tools\adb.exe"
            ),
        ]
        for path in windows_paths:
            if os.path.exists(path):
                return path
    
    # Method 3: Linux/Mac Common Paths
    else:
        linux_paths = [
            "/usr/bin/adb",
            "/usr/local/bin/adb",
            os.path.expanduser(
                "~/Android/Sdk/platform-tools/adb"
            ),
            "/opt/android-sdk/platform-tools/adb",
        ]
        for path in linux_paths:
            if os.path.exists(path):
                return path
    
    # Default
    return "adb"

# Global ADB Path
ADB_PATH = get_adb_path()
print(f"✅ ADB Found: {ADB_PATH}")

class ADBInterface:
    def __init__(self):
        self.ADB_PATH = ADB_PATH

    def run_command(self, cmd):
        try:
            result = subprocess.run(
                f'"{ADB_PATH}" shell {cmd}',
                capture_output=True,
                shell=True,
                timeout=30
            )
            return result.stdout.decode(
                'utf-8', errors='replace'
            ).strip()
        except subprocess.TimeoutExpired:
            return "Timeout Error"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_devices(self):
        try:
            result = subprocess.run(
                f'"{ADB_PATH}" devices',
                capture_output=True,
                shell=True
            )
            return result.stdout.decode(
                'utf-8', errors='replace'
            ).strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def check_bootloader(self):
        return self.run_command(
            "getprop ro.boot.verifiedbootstate"
        )

    def check_selinux(self):
        return self.run_command("getenforce")

    def check_usb_debug(self):
        return self.run_command(
            "settings get global adb_enabled"
        )

    def check_security_patch(self):
        return self.run_command(
            "getprop ro.build.version.security_patch"
        )

    def check_kernel_version(self):
        return self.run_command("uname -r")

    def check_encryption(self):
        return self.run_command(
            "getprop ro.crypto.state"
        )

    def check_android_version(self):
        return self.run_command(
            "getprop ro.build.version.release"
        )

    def check_dm_verity(self):
        return self.run_command(
            "getprop ro.boot.veritymode"
        )

    def check_hardware_keystore(self):
        return self.run_command(
            "getprop ro.hardware.keystore"
        )

    def check_build_type(self):
        return self.run_command(
            "getprop ro.build.type"
        )

    def check_test_keys(self):
        return self.run_command(
            "getprop ro.build.tags"
        )

if __name__ == "__main__":
    print(f"Platform: {sys.platform}")
    print(f"ADB Path: {ADB_PATH}")
    
    adb = ADBInterface()
    print("\nDevice Info:")
    print(f"Devices: {adb.get_devices()}")
    print(f"Android: {adb.check_android_version()}")
    print(f"SELinux: {adb.check_selinux()}")
    print(f"Build Type: {adb.check_build_type()}")
    print(f"Build Tags: {adb.check_test_keys()}")
    print(f"DM-Verity: {adb.check_dm_verity()}")