import subprocess

# ADB Ka Full Path
ADB_PATH = r"C:\platform-tools\adb.exe"

class ADBInterface:
    
    def run_command(self, cmd):
        try:
            result = subprocess.run(
                f"{ADB_PATH} shell {cmd}",
                capture_output=True,
                text=True,
                shell=True
            )
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_devices(self):
        result = subprocess.run(
            f"{ADB_PATH} devices",
            capture_output=True,
            text=True,
            shell=True
        )
        return result.stdout.strip()
    
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

# Test Karo
if __name__ == "__main__":
    adb = ADBInterface()
    print("Connected Devices:")
    print(adb.get_devices())
    print("\nSecurity Patch:")
    print(adb.check_security_patch())
    print("\nSELinux Status:")
    print(adb.check_selinux())
    print("\nAndroid Version:")
    print(adb.check_android_version())
    print("\nBootloader Status:")
    print(adb.check_bootloader())
    print("\nEncryption Status:")
    print(adb.check_encryption())