
import os

def check_rules():
    base = "detections"
    for root, dirs, files in os.walk(base):
        for file in files:
            if file.endswith((".yaral", ".spl", ".kql")):
                print(f"[+] Found rule: {file}")

if __name__ == "__main__":
    check_rules()
