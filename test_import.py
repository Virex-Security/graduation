import sys
import traceback

try:
    from detections import detect_csrf, detect_ssrf
    print("SUCCESS: Imported detections")
except Exception as e:
    print("ERROR:")
    traceback.print_exc()
