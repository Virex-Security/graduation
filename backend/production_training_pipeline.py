import subprocess
import sys
import os

def run_cmd(cmd):
    print(f"\n======================================")
    print(f"RUNNING: {' '.join(cmd)}")
    print(f"======================================\n")
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    # Stream output live
    for line in iter(process.stdout.readline, ''):
        sys.stdout.write(line)
        sys.stdout.flush()
        
    process.wait()
    if process.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {process.returncode}")
        sys.exit(process.returncode)
    
    print("\n[OK] Step Completed Successfully.")

def main():
    print("Starting VIREX Production Retraining Pipeline...")
    
    run_cmd(["python", "build_lightgbm_model.py", "30"])
    
    # 2. Export to ONNX
    run_cmd(["python", "convert_lightgbm_onnx.py"])
    
    # 3. Audit Model
    run_cmd(["python", "audit_model.py"])
    
    # 4. Generate Markdown Deliverables
    run_cmd(["python", "generate_reports.py"])
    
    print("\n[SUCCESS] Production pipeline complete. All models and reports are ready in backend/models/")

if __name__ == "__main__":
    main()
