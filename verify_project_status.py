"""
Project Status Verification Script
===================================
Verifies all fixes from the conversation summary are in place
"""
import os
import sys
from pathlib import Path

def check_file_exists(filepath, description):
    """Check if a file exists"""
    exists = Path(filepath).exists()
    status = "[OK]" if exists else "[FAIL]"
    print(f"{status} {description}: {filepath}")
    return exists

def check_syntax(filepath):
    """Check Python file syntax"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            compile(f.read(), filepath, 'exec')
        print(f"[OK] Syntax valid: {filepath}")
        return True
    except SyntaxError as e:
        print(f"[FAIL] Syntax error in {filepath}: {e}")
        return False

def check_env_example():
    """Check .env.example has required variables"""
    required_vars = [
        "SECRET_KEY",
        "ADMIN_PASSWORD",
        "DATABASE_URL",
        "COOKIE_SECURE",
        "GEMINI_API_KEY"
    ]
    
    if not Path(".env.example").exists():
        print("❌ .env.example not found")
        return False
    
    with open(".env.example", 'r', encoding='utf-8') as f:
        content = f.read()
    
    missing = []
    for var in required_vars:
        if var not in content:
            missing.append(var)
    
    if missing:
        print(f"[FAIL] .env.example missing variables: {', '.join(missing)}")
        return False
    else:
        print("[OK] .env.example has all required variables")
        return True

def check_dockerfile_security():
    """Check Dockerfile has non-root user"""
    if not Path("Dockerfile").exists():
        print("❌ Dockerfile not found")
        return False
    
    with open("Dockerfile", 'r', encoding='utf-8') as f:
        content = f.read()
    
    has_user = "USER appuser" in content
    has_useradd = "useradd" in content
    
    if has_user and has_useradd:
        print("[OK] Dockerfile runs as non-root user")
        return True
    else:
        print("[FAIL] Dockerfile missing non-root user configuration")
        return False

def check_database_security():
    """Check database.py has security fixes"""
    if not Path("app/database.py").exists():
        print("❌ app/database.py not found")
        return False
    
    with open("app/database.py", 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = {
        "ADMIN_PASSWORD env var": 'os.getenv("ADMIN_PASSWORD")' in content,
        "CSRF rules": '"CSRF' in content or 'csrf' in content.lower(),
        "SSRF rules": '"SSRF' in content or 'ssrf' in content.lower(),
    }
    
    all_passed = True
    for check_name, passed in checks.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{status} Database security: {check_name}")
        if not passed:
            all_passed = False
    
    return all_passed

def check_ml_pipeline():
    """Check ML training uses Pipeline"""
    if not Path("train_model.py").exists():
        print("❌ train_model.py not found")
        return False
    
    with open("train_model.py", 'r', encoding='utf-8') as f:
        content = f.read()
    
    has_pipeline = "Pipeline" in content and "from sklearn.pipeline import Pipeline" in content
    has_overfitting_check = "overfitting" in content.lower()
    has_fpr = "False Positive Rate" in content or "fpr" in content
    
    checks = {
        "Uses sklearn.Pipeline": has_pipeline,
        "Overfitting detection": has_overfitting_check,
        "False Positive Rate check": has_fpr,
    }
    
    all_passed = True
    for check_name, passed in checks.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{status} ML Training: {check_name}")
        if not passed:
            all_passed = False
    
    return all_passed

def check_attack_simulator():
    """Check attack simulator targets real endpoints"""
    if not Path("attack_simulator.py").exists():
        print("❌ attack_simulator.py not found")
        return False
    
    with open("attack_simulator.py", 'r', encoding='utf-8') as f:
        content = f.read()
    
    real_endpoints = [
        "api/users",
        "api/orders",
        "api/products",
        "api/data",
        "api/login"
    ]
    
    checks = {
        f"Targets {endpoint}": endpoint in content
        for endpoint in real_endpoints
    }
    
    all_passed = True
    for check_name, passed in checks.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{status} Attack Simulator: {check_name}")
        if not passed:
            all_passed = False
    
    return all_passed

def check_sidebar_api_status():
    """Check sidebar has API connection status"""
    if not Path("app/static/javascript/sidebar_component.js").exists():
        print("❌ sidebar_component.js not found")
        return False
    
    with open("app/static/javascript/sidebar_component.js", 'r', encoding='utf-8') as f:
        content = f.read()
    
    has_check_function = "checkAPIConnection" in content
    has_health_endpoint = "/api/health" in content
    has_interval = "setInterval" in content
    
    checks = {
        "Has checkAPIConnection function": has_check_function,
        "Checks /api/health endpoint": has_health_endpoint,
        "Periodic checking (setInterval)": has_interval,
    }
    
    all_passed = True
    for check_name, passed in checks.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{status} Sidebar API Status: {check_name}")
        if not passed:
            all_passed = False
    
    return all_passed

def main():
    print("="*70)
    print("  VIREX PROJECT STATUS VERIFICATION")
    print("="*70)
    print()
    
    all_checks = []
    
    # Task 1: Git merge conflicts resolved
    print("[TASK 1] Git Merge Conflicts")
    print("-" * 70)
    all_checks.append(check_syntax("app/dashboard/routes.py"))
    all_checks.append(check_syntax("app/database.py"))
    all_checks.append(check_syntax("app/auth/decorators.py"))
    all_checks.append(check_syntax("app/auth/auth.py"))
    print()
    
    # Task 2: Dependencies
    print("[TASK 2] Dependencies")
    print("-" * 70)
    all_checks.append(check_file_exists("requirements.txt", "Requirements file"))
    print()
    
    # Task 3: User login fixes
    print("[TASK 3] User Login Fixes")
    print("-" * 70)
    all_checks.append(check_file_exists("data/users.json", "Users data file"))
    all_checks.append(check_file_exists("app/templates/login.html", "Login template"))
    all_checks.append(check_file_exists("app/static/javascript/login.js", "Login JavaScript"))
    print()
    
    # Task 4: API connection status
    print("[TASK 4] API Connection Status Indicator")
    print("-" * 70)
    all_checks.append(check_sidebar_api_status())
    print()
    
    # Task 5: Security fixes
    print("[TASK 5] Critical Security Fixes")
    print("-" * 70)
    all_checks.append(check_database_security())
    all_checks.append(check_dockerfile_security())
    all_checks.append(check_env_example())
    all_checks.append(check_file_exists("SECURITY.md", "Security documentation"))
    print()
    
    # Task 6: ML improvements
    print("[TASK 6] ML Model Accuracy Improvements")
    print("-" * 70)
    all_checks.append(check_file_exists("generate_realistic_training_data.py", "Training data generator"))
    all_checks.append(check_file_exists("train_model.py", "Model training script"))
    all_checks.append(check_file_exists("app/ml/inference_simple.py", "ML inference module"))
    all_checks.append(check_file_exists("test_ml_model.py", "ML test script"))
    all_checks.append(check_file_exists("ML_TRAINING_GUIDE.md", "ML training guide"))
    all_checks.append(check_ml_pipeline())
    print()
    
    # Task 7: Attack simulator
    print("[TASK 7] Real Attack Simulator")
    print("-" * 70)
    all_checks.append(check_file_exists("attack_simulator.py", "Attack simulator"))
    all_checks.append(check_file_exists("ATTACK_SIMULATOR_GUIDE.md", "Attack simulator guide"))
    all_checks.append(check_syntax("attack_simulator.py"))
    all_checks.append(check_attack_simulator())
    print()
    
    # Summary
    print("="*70)
    passed = sum(all_checks)
    total = len(all_checks)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"  SUMMARY: {passed}/{total} checks passed ({percentage:.1f}%)")
    print("="*70)
    
    if passed == total:
        print("\n[SUCCESS] All checks passed! Project is ready.")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} check(s) failed. Review output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
