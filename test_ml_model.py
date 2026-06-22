"""
Quick ML Model Test Script
===========================
Tests the trained model with sample inputs
"""

def test_model():
    """Test ML model with various inputs"""
    
    try:
        from app.ml.inference import ml_analyze
    except ImportError:
        print("❌ Could not import ml_analyze")
        print("   Make sure you're in the project root directory")
        return
    
    print("="*60)
    print("  ML Model Test")
    print("="*60)
    
    # Test cases
    test_cases = [
        # Normal requests
        ("search=laptop&category=electronics", "Normal"),
        ("username=john&email=john@example.com", "Normal"),
        ("page=1&limit=10&sort=date", "Normal"),
        
        # SQL Injection
        ("id=1' OR '1'='1", "SQL Injection"),
        ("username=admin'--", "SQL Injection"),
        ("search=' UNION SELECT * FROM users--", "SQL Injection"),
        
        # XSS
        ("<script>alert(1)</script>", "XSS"),
        ("<img src=x onerror=alert(1)>", "XSS"),
        ("name=<svg onload=alert(document.cookie)>", "XSS"),
        
        # Command Injection
        ("file=test.txt; cat /etc/passwd", "Command Injection"),
        ("url=http://example.com | whoami", "Command Injection"),
        
        # Path Traversal
        ("file=../../../etc/passwd", "Path Traversal"),
        ("path=..\\..\\windows\\system32", "Path Traversal"),
    ]
    
    print("\n📊 Testing {} samples...\n".format(len(test_cases)))
    
    correct = 0
    total = len(test_cases)
    
    for text, expected_type in test_cases:
        result = ml_analyze(text)
        
        # Check if detection is correct
        is_attack = expected_type != "Normal"
        detected_attack = result.action in ["monitor", "block"]
        
        if is_attack == detected_attack:
            status = "✅"
            correct += 1
        else:
            status = "❌"
        
        print(f"{status} {expected_type:20s} | Risk: {result.risk_score:.2f} | Action: {result.action:8s} | Type: {result.attack_type}")
        print(f"   Input: {text[:60]}")
        print()
    
    accuracy = (correct / total) * 100
    print("="*60)
    print(f"📈 Results: {correct}/{total} correct ({accuracy:.1f}%)")
    print("="*60)
    
    if accuracy >= 80:
        print("✅ Model performance is good!")
    elif accuracy >= 60:
        print("⚠️  Model performance is acceptable but could be better")
    else:
        print("❌ Model performance is poor - consider retraining")
        print("   Run: python generate_realistic_training_data.py")
        print("   Then: python train_model.py")


if __name__ == "__main__":
    test_model()
