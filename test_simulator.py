"""
Quick Simulator Test
====================
Tests a few attacks to verify the simulator works
"""

def test_simulator():
    """Run a quick test of the attack simulator"""
    
    try:
        from attack_simulator import RealAttackSimulator
    except ImportError:
        print("❌ Could not import RealAttackSimulator")
        return
    
    print("="*60)
    print("  Quick Simulator Test")
    print("="*60)
    
    # Create simulator
    sim = RealAttackSimulator(
        dashboard_url="http://localhost:8070",
        api_url="http://localhost:5000"
    )
    
    # Test connectivity
    print("\n🔍 Testing connectivity...")
    try:
        import requests
        resp = requests.get("http://localhost:5000/api/health", timeout=3)
        print(f"✅ API is reachable (status {resp.status_code})")
    except Exception as e:
        print(f"❌ API not reachable: {e}")
        print("   Make sure to run: python run_api.py")
        return
    
    try:
        resp = requests.get("http://localhost:8070/api/health", timeout=3)
        print(f"✅ Dashboard is reachable (status {resp.status_code})")
    except Exception as e:
        print(f"⚠️  Dashboard not reachable: {e}")
        print("   Dashboard attacks will be skipped")
    
    # Run small test
    print("\n🎯 Running quick test (5 attacks of each type)...\n")
    
    sim.sql_injection_attacks(5)
    sim.legitimate_traffic(3)
    
    sim.xss_attacks(5)
    sim.legitimate_traffic(3)
    
    sim.brute_force_login(10)
    sim.legitimate_traffic(3)
    
    sim.scanner_simulation(5)
    
    # Show results
    sim.print_stats()
    sim.export_dataset("data/test_attack_dataset.csv")
    
    print("\n✅ Test complete!")
    print("\nTo run full simulation:")
    print("  python attack_simulator.py")


if __name__ == "__main__":
    test_simulator()
