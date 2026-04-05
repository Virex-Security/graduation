from dobby_chat import SecurityChatbot
from dashboard import dashboard
import time

def test_nlp_fix():
    print("--- Testing Dobby Arabic NLP Fix ---")
    bot = SecurityChatbot(dashboard)
    
    # Pre-populate dashboard with some data
    dashboard.stats['total_requests'] = 500
    dashboard.log_threat("SQL Injection", "192.168.1.50", "Test threat", severity="High")
    
    test_cases = [
        ("احصايات", "Status Report", "تقرير الحالة"),
        ("هات احصائيات", "Status Report Var 2", "تقرير الحالة"),
        ("حلل الهجمات", "General Analysis", "تهديدات حديثة"),
        ("Analyze attacks", "General Analysis EN", "recent threats"),
        ("ايه الاخبار", "Status colloquial", "تقرير الحالة")
    ]
    
    for query, test_name, expected_keyword in test_cases:
        print(f"\n[Test: {test_name}] Query: '{query}'")
        response = bot.generate_response(query)
        print(f"Response: {response}")
        
        if expected_keyword in response:
            print("✅ Passed")
        else:
            print(f"❌ Failed. Expected '{expected_keyword}'")

if __name__ == "__main__":
    test_nlp_fix()
