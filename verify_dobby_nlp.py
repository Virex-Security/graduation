from dobby_chat import SecurityChatbot
from dashboard import dashboard
import time

def test_nlp():
    print("--- Testing Dobby NLP & Analytics ---")
    bot = SecurityChatbot(dashboard)
    
    test_cases = [
        # Identity
        ("What is your name?", "Name EN", "Dobby"),
        ("اسمك ايه؟", "Name AR", "دبي"),
        ("Who are you?", "Identity EN", "Assistant"),
        
        # Small Talk
        ("Thanks Dobby", "Thanks EN", "welcome"),
        ("شكرا يا دبي", "Thanks AR", "العفو"),
        ("How are you?", "Status EN", "monitoring"),
        
        # Analytics
        ("How many SQL injections?", "SQL Stats", "SQL Injection"),
        ("كام هجمة XSS؟", "XSS Stats AR", "XSS"),
        ("Top attacker", "Top IP", "top offender"),
        ("اكتر اي بي بيعمل هجوم", "Top IP AR", "أخطر IP"),
        
        # General Status
        ("System status", "General Status", "Health"),
        ("ايه الاخبار", "General Status AR", "تقرير الحالة")
    ]
    
    for query, test_name, expected_keyword in test_cases:
        print(f"\n[Test: {test_name}] Query: '{query}'")
        response = bot.generate_response(query)
        print(f"Response: {response}")
        
        # Loose matching for robustness
        if expected_keyword.lower() in response.lower():
            print("✅ Passed")
        else:
            print(f"❌ Failed. Expected '{expected_keyword}' in response.")

if __name__ == "__main__":
    # Populate some dummy stats for testing
    dashboard.stats['sql_injection_attempts'] = 5
    dashboard.stats['total_requests'] = 100
    test_nlp()
