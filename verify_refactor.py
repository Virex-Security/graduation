from dobby_chat import SecurityChatbot
from dashboard import dashboard

def test_refactor():
    print("Testing SecurityChatbot import and instantiation...")
    bot = SecurityChatbot(dashboard)
    response = bot.generate_response("hello")
    print(f"Response: {response}")
    assert "Dobby" not in response, "Dobby should not reintroduce himself in Natural Mode"
    assert any(g in response for g in ["Hey", "Hi", "here", "What's up", "Ready"]), "Standard greeting failed"
    print("✅ Refactor Semantic Check Passed")

if __name__ == "__main__":
    test_refactor()
