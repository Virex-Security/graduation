from app.repositories.rule_repo import RuleRepository

class RuleService:
    """Business logic for WAF rules."""
    
    @staticmethod
    def get_active_rules():
        return RuleRepository.get_all(active_only=True)
    
    @staticmethod
    def get_all_rules():
        return RuleRepository.get_all(active_only=False)
    
    @staticmethod
    def initialize_rules():
        RuleRepository.ensure_default_rules()
