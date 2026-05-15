class Role:
    ADMIN = "admin"
    ANALYST = "analyst"
    MANAGER = "manager"
    USER = "user"

    @classmethod
    def all_roles(cls):
        return [cls.ADMIN, cls.ANALYST, cls.MANAGER, cls.USER]

    @classmethod
    def manager_and_above(cls):
        return [cls.ADMIN, cls.ANALYST, cls.MANAGER, cls.USER]

    @classmethod
    def analyst_and_above(cls):
        return [cls.ADMIN, cls.ANALYST]

    @classmethod
    def admin_only(cls):
        return [cls.ADMIN]
