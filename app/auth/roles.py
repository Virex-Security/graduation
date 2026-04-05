class Role:
    ADMIN = "admin"
    USER = "user"

    @classmethod
    def all_roles(cls):
        return [cls.ADMIN, cls.USER]
