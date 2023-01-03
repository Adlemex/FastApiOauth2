from models import User


class RegUser(User):
    password: str
    disabled = True