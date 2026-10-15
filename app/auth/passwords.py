from argon2 import PasswordHasher
try:
    from argon2.exceptions import InvalidHashError, VerifyMismatchError
except ImportError:
    try:
        from argon2.exceptions import InvalidHash as InvalidHashError, VerifyMismatchError
    except ImportError:
        class VerifyMismatchError(Exception): pass
        class InvalidHashError(Exception): pass

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
