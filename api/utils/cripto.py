import os
from cryptography.fernet import Fernet, InvalidToken

_fernet = None

def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.getenv("USER_ID_ENC_KEY")
        if not key:
            raise RuntimeError("Missing USER_ID_ENC_KEY env var")
        _fernet = Fernet(key.encode("utf-8"))
    return _fernet


def encrypt_user_id(user_id: int) -> str:
    """
    Encrypt user_id to a URL-safe token (Fernet).
    """
    f = _get_fernet()
    return f.encrypt(str(user_id).encode("utf-8")).decode("utf-8")


def decrypt_user_id(token: str) -> int:
    """
    Decrypt token back to user_id.
    Raises ValueError if token is invalid/tampered.
    """
    f = _get_fernet()
    try:
        raw = f.decrypt(token.encode("utf-8"))
        return int(raw.decode("utf-8"))
    except (InvalidToken, ValueError) as e:
        raise ValueError("Invalid user_id token") from e
