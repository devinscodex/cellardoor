"""Password hashing (argon2id after a pepper HMAC) and random token helpers."""
import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

MIN_PASSWORD = 12
MAX_PASSWORD = 128
MIN_PEPPER_BYTES = 32

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("cellardoor-timing-equalizer")


class CryptoError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def check_password_policy(password):
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise CryptoError("password_policy")


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _version_number(version):
    if not (isinstance(version, str) and re.fullmatch(r"p[0-9]{1,6}", version)):
        raise CryptoError("pepper_version")
    return int(version[1:])


def current_version(peppers):
    """Newest pepper version. Versions look like p1, p2, p10 and sort by number."""
    return max(peppers, key=_version_number)


def _prehash(password, pepper):
    if len(pepper) < MIN_PEPPER_BYTES:
        raise CryptoError("pepper_short")
    return hmac.new(pepper, password.encode(), hashlib.sha256).hexdigest()


def hash_password(password, peppers, version):
    """Return 'version$argon2id-hash'. peppers maps version -> secret bytes."""
    check_password_policy(password)
    return f"{version}${_ph.hash(_prehash(password, peppers[version]))}"


def verify_password(password, stored, peppers):
    """Return (ok, needs_rehash). Never raises on a wrong password or bad hash."""
    version, _, encoded = stored.partition("$")
    pepper = peppers.get(version)
    if pepper is None or not isinstance(password, str) or len(password) > MAX_PASSWORD:
        verify_dummy()
        return False, False
    try:
        _ph.verify(encoded, _prehash(password, pepper))
    except (VerifyMismatchError, InvalidHashError):
        return False, False
    return True, _ph.check_needs_rehash(encoded) or version != current_version(peppers)


def verify_dummy():
    """Burn the same argon2 work as a real check, for unknown-user timing."""
    try:
        _ph.verify(_DUMMY_HASH, "never-matches")
    except VerifyMismatchError:
        pass
