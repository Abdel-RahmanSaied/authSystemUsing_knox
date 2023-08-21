import secrets
import urllib.parse


def generate_key():
    return secrets.token_urlsafe(16)


def generate_verifyAccount_url(request):
    key = generate_key()
    url = request.build_absolute_uri(f"/auth/users/{urllib.parse.quote(key)}/verifyAccount/")
    return url, key


def generate_ResetPassword_url(request):
    key = generate_key()
    url = request.build_absolute_uri(f"/auth/password-reset/{urllib.parse.quote(key)}/confirm/")
    return url, key
