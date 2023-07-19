# from .models import USER
from django.db.models import Q
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

USER = get_user_model()
class EmailAuthBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = USER.objects.get(
                Q(username__iexact=username) |
                Q(email__iexact=username)
            )

        except USER.DoesNotExist:
            return None

        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def get_user(self, user_id):
        try:
            user = USER.objects.get(pk=user_id)
        except USER.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None