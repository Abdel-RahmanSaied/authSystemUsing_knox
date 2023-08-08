import datetime

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.conf import settings
from django.dispatch import receiver
from django.urls import reverse
# from django_rest_passwordreset.signals import reset_password_token_created
# from django.core.mail import send_mail
from django.utils.translation import gettext_lazy as _
from django.utils import timezone


# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class USER(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, null=False, blank=False,
                              error_messages={
                                  "unique": _("A user with that email already exists."),
                              })
    username = models.CharField(max_length=30, unique=True, null=False, blank=False)
    first_name = models.CharField(max_length=30, null=False, blank=False)
    last_name = models.CharField(max_length=30, null=False, blank=False)
    profile_picture = models.ImageField(upload_to='profile_pics', default='profile_pics/default_profile.jpg',
                                        blank=True, null=True)
    phone = models.CharField(max_length=15, null=False, blank=False,
                             error_messages={
                                 "unique": _("A user with that phone number already exists."),
                             })
    job_tittle = models.CharField(max_length=20, )
    department = models.CharField(max_length=20, )
    organization = models.CharField(max_length=20, )
    country = models.CharField(max_length=20, )
    email_verified = models.BooleanField(_("email_verified"),
                                         default=False,
                                         help_text=_(
                                             "Designates whether this user's email is verified "), )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    def verify_account(self):
        try:
            self.email_verified = True
            self.save()
            return True
        except Exception as e:
            print(e)
            return False

    def change_password(self, password):
        try:
            self.set_password(password)
            self.save()
            return True
        except Exception as e:
            print(e)
            return False

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


class PasswordReset(models.Model):
    user = models.ForeignKey(USER, on_delete=models.CASCADE)
    key = models.CharField(_("Key"), max_length=64, db_index=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=datetime.datetime.now() + timezone.timedelta(hours=1),
                                      null=False, blank=False)

    def __str__(self):
        return self.user.email

    def get_absolute_url(self):
        return reverse('password_reset_confirm', kwargs={'key': self.key})

class EmailVerification(models.Model):
    user = models.ForeignKey(USER, on_delete=models.CASCADE)
    key = models.CharField(_("Key"), max_length=64, db_index=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=datetime.datetime.now() + timezone.timedelta(hours=1),
                                      null=False, blank=False)

    def __str__(self):
        return str(self.user.email)
