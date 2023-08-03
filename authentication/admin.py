from django.contrib import admin
from .models import USER, PasswordReset, EmailVerification

# Register your models here.

admin.site.register(USER)
admin.site.register(PasswordReset)
admin.site.register(EmailVerification)

