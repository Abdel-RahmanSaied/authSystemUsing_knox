from django.contrib import admin
from .models import USER, PasswordReset

# Register your models here.

admin.site.register(USER)
admin.site.register(PasswordReset)

