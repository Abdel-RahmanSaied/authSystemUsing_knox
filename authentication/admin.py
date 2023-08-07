from django.contrib import admin
from .models import USER, PasswordReset, EmailVerification
from django.utils.html import format_html

# Register your models here.

# admin.site.register(USER)
# admin.site.register(PasswordReset)
# admin.site.register(EmailVerification)


@admin.register(USER)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'thumbnail',
                    'phone', 'job_tittle', 'department', 'organization', 'country', 'email_verified',
                    'date_joined', 'last_login')
    list_display_links = ('id', 'username', 'email',)

    list_filter = ('id', 'username', 'email', 'first_name', 'last_name', 'profile_picture',
                   'phone', 'job_tittle', 'department', 'organization', 'country', 'email_verified',
                   'date_joined', 'last_login')

    search_fields = ('id', 'username', 'email', 'first_name', 'last_name', 'profile_picture',
                     'phone', 'job_tittle', 'department', 'organization', 'country', 'email_verified',
                     'date_joined', 'last_login')

    ordering = ('id', 'username', 'email', 'first_name', 'last_name', 'profile_picture',
                'phone', 'job_tittle', 'department', 'organization', 'country', 'email_verified',
                'date_joined', 'last_login')

    list_per_page = 25

    def thumbnail(self, obj):
        if obj.profile_picture.name != '':
            return format_html(
                f'<img src="{obj.profile_picture.url}" style= "width: 45px; height: 45px; object-fit : cover; "  />')
        return obj.profile_picture.url

    thumbnail.short_description = 'Profile Picture'


@admin.register(PasswordReset)
class PasswordResetAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'key', 'created_at', 'expires_at')
    list_display_links = ('id', 'user', 'key', 'created_at', 'expires_at')
    list_filter = ('id', 'user', 'key', 'created_at', 'expires_at')

@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'key', 'created_at', 'expires_at')
    list_display_links = ('id', 'user', )
    list_filter = ('id', 'user', 'key', 'created_at', 'expires_at')


