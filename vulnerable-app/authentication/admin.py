"""
Authentication Admin Configuration

Register models with Django admin.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, LoginAttempt


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin configuration."""
    list_display = ('username', 'email', 'is_staff', 'is_verified', 'failed_login_attempts')
    list_filter = ('is_staff', 'is_superuser', 'is_verified', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name')

    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('phone', 'address', 'date_of_birth', 'profile_picture')
        }),
        ('Security', {
            'fields': ('is_verified', 'failed_login_attempts')
        }),
        ('Sensitive Data (DEMO ONLY)', {
            'fields': ('credit_card', 'ssn'),
            'classes': ('collapse',),
            'description': 'WARNING: These fields store data in plain text for demonstration purposes.'
        }),
    )


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Login Attempt admin configuration."""
    list_display = ('username', 'ip_address', 'timestamp', 'successful')
    list_filter = ('successful', 'timestamp')
    search_fields = ('username', 'ip_address')
    ordering = ('-timestamp',)
    readonly_fields = ('username', 'ip_address', 'user_agent', 'timestamp', 'successful')
