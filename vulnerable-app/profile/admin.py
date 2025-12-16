"""
Profile Admin Configuration
"""

from django.contrib import admin
from .models import UserPreferences, Address


@admin.register(UserPreferences)
class UserPreferencesAdmin(admin.ModelAdmin):
    list_display = ('user', 'newsletter', 'dark_mode', 'language')
    list_filter = ('newsletter', 'dark_mode', 'language')
    search_fields = ('user__username',)


@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('user', 'label', 'address_type', 'city', 'country', 'is_default')
    list_filter = ('address_type', 'country', 'is_default')
    search_fields = ('user__username', 'city', 'street_address')
