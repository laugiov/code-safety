"""
Profile URL Configuration

Maps profile endpoints to views.
Contains vulnerable endpoints V07 (IDOR) and V08 (Mass Assignment).
"""

from django.urls import path
from . import views

app_name = 'profile'

urlpatterns = [
    # View profile - V07: IDOR
    path('', views.view_profile, name='view_profile'),
    path('lookup/', views.user_lookup, name='user_lookup'),

    # Update profile - V08: Mass Assignment
    path('update/', views.update_profile, name='update_profile'),
    path('update/api/', views.update_profile_api, name='update_profile_api'),

    # Addresses
    path('addresses/', views.manage_addresses, name='addresses'),
    path('addresses/add/', views.add_address, name='add_address'),
    path('addresses/delete/<int:address_id>/', views.delete_address, name='delete_address'),

    # Preferences
    path('preferences/', views.update_preferences, name='preferences'),
]
