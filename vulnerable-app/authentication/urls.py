"""
Authentication URL Configuration

Maps authentication endpoints to views.
Contains vulnerable endpoints V01 (SQL Injection) and V16 (Brute Force).
"""

from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Login - V01: SQL Injection, V16: No rate limiting
    path('login/', views.login_view, name='login'),
    path('login/api/', views.login_api, name='login_api'),

    # Registration
    path('register/', views.register_view, name='register'),

    # Logout
    path('logout/', views.logout_view, name='logout'),

    # Password management
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('change-password/', views.change_password_view, name='change_password'),
]
