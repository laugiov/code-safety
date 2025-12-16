"""
Notifications URL Configuration

Maps notification endpoints to views.
Contains vulnerable endpoint V11 (SSTI).
"""

from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    # Settings
    path('settings/', views.notification_settings, name='settings'),

    # Email preview - V11: SSTI
    path('preview/', views.preview_email, name='preview'),
    path('custom/', views.custom_notification, name='custom'),
    path('editor/', views.template_editor, name='editor'),
    path('test/', views.send_test_email, name='test'),

    # Templates
    path('templates/', views.list_templates, name='templates'),

    # Webhook notifications
    path('webhook/', views.webhook_notification, name='webhook'),
]
