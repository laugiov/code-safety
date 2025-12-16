"""
Webhooks URL Configuration

Maps webhook endpoints to views.
Contains vulnerable endpoint V09 (SSRF).
"""

from django.urls import path
from . import views

app_name = 'webhooks'

urlpatterns = [
    # Configuration
    path('configure/', views.configure_webhook, name='configure'),

    # Test/Send webhooks - V09: SSRF
    path('test/', views.test_webhook, name='test'),
    path('send/', views.send_webhook, name='send'),
    path('validate/', views.validate_url, name='validate'),
    path('preview/', views.url_preview, name='preview'),

    # Image proxy - V09: SSRF
    path('image/', views.fetch_product_image, name='fetch_image'),

    # Receive webhooks
    path('receive/', views.receive_webhook, name='receive'),
]
