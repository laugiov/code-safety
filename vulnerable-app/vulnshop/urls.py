"""
VulnShop URL Configuration

This module defines all URL routes for the VulnShop application.
Each app module contains its own set of vulnerable endpoints.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse


def health_check(request):
    """Health check endpoint for Docker/Kubernetes."""
    return JsonResponse({'status': 'healthy', 'app': 'vulnshop'})


def home(request):
    """Home page redirect."""
    from django.shortcuts import render
    return render(request, 'home.html')


urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # Health check
    path('health/', health_check, name='health'),

    # Home
    path('', home, name='home'),

    # Authentication (V01: SQL Injection, V16: Brute Force)
    path('auth/', include('authentication.urls')),

    # Catalog (V02: SQL Injection, V03: Reflected XSS)
    path('catalog/', include('catalog.urls')),

    # Reviews (V04: Stored XSS)
    path('reviews/', include('reviews.urls')),

    # Cart (V10: Insecure Deserialization)
    path('cart/', include('cart.urls')),

    # Payment
    path('payment/', include('payment.urls')),

    # Profile (V07: IDOR, V08: Mass Assignment)
    path('profile/', include('profile.urls')),

    # Admin Panel (V05: Command Injection, V06: Path Traversal)
    path('admin-panel/', include('admin_panel.urls')),

    # Webhooks (V09: SSRF)
    path('webhooks/', include('webhooks.urls')),

    # Notifications (V11: SSTI)
    path('notifications/', include('notifications.urls')),

    # API (V15: XXE)
    path('api/', include('api.urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
