"""
API URL Configuration

Maps API endpoints to views.
Contains vulnerable endpoint V15 (XXE).
"""

from django.urls import path
from . import views

app_name = 'api'

urlpatterns = [
    # Info
    path('', views.api_info, name='info'),

    # Products (safe)
    path('products/', views.list_products, name='products'),
    path('products/<int:product_id>/', views.get_product, name='product'),

    # Categories (safe)
    path('categories/', views.list_categories, name='categories'),

    # User (safe)
    path('user/', views.current_user, name='current_user'),

    # Import - V15: XXE
    path('import/products/', views.import_products, name='import_products'),
    path('import/users/', views.import_users, name='import_users'),
    path('import/config/', views.parse_config, name='parse_config'),

    # Webhook - V15: XXE
    path('webhook/', views.webhook_handler, name='webhook'),
]
