"""
Cart URL Configuration

Maps cart endpoints to views.
Contains vulnerable endpoint V10 (Insecure Deserialization).
"""

from django.urls import path
from . import views

app_name = 'cart'

urlpatterns = [
    # View cart - V10: Insecure Deserialization
    path('', views.view_cart, name='view_cart'),

    # Cart operations
    path('add/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('update/<int:product_id>/', views.update_cart, name='update_cart'),
    path('remove/<int:product_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('clear/', views.clear_cart, name='clear_cart'),

    # Import/Export - V10: Insecure Deserialization
    path('import/', views.import_cart, name='import_cart'),
    path('export/', views.export_cart, name='export_cart'),

    # Save to database
    path('save/', views.save_cart_to_db, name='save_cart'),
]
