"""
Catalog URL Configuration

Maps catalog endpoints to views.
Contains vulnerable endpoints V02 (SQL Injection) and V03 (Reflected XSS).
"""

from django.urls import path
from . import views

app_name = 'catalog'

urlpatterns = [
    # Product listing
    path('', views.product_list, name='product_list'),
    path('featured/', views.featured_products, name='featured'),
    path('filter/', views.product_filter, name='product_filter'),

    # Search - V02: SQL Injection, V03: Reflected XSS
    path('search/', views.search_products, name='search'),
    path('search/api/', views.search_api, name='search_api'),

    # Category
    path('category/<slug:slug>/', views.category_detail, name='category_detail'),

    # Product detail
    path('product/<slug:slug>/', views.product_detail, name='product_detail'),
]
