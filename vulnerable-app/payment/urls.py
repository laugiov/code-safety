"""
Payment URL Configuration
"""

from django.urls import path
from . import views

app_name = 'payment'

urlpatterns = [
    # Checkout
    path('checkout/', views.checkout, name='checkout'),
    path('process/', views.process_payment, name='process_payment'),
    path('confirmation/<str:order_number>/', views.order_confirmation, name='confirmation'),

    # Orders
    path('orders/', views.order_history, name='order_history'),
    path('orders/<str:order_number>/', views.order_detail, name='order_detail'),

    # Payment methods
    path('methods/', views.manage_payment_methods, name='payment_methods'),
    path('methods/add/', views.add_payment_method, name='add_payment_method'),
    path('methods/delete/<int:method_id>/', views.delete_payment_method, name='delete_payment_method'),
]
