"""
Reviews URL Configuration

Maps review endpoints to views.
Contains vulnerable endpoint V04 (Stored XSS).
"""

from django.urls import path
from . import views

app_name = 'reviews'

urlpatterns = [
    # Add/Edit/Delete reviews - V04: Stored XSS
    path('add/<int:product_id>/', views.add_review, name='add_review'),
    path('edit/<int:review_id>/', views.edit_review, name='edit_review'),
    path('delete/<int:review_id>/', views.delete_review, name='delete_review'),

    # View reviews
    path('product/<int:product_id>/', views.product_reviews, name='product_reviews'),
    path('latest/', views.latest_reviews, name='latest_reviews'),

    # Vote on reviews
    path('vote/<int:review_id>/', views.vote_review, name='vote_review'),

    # API
    path('api/<int:product_id>/', views.review_api, name='review_api'),
]
