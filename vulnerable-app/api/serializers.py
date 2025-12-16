"""
API Serializers

Django REST Framework serializers for API endpoints.
"""

from rest_framework import serializers
from catalog.models import Product, Category
from authentication.models import User


class CategorySerializer(serializers.ModelSerializer):
    """Serializer for Category model."""

    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 'image']


class ProductSerializer(serializers.ModelSerializer):
    """Serializer for Product model."""

    category = CategorySerializer(read_only=True)
    category_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'slug', 'description', 'price', 'sale_price',
            'category', 'category_id', 'image_url', 'stock', 'sku',
            'is_active', 'is_featured', 'created_at'
        ]
        read_only_fields = ['id', 'slug', 'created_at']


class ProductListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for product lists."""

    class Meta:
        model = Product
        fields = ['id', 'name', 'slug', 'price', 'sale_price', 'image_url', 'stock']


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model (public info only)."""

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'date_joined']
        read_only_fields = fields


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user's own profile (private info)."""

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone', 'address', 'date_of_birth', 'profile_picture',
            'is_verified', 'date_joined'
        ]
        read_only_fields = ['id', 'username', 'date_joined', 'is_verified']
