"""
Payment Admin Configuration
"""

from django.contrib import admin
from .models import Order, OrderItem, PaymentMethod, Transaction


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0


class TransactionInline(admin.TabularInline):
    model = Transaction
    extra = 0
    readonly_fields = ('transaction_id', 'gateway_response', 'created_at')


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_number', 'user', 'status', 'total', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('order_number', 'user__username', 'user__email')
    inlines = [OrderItemInline, TransactionInline]
    readonly_fields = ('created_at', 'updated_at')


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'masked_number', 'expiry', 'is_default')
    list_filter = ('is_default',)
    search_fields = ('user__username', 'card_holder')


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('order', 'amount', 'status', 'transaction_id', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('transaction_id', 'order__order_number')
