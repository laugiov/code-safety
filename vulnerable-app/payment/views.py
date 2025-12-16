"""
Payment Views

Handles checkout and payment processing.
Uses hardcoded API keys from settings (V12).
"""

import uuid
import pickle
import base64

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from .models import Order, OrderItem, PaymentMethod, Transaction
from catalog.models import Product


@login_required
def checkout(request):
    """
    Checkout page.

    Loads cart from cookie (vulnerable deserialization).
    """
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # V10: Still vulnerable here
        except Exception:
            cart_data = {}

    if not cart_data:
        messages.warning(request, 'Your cart is empty.')
        return redirect('catalog:product_list')

    # Build cart items for display
    items = []
    subtotal = 0

    for product_id, quantity in cart_data.items():
        try:
            product = Product.objects.get(id=product_id)
            item_total = float(product.current_price) * quantity
            items.append({
                'product': product,
                'quantity': quantity,
                'subtotal': item_total,
            })
            subtotal += item_total
        except Product.DoesNotExist:
            continue

    tax = subtotal * 0.08  # 8% tax
    shipping = 9.99 if subtotal < 50 else 0
    total = subtotal + tax + shipping

    # Get user's saved payment methods
    payment_methods = PaymentMethod.objects.filter(user=request.user)

    return render(request, 'payment/checkout.html', {
        'items': items,
        'subtotal': subtotal,
        'tax': tax,
        'shipping': shipping,
        'total': total,
        'payment_methods': payment_methods,
    })


@login_required
@csrf_exempt
def process_payment(request):
    """
    Process payment submission.

    VULNERABILITY: Uses hardcoded API keys (V12) from settings.
    In a real attack scenario, these keys could be exposed through
    error messages, logs, or code repositories.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    # Get cart data
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # V10
        except Exception:
            return JsonResponse({'error': 'Invalid cart'}, status=400)

    if not cart_data:
        return JsonResponse({'error': 'Cart is empty'}, status=400)

    # Calculate totals
    subtotal = 0
    for product_id, quantity in cart_data.items():
        try:
            product = Product.objects.get(id=product_id)
            subtotal += float(product.current_price) * quantity
        except Product.DoesNotExist:
            continue

    tax = subtotal * 0.08
    shipping = 9.99 if subtotal < 50 else 0
    total = subtotal + tax + shipping

    # Create order
    order = Order.objects.create(
        user=request.user,
        order_number=f"VS-{uuid.uuid4().hex[:8].upper()}",
        subtotal=subtotal,
        tax=tax,
        shipping=shipping,
        total=total,
        shipping_name=request.POST.get('shipping_name', ''),
        shipping_address=request.POST.get('shipping_address', ''),
        shipping_city=request.POST.get('shipping_city', ''),
        shipping_state=request.POST.get('shipping_state', ''),
        shipping_zip=request.POST.get('shipping_zip', ''),
        shipping_country=request.POST.get('shipping_country', 'US'),
        billing_name=request.POST.get('billing_name', ''),
        billing_address=request.POST.get('billing_address', ''),
        billing_city=request.POST.get('billing_city', ''),
        billing_state=request.POST.get('billing_state', ''),
        billing_zip=request.POST.get('billing_zip', ''),
        billing_country=request.POST.get('billing_country', 'US'),
    )

    # Create order items
    for product_id, quantity in cart_data.items():
        try:
            product = Product.objects.get(id=product_id)
            OrderItem.objects.create(
                order=order,
                product_name=product.name,
                product_sku=product.sku,
                quantity=quantity,
                price=product.current_price,
            )
        except Product.DoesNotExist:
            continue

    # Process payment (mock)
    # VULNERABILITY V12: Using hardcoded API key from settings
    stripe_key = settings.STRIPE_SECRET_KEY  # Hardcoded in settings.py

    # Simulate payment processing
    transaction = Transaction.objects.create(
        order=order,
        amount=total,
        status='captured',
        transaction_id=f"ch_{uuid.uuid4().hex}",
        gateway_response=f"Using API key: {stripe_key[:10]}...",  # Exposing key in logs
    )

    order.status = 'processing'
    order.save()

    # Clear cart
    response = JsonResponse({
        'success': True,
        'order_number': order.order_number,
        'redirect': f'/payment/confirmation/{order.order_number}/',
    })
    response.delete_cookie('cart')

    return response


@login_required
def order_confirmation(request, order_number):
    """Display order confirmation."""
    order = get_object_or_404(Order, order_number=order_number, user=request.user)

    return render(request, 'payment/confirmation.html', {
        'order': order,
    })


@login_required
def order_history(request):
    """Display user's order history."""
    orders = Order.objects.filter(user=request.user)

    return render(request, 'payment/order_history.html', {
        'orders': orders,
    })


@login_required
def order_detail(request, order_number):
    """Display order details."""
    order = get_object_or_404(Order, order_number=order_number, user=request.user)

    return render(request, 'payment/order_detail.html', {
        'order': order,
    })


@login_required
def manage_payment_methods(request):
    """Manage saved payment methods."""
    payment_methods = PaymentMethod.objects.filter(user=request.user)

    return render(request, 'payment/payment_methods.html', {
        'payment_methods': payment_methods,
    })


@login_required
@csrf_exempt
def add_payment_method(request):
    """
    Add a new payment method.

    VULNERABILITY: Stores credit card data in plain text (CWE-312).
    VULNERABILITY: Stores CVV which should never be persisted.
    """
    if request.method != 'POST':
        return render(request, 'payment/add_payment_method.html')

    # VULNERABLE: Storing sensitive card data in plain text
    PaymentMethod.objects.create(
        user=request.user,
        nickname=request.POST.get('nickname', ''),
        card_number=request.POST.get('card_number', ''),  # Plain text
        card_holder=request.POST.get('card_holder', ''),
        expiry_month=request.POST.get('expiry_month', ''),
        expiry_year=request.POST.get('expiry_year', ''),
        cvv=request.POST.get('cvv', ''),  # Should never store CVV!
    )

    messages.success(request, 'Payment method added.')
    return redirect('payment:payment_methods')


@login_required
def delete_payment_method(request, method_id):
    """Delete a payment method."""
    method = get_object_or_404(PaymentMethod, id=method_id, user=request.user)
    method.delete()
    messages.success(request, 'Payment method deleted.')
    return redirect('payment:payment_methods')
