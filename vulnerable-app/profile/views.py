"""
Profile Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V07: IDOR (Insecure Direct Object Reference)
- V08: Mass Assignment
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

from authentication.models import User
from payment.models import Order, PaymentMethod
from .models import UserPreferences, Address


def view_profile(request):
    """
    View user profile.

    ==========================================================================
    VULNERABILITY V07: IDOR (Insecure Direct Object Reference)
    ==========================================================================
    CWE-639: Authorization Bypass Through User-Controlled Key

    Taint Flow:
        Source: request.GET['user_id']
        Sink: User.objects.get(id=user_id) without authorization check

    Attack Vector:
        /profile/?user_id=1  (access admin's profile)
        /profile/?user_id=2  (access another user's profile)

    The vulnerability allows any authenticated user to view any other user's
    profile, including sensitive data like orders and payment methods.

    Expected Detection:
        - Pysa: UserControlled -> DatabaseQuery (missing authorization)
        - CodeQL: py/idor
        - Semgrep: python.django.security.idor

    ==========================================================================
    """
    # =================================================================
    # VULNERABLE CODE - IDOR (V07)
    # =================================================================
    # SINK: Using user-controlled ID without authorization check

    user_id = request.GET.get('user_id')

    if user_id:
        # VULNERABLE: Any user can view any profile by changing the ID
        try:
            profile_user = User.objects.get(id=user_id)  # SINK
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('home')
    else:
        # Default to current user if no ID provided
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        profile_user = request.user

    # Fetch sensitive data - exposed through IDOR
    orders = Order.objects.filter(user=profile_user)
    payment_methods = PaymentMethod.objects.filter(user=profile_user)

    try:
        preferences = profile_user.preferences
    except UserPreferences.DoesNotExist:
        preferences = None

    addresses = Address.objects.filter(user=profile_user)

    return render(request, 'profile/view.html', {
        'profile_user': profile_user,
        'orders': orders,
        'payment_methods': payment_methods,  # Sensitive data exposed!
        'preferences': preferences,
        'addresses': addresses,
    })


@login_required
@csrf_exempt
def update_profile(request):
    """
    Update user profile.

    ==========================================================================
    VULNERABILITY V08: Mass Assignment
    ==========================================================================
    CWE-915: Improperly Controlled Modification of Dynamically-Determined
             Object Attributes

    Taint Flow:
        Source: request.POST (all fields)
        Propagation: Iteration over POST data
        Sink: setattr(user, key, value)

    Attack Vector:
        POST /profile/update/
        Content-Type: application/x-www-form-urlencoded

        first_name=John&is_staff=true&is_superuser=true

    By including is_staff=true and is_superuser=true, a regular user
    can escalate their privileges to become an admin.

    Expected Detection:
        - Pysa: UserControlled -> ObjectAttributeWrite
        - CodeQL: py/mass-assignment
        - Semgrep: python.django.security.mass-assignment

    ==========================================================================
    """
    if request.method != 'POST':
        return render(request, 'profile/edit.html', {'user': request.user})

    user = request.user

    # =================================================================
    # VULNERABLE CODE - Mass Assignment (V08)
    # =================================================================
    # SINK: Blindly setting all attributes from user input

    for key, value in request.POST.items():
        if key == 'csrfmiddlewaretoken':
            continue

        # VULNERABLE: Setting any attribute the user provides
        if hasattr(user, key):
            # Convert string 'true'/'false' to boolean for boolean fields
            if value.lower() in ('true', 'false'):
                value = value.lower() == 'true'

            setattr(user, key, value)  # SINK - Mass Assignment

    user.save()

    messages.success(request, 'Profile updated successfully.')
    return redirect('profile:view_profile')


@login_required
@csrf_exempt
def update_profile_api(request):
    """
    API endpoint for profile updates.

    VULNERABILITY V08 (variant): Mass Assignment via JSON
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import json

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    user = request.user

    # VULNERABLE: Mass assignment from JSON body
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)  # SINK

    user.save()

    return JsonResponse({
        'success': True,
        'message': 'Profile updated',
        'user': {
            'id': user.id,
            'username': user.username,
            'is_staff': user.is_staff,  # Reveals privilege escalation
            'is_superuser': user.is_superuser,
        }
    })


@csrf_exempt
def user_lookup(request):
    """
    Look up user by various criteria.

    VULNERABILITY V07 (variant): IDOR via email/username lookup
    """
    email = request.GET.get('email')
    username = request.GET.get('username')

    user = None

    # VULNERABLE: No authorization check
    if email:
        try:
            user = User.objects.get(email=email)  # SINK
        except User.DoesNotExist:
            pass
    elif username:
        try:
            user = User.objects.get(username=username)  # SINK
        except User.DoesNotExist:
            pass

    if not user:
        return JsonResponse({'error': 'User not found'}, status=404)

    # VULNERABLE: Exposing sensitive user data
    return JsonResponse({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone': user.phone,
        'address': user.address,
        'date_joined': user.date_joined.isoformat(),
    })


@login_required
def manage_addresses(request):
    """Manage saved addresses."""
    addresses = Address.objects.filter(user=request.user)
    return render(request, 'profile/addresses.html', {'addresses': addresses})


@login_required
@csrf_exempt
def add_address(request):
    """Add a new address."""
    if request.method != 'POST':
        return render(request, 'profile/add_address.html')

    Address.objects.create(
        user=request.user,
        label=request.POST.get('label', 'Home'),
        address_type=request.POST.get('address_type', 'both'),
        name=request.POST.get('name', ''),
        street_address=request.POST.get('street_address', ''),
        city=request.POST.get('city', ''),
        state=request.POST.get('state', ''),
        zip_code=request.POST.get('zip_code', ''),
        country=request.POST.get('country', 'US'),
        phone=request.POST.get('phone', ''),
    )

    messages.success(request, 'Address added.')
    return redirect('profile:addresses')


@login_required
def delete_address(request, address_id):
    """Delete an address."""
    address = get_object_or_404(Address, id=address_id, user=request.user)
    address.delete()
    messages.success(request, 'Address deleted.')
    return redirect('profile:addresses')


@login_required
@csrf_exempt
def update_preferences(request):
    """Update user preferences."""
    if request.method != 'POST':
        try:
            preferences = request.user.preferences
        except UserPreferences.DoesNotExist:
            preferences = UserPreferences.objects.create(user=request.user)

        return render(request, 'profile/preferences.html', {'preferences': preferences})

    preferences, created = UserPreferences.objects.get_or_create(user=request.user)

    # Safe update - only specific fields
    preferences.newsletter = request.POST.get('newsletter', 'off') == 'on'
    preferences.marketing_emails = request.POST.get('marketing_emails', 'off') == 'on'
    preferences.order_notifications = request.POST.get('order_notifications', 'off') == 'on'
    preferences.dark_mode = request.POST.get('dark_mode', 'off') == 'on'
    preferences.language = request.POST.get('language', 'en')
    preferences.timezone = request.POST.get('timezone', 'UTC')
    preferences.save()

    messages.success(request, 'Preferences updated.')
    return redirect('profile:view_profile')
