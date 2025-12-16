"""
Authentication Views

Contains intentionally vulnerable authentication endpoints for
taint analysis demonstration.

Vulnerabilities:
- V01: SQL Injection in login_view()
- V16: No rate limiting on login attempts
"""

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.db import connection
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .models import User, LoginAttempt


def login_view(request):
    """
    User login endpoint.

    ==========================================================================
    VULNERABILITY V01: SQL Injection
    ==========================================================================
    CWE-89: Improper Neutralization of Special Elements used in SQL Command

    Taint Flow:
        Source: request.POST['username']
        Propagation: f-string formatting into SQL query
        Sink: cursor.execute()

    Attack Vector:
        username: admin'--
        password: anything

    Expected Detection:
        - Pysa: UserControlled -> SqlExecution
        - CodeQL: py/sql-injection
        - Semgrep: python.django.security.sql-injection

    ==========================================================================
    VULNERABILITY V16: No Rate Limiting
    ==========================================================================
    CWE-307: Improper Restriction of Excessive Authentication Attempts

    Issue: No limit on login attempts allows brute force attacks.
    The LoginAttempt model exists but is never checked.
    ==========================================================================
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        # Record login attempt (but don't check for rate limiting - V16)
        LoginAttempt.objects.create(
            username=username,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            successful=False  # Will update if successful
        )

        # =================================================================
        # VULNERABLE CODE - SQL Injection (V01)
        # =================================================================
        # SINK: User input directly interpolated into SQL query
        # This allows authentication bypass and data extraction

        query = f"SELECT id, username, password FROM authentication_user WHERE username = '{username}'"

        with connection.cursor() as cursor:
            cursor.execute(query)  # SINK: SQL execution with unsanitized input
            result = cursor.fetchone()

        if result:
            # Attempt to get user and verify password
            # Note: This simplified check is also vulnerable
            try:
                user = User.objects.get(username=username)
                # In real SQL injection, password check is bypassed with '--
                if user.check_password(password) or "'" in username:
                    login(request, user)
                    # Update login attempt as successful
                    LoginAttempt.objects.filter(
                        username=username
                    ).order_by('-timestamp').first().successful = True

                    messages.success(request, f'Welcome back, {user.username}!')
                    return redirect('home')
            except User.DoesNotExist:
                pass

        # V16: No account lockout after failed attempts
        messages.error(request, 'Invalid username or password.')

    return render(request, 'authentication/login.html')


@csrf_exempt
def login_api(request):
    """
    Alternative login endpoint demonstrating another SQL injection pattern.

    VULNERABILITY V01 (variant): SQL Injection via string concatenation

    Taint Flow:
        Source: request.POST['email']
        Propagation: string concatenation
        Sink: raw()
    """
    if request.method == 'POST':
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')

        # VULNERABLE: String concatenation in raw query
        query = "SELECT * FROM authentication_user WHERE email = '" + email + "'"
        users = User.objects.raw(query)  # SINK

        user_list = list(users)
        if user_list:
            user = user_list[0]
            if user.check_password(password):
                login(request, user)
                return HttpResponse('Login successful', status=200)

        return HttpResponse('Invalid credentials', status=401)

    return HttpResponse('POST required', status=405)


def register_view(request):
    """
    User registration endpoint.

    This endpoint is relatively safe but stores sensitive data
    in plain text (credit_card field - see models.py).
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')

        # Basic validation
        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'authentication/register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'authentication/register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'authentication/register.html')

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        login(request, user)
        messages.success(request, 'Registration successful!')
        return redirect('home')

    return render(request, 'authentication/register.html')


def logout_view(request):
    """Log out the current user."""
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('home')


def password_reset_view(request):
    """
    Password reset request.

    VULNERABILITY: User enumeration possible through different error messages.
    """
    if request.method == 'POST':
        email = request.POST.get('email', '')

        try:
            user = User.objects.get(email=email)
            # In a real app, would send reset email here
            # VULNERABLE: Different response reveals if email exists
            messages.success(request, 'Password reset email sent.')
        except User.DoesNotExist:
            # VULNERABLE: This reveals that the email doesn't exist
            messages.error(request, 'No account found with that email.')

        return redirect('login')

    return render(request, 'authentication/password_reset.html')


@login_required
def change_password_view(request):
    """Change password for authenticated user."""
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '')
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'authentication/change_password.html')

        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return render(request, 'authentication/change_password.html')

        request.user.set_password(new_password)
        request.user.save()
        messages.success(request, 'Password changed successfully.')
        return redirect('login')

    return render(request, 'authentication/change_password.html')


def get_client_ip(request):
    """Extract client IP from request, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip
