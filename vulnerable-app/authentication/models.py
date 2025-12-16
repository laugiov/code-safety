"""
Authentication Models

Contains the custom User model with intentional security issues
for taint analysis demonstration.

Vulnerabilities:
- Storing sensitive data (credit card) in plain text
- No encryption for PII
"""

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.

    VULNERABILITY: Sensitive data stored in plain text
    CWE-312: Cleartext Storage of Sensitive Information

    Taint Analysis Note:
    - credit_card field stores unencrypted payment data
    - ssn field stores unencrypted government ID
    """

    # Standard profile fields
    phone = models.CharField(
        max_length=20,
        blank=True,
        help_text="User phone number"
    )
    address = models.TextField(
        blank=True,
        help_text="User mailing address"
    )

    # VULNERABLE: Storing credit card in plain text
    # CWE-312: Cleartext Storage of Sensitive Information
    credit_card = models.CharField(
        max_length=19,
        blank=True,
        help_text="Credit card number (VULNERABLE: stored in plain text)"
    )

    # VULNERABLE: Storing SSN in plain text
    ssn = models.CharField(
        max_length=11,
        blank=True,
        help_text="Social Security Number (VULNERABLE: stored in plain text)"
    )

    # Additional profile fields
    date_of_birth = models.DateField(
        null=True,
        blank=True
    )
    profile_picture = models.URLField(
        blank=True,
        help_text="URL to profile picture"
    )

    # Account status
    is_verified = models.BooleanField(
        default=False,
        help_text="Email verification status"
    )
    failed_login_attempts = models.IntegerField(
        default=0,
        help_text="Number of consecutive failed login attempts"
    )
    # Note: failed_login_attempts is tracked but NOT used for lockout (V16)

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.username

    def get_masked_card(self):
        """Return masked credit card number for display."""
        if self.credit_card and len(self.credit_card) >= 4:
            return '*' * 12 + self.credit_card[-4:]
        return None


class LoginAttempt(models.Model):
    """
    Track login attempts for auditing.

    Note: This model exists but is NOT used for rate limiting (V16).
    A proper implementation would check this before allowing login.
    """

    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        ordering = ['-timestamp']

    def __str__(self):
        status = 'Success' if self.successful else 'Failed'
        return f"{self.username} - {status} - {self.timestamp}"
