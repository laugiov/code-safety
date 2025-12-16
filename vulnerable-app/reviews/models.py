"""
Reviews Models

Product review model for user feedback.
"""

from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from catalog.models import Product


class Review(models.Model):
    """
    Product review model.

    VULNERABILITY V04: Stored XSS vector
    The comment field stores user input without sanitization.
    When rendered with mark_safe() or |safe filter, XSS payload executes.
    """

    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating from 1 to 5 stars"
    )
    title = models.CharField(
        max_length=200,
        blank=True,
        help_text="Review title (optional)"
    )
    # VULNERABLE: This field stores unsanitized HTML/script content
    comment = models.TextField(
        help_text="Review comment (VULNERABLE: allows HTML/scripts)"
    )
    is_verified_purchase = models.BooleanField(
        default=False,
        help_text="Whether reviewer purchased this product"
    )
    is_approved = models.BooleanField(
        default=True,  # Auto-approve for demo (also a vulnerability)
        help_text="Whether review is approved for display"
    )
    helpful_votes = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Review'
        verbose_name_plural = 'Reviews'
        ordering = ['-created_at']
        # Prevent duplicate reviews
        unique_together = ['product', 'user']

    def __str__(self):
        return f"{self.user.username}'s review of {self.product.name}"

    @property
    def stars(self):
        """Return rating as star characters."""
        return '★' * self.rating + '☆' * (5 - self.rating)


class ReviewVote(models.Model):
    """Track helpful votes on reviews."""

    review = models.ForeignKey(
        Review,
        on_delete=models.CASCADE,
        related_name='votes'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    is_helpful = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['review', 'user']

    def __str__(self):
        vote_type = 'helpful' if self.is_helpful else 'not helpful'
        return f"{self.user.username} voted {vote_type}"
