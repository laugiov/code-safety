"""
Catalog Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V02: SQL Injection in search_products()
- V03: Reflected XSS in search results
"""

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import Product, Category


def product_list(request):
    """List all active products."""
    products = Product.objects.filter(is_active=True)
    categories = Category.objects.all()

    return render(request, 'catalog/product_list.html', {
        'products': products,
        'categories': categories,
    })


def product_detail(request, slug):
    """Display product details."""
    product = get_object_or_404(Product, slug=slug, is_active=True)

    # Get related products from same category
    related_products = []
    if product.category:
        related_products = Product.objects.filter(
            category=product.category,
            is_active=True
        ).exclude(id=product.id)[:4]

    return render(request, 'catalog/product_detail.html', {
        'product': product,
        'related_products': related_products,
    })


def category_detail(request, slug):
    """Display products in a specific category."""
    category = get_object_or_404(Category, slug=slug)
    products = Product.objects.filter(category=category, is_active=True)

    return render(request, 'catalog/category_detail.html', {
        'category': category,
        'products': products,
    })


def search_products(request):
    """
    Search products endpoint.

    ==========================================================================
    VULNERABILITY V02: SQL Injection
    ==========================================================================
    CWE-89: Improper Neutralization of Special Elements used in SQL Command

    Taint Flow:
        Source: request.GET['q']
        Propagation: string concatenation
        Sink: Product.objects.raw()

    Attack Vector:
        q=%' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11,12,13 FROM authentication_user--

    Expected Detection:
        - Pysa: UserControlled -> SqlExecution
        - CodeQL: py/sql-injection
        - Semgrep: python.django.security.sql-injection

    ==========================================================================
    VULNERABILITY V03: Reflected XSS
    ==========================================================================
    CWE-79: Improper Neutralization of Input During Web Page Generation

    Taint Flow:
        Source: request.GET['q']
        Propagation: context variable passed to template
        Sink: Template rendering with |safe filter

    Attack Vector:
        q=<script>alert('XSS')</script>

    Expected Detection:
        - Pysa: UserControlled -> HtmlOutput
        - CodeQL: py/reflected-xss
        - Semgrep: python.django.security.xss

    ==========================================================================
    """
    query = request.GET.get('q', '')
    sort = request.GET.get('sort', 'name')
    category_id = request.GET.get('category', '')

    products = []

    if query:
        # =================================================================
        # VULNERABLE CODE - SQL Injection (V02)
        # =================================================================
        # SINK: User input directly concatenated into SQL query

        sql = "SELECT * FROM catalog_product WHERE name LIKE '%" + query + "%' OR description LIKE '%" + query + "%'"

        if category_id:
            sql += f" AND category_id = {category_id}"  # Also vulnerable

        sql += f" ORDER BY {sort}"  # ORDER BY injection also possible

        products = Product.objects.raw(sql)  # SINK

    # =================================================================
    # VULNERABLE CODE - Reflected XSS (V03)
    # =================================================================
    # The query is passed directly to template where it's rendered
    # with the |safe filter, allowing script injection

    return render(request, 'catalog/search_results.html', {
        'query': query,  # Will be rendered with |safe in template
        'products': products,
        'sort': sort,
        'category_id': category_id,
        'categories': Category.objects.all(),
    })


@csrf_exempt
def search_api(request):
    """
    API search endpoint.

    VULNERABILITY V02 (variant): SQL Injection via JSON input

    Taint Flow:
        Source: request.POST['search_term']
        Propagation: string formatting
        Sink: raw()
    """
    import json

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            search_term = data.get('search_term', '')
            min_price = data.get('min_price', 0)
            max_price = data.get('max_price', 999999)

            # VULNERABLE: SQL injection via multiple parameters
            sql = f"""
                SELECT * FROM catalog_product
                WHERE (name LIKE '%{search_term}%' OR description LIKE '%{search_term}%')
                AND price >= {min_price}
                AND price <= {max_price}
                AND is_active = 1
            """

            products = Product.objects.raw(sql)  # SINK

            result = [{
                'id': p.id,
                'name': p.name,
                'price': str(p.price),
                'image_url': p.image_url,
            } for p in products]

            return JsonResponse({'products': result})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return JsonResponse({'error': 'POST required'}, status=405)


def featured_products(request):
    """Display featured products."""
    products = Product.objects.filter(is_featured=True, is_active=True)

    return render(request, 'catalog/featured.html', {
        'products': products,
    })


def product_filter(request):
    """
    Filter products by various criteria.

    Demonstrates a safer pattern (using Django ORM properly)
    but still includes one vulnerable path for demonstration.
    """
    min_price = request.GET.get('min_price')
    max_price = request.GET.get('max_price')
    category = request.GET.get('category')
    in_stock = request.GET.get('in_stock')
    order_by = request.GET.get('order_by', 'name')

    products = Product.objects.filter(is_active=True)

    if min_price:
        products = products.filter(price__gte=min_price)
    if max_price:
        products = products.filter(price__lte=max_price)
    if category:
        products = products.filter(category__slug=category)
    if in_stock:
        products = products.filter(stock__gt=0)

    # VULNERABLE: ORDER BY clause injection
    # While the filtering is safe, the ordering allows injection
    valid_orders = ['name', '-name', 'price', '-price', 'created_at', '-created_at']
    if order_by not in valid_orders:
        # Vulnerable fallback using raw SQL for order
        sql = f"SELECT * FROM catalog_product WHERE is_active = 1 ORDER BY {order_by}"
        products = Product.objects.raw(sql)  # SINK

    return render(request, 'catalog/product_list.html', {
        'products': products,
        'categories': Category.objects.all(),
    })
