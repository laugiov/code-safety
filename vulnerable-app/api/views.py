"""
API Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V15: XXE (XML External Entity)
"""

from lxml import etree

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from catalog.models import Product, Category
from authentication.models import User


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def import_products(request):
    """
    Import products from XML.

    ==========================================================================
    VULNERABILITY V15: XML External Entity (XXE)
    ==========================================================================
    CWE-611: Improper Restriction of XML External Entity Reference

    Taint Flow:
        Source: request.body (XML data)
        Sink: etree.fromstring() with default parser

    Attack Vectors:
        1. File disclosure:
           <?xml version="1.0"?>
           <!DOCTYPE products [
             <!ENTITY xxe SYSTEM "file:///etc/passwd">
           ]>
           <products><product><name>&xxe;</name></product></products>

        2. SSRF via XXE:
           <?xml version="1.0"?>
           <!DOCTYPE products [
             <!ENTITY xxe SYSTEM "http://internal-service:8080/secret">
           ]>
           <products><product><name>&xxe;</name></product></products>

        3. Denial of Service (Billion Laughs):
           <?xml version="1.0"?>
           <!DOCTYPE lolz [
             <!ENTITY lol "lol">
             <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
             <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
           ]>
           <products><product><name>&lol3;</name></product></products>

    Expected Detection:
        - Pysa: UserControlled -> XmlParsing
        - CodeQL: py/xxe
        - Semgrep: python.lang.security.xxe.lxml-unsafe-parser

    ==========================================================================
    """
    if not request.body:
        return JsonResponse({'error': 'XML body required'}, status=400)

    xml_data = request.body

    # =================================================================
    # VULNERABLE CODE - XXE (V15)
    # =================================================================
    # SINK: Parsing XML with default parser (allows external entities)

    try:
        # VULNERABLE: Default XMLParser allows external entities and DTD
        parser = etree.XMLParser()  # No security flags set
        root = etree.fromstring(xml_data, parser)  # SINK - XXE

        products = []
        for product_elem in root.findall('.//product'):
            name_elem = product_elem.find('name')
            price_elem = product_elem.find('price')
            description_elem = product_elem.find('description')
            sku_elem = product_elem.find('sku')

            product_data = {
                'name': name_elem.text if name_elem is not None else '',
                'price': float(price_elem.text) if price_elem is not None else 0,
                'description': description_elem.text if description_elem is not None else '',
                'sku': sku_elem.text if sku_elem is not None else '',
            }
            products.append(product_data)

        return JsonResponse({
            'imported': len(products),
            'products': products
        })

    except etree.XMLSyntaxError as e:
        return JsonResponse({'error': f'XML syntax error: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def import_users(request):
    """
    Import users from XML.

    VULNERABILITY V15 (variant): XXE with different entity resolution
    """
    if not request.body:
        return JsonResponse({'error': 'XML body required'}, status=400)

    xml_data = request.body

    try:
        # VULNERABLE: resolve_entities=True (default) allows XXE
        parser = etree.XMLParser(
            resolve_entities=True,  # VULNERABLE
            load_dtd=True,  # VULNERABLE
            no_network=False  # VULNERABLE
        )
        root = etree.fromstring(xml_data, parser)  # SINK

        users = []
        for user_elem in root.findall('.//user'):
            username = user_elem.find('username')
            email = user_elem.find('email')

            users.append({
                'username': username.text if username is not None else '',
                'email': email.text if email is not None else '',
            })

        return JsonResponse({
            'parsed': len(users),
            'users': users
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def parse_config(request):
    """
    Parse configuration XML.

    VULNERABILITY V15 (variant): XXE in configuration parsing
    """
    xml_data = request.body

    if not xml_data:
        return JsonResponse({'error': 'XML body required'}, status=400)

    try:
        # VULNERABLE: Parsing untrusted XML
        root = etree.fromstring(xml_data)  # SINK - uses default parser

        config = {}
        for setting in root.findall('.//setting'):
            key = setting.get('key')
            value = setting.text
            if key:
                config[key] = value

        return JsonResponse({
            'config': config
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def list_products(request):
    """List all products (safe endpoint)."""
    products = Product.objects.filter(is_active=True).values(
        'id', 'name', 'slug', 'price', 'image_url', 'stock'
    )
    return Response({'products': list(products)})


@api_view(['GET'])
@permission_classes([AllowAny])
def get_product(request, product_id):
    """Get product details (safe endpoint)."""
    try:
        product = Product.objects.get(id=product_id)
        return Response({
            'id': product.id,
            'name': product.name,
            'slug': product.slug,
            'description': product.description,
            'price': str(product.price),
            'sale_price': str(product.sale_price) if product.sale_price else None,
            'image_url': product.image_url,
            'stock': product.stock,
            'category': product.category.name if product.category else None,
        })
    except Product.DoesNotExist:
        return Response({'error': 'Product not found'}, status=404)


@api_view(['GET'])
@permission_classes([AllowAny])
def list_categories(request):
    """List all categories (safe endpoint)."""
    categories = Category.objects.values('id', 'name', 'slug')
    return Response({'categories': list(categories)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Get current user info (safe endpoint)."""
    user = request.user
    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
    })


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def webhook_handler(request):
    """
    Handle incoming webhooks (may contain XML).

    VULNERABILITY V15 (variant): XXE in webhook handler
    """
    content_type = request.content_type

    if 'xml' in content_type:
        try:
            # VULNERABLE: Parsing XML webhook payload
            root = etree.fromstring(request.body)  # SINK

            # Extract event data
            event_type = root.find('event_type')
            payload = root.find('payload')

            return JsonResponse({
                'received': True,
                'event_type': event_type.text if event_type is not None else 'unknown',
                'payload': etree.tostring(payload, encoding='unicode') if payload is not None else '',
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    elif 'json' in content_type:
        import json
        try:
            data = json.loads(request.body)
            return JsonResponse({
                'received': True,
                'data': data
            })
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    else:
        return JsonResponse({'error': 'Unsupported content type'}, status=415)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_info(request):
    """API information endpoint."""
    return Response({
        'name': 'VulnShop API',
        'version': '1.0.0',
        'description': 'Intentionally vulnerable API for security testing',
        'endpoints': {
            'products': '/api/products/',
            'categories': '/api/categories/',
            'import_products': '/api/import/products/',
            'import_users': '/api/import/users/',
        }
    })
