"""
Webhooks Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V09: SSRF (Server-Side Request Forgery)
"""

import requests
from urllib.parse import urlparse

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt


@login_required
@csrf_exempt
def test_webhook(request):
    """
    Test webhook endpoint.

    ==========================================================================
    VULNERABILITY V09: Server-Side Request Forgery (SSRF)
    ==========================================================================
    CWE-918: Server-Side Request Forgery (SSRF)

    Taint Flow:
        Source: request.POST['url']
        Sink: requests.get()

    Attack Vectors:
        1. Access internal services:
           url=http://localhost:6379/  (Redis)
           url=http://localhost:5432/  (PostgreSQL)
           url=http://127.0.0.1:8000/admin/  (Django admin)

        2. Cloud metadata (AWS, GCP, Azure):
           url=http://169.254.169.254/latest/meta-data/
           url=http://metadata.google.internal/computeMetadata/v1/
           url=http://169.254.169.254/metadata/instance

        3. Internal network scanning:
           url=http://10.0.0.1:22/  (SSH)
           url=http://192.168.1.1/  (Router)

        4. File access (on some systems):
           url=file:///etc/passwd

    SSRF can lead to:
    - Access to internal services
    - Cloud credential theft
    - Internal network reconnaissance
    - Data exfiltration

    Expected Detection:
        - Pysa: UserControlled -> HttpRequest
        - CodeQL: py/ssrf
        - Semgrep: python.requests.security.ssrf

    ==========================================================================
    """
    if request.method != 'POST':
        return render(request, 'webhooks/test.html')

    webhook_url = request.POST.get('url', '')

    if not webhook_url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    # =================================================================
    # VULNERABLE CODE - SSRF (V09)
    # =================================================================
    # SINK: Making request to user-controlled URL

    try:
        # VULNERABLE: No URL validation or allowlist
        response = requests.get(
            webhook_url,  # SINK - SSRF
            timeout=10,
            allow_redirects=True,
            verify=False  # Also insecure: SSL verification disabled
        )

        return JsonResponse({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text[:5000],  # First 5000 chars
            'url': response.url,
        })

    except requests.RequestException as e:
        return JsonResponse({
            'error': str(e),
        }, status=500)


@login_required
@csrf_exempt
def send_webhook(request):
    """
    Send webhook notification to external service.

    VULNERABILITY V09 (variant): SSRF via POST request
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import json

    webhook_url = request.POST.get('url', '')
    payload = request.POST.get('payload', '{}')

    if not webhook_url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {'message': payload}

    try:
        # VULNERABLE: SSRF via POST
        response = requests.post(
            webhook_url,  # SINK
            json=data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )

        return JsonResponse({
            'success': True,
            'status_code': response.status_code,
            'response': response.text[:1000],
        })

    except requests.RequestException as e:
        return JsonResponse({'error': str(e)}, status=500)


def fetch_product_image(request):
    """
    Fetch product image from external URL.

    VULNERABILITY V09 (variant): SSRF via image proxy
    """
    image_url = request.GET.get('url', '')

    if not image_url:
        return HttpResponse('URL parameter required', status=400)

    # =================================================================
    # VULNERABLE CODE - SSRF (V09)
    # =================================================================
    # SINK: Fetching arbitrary URL as image proxy

    try:
        response = requests.get(
            image_url,  # SINK
            timeout=10,
            stream=True
        )

        # Return the content with appropriate content type
        content_type = response.headers.get('Content-Type', 'image/jpeg')
        return HttpResponse(
            response.content,
            content_type=content_type
        )

    except requests.RequestException as e:
        return HttpResponse(f'Error fetching image: {e}', status=500)


@login_required
@csrf_exempt
def validate_url(request):
    """
    Validate if URL is accessible.

    VULNERABILITY V09 (variant): SSRF via URL validation
    """
    url = request.POST.get('url', '') or request.GET.get('url', '')

    if not url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    try:
        # VULNERABLE: HEAD request still allows SSRF
        response = requests.head(
            url,  # SINK
            timeout=5,
            allow_redirects=True
        )

        return JsonResponse({
            'valid': True,
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type'),
            'content_length': response.headers.get('Content-Length'),
        })

    except requests.RequestException as e:
        return JsonResponse({
            'valid': False,
            'error': str(e)
        })


@login_required
def configure_webhook(request):
    """Webhook configuration page."""
    return render(request, 'webhooks/configure.html')


@csrf_exempt
def receive_webhook(request):
    """
    Receive incoming webhooks.

    This endpoint is intentionally open to receive external webhooks.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    # Log the incoming webhook (vulnerable to log injection if not careful)
    import logging
    logger = logging.getLogger(__name__)

    # VULNERABLE: Logging user-controlled data without sanitization
    logger.info(f"Received webhook: {request.body.decode('utf-8', errors='replace')}")

    return JsonResponse({
        'received': True,
        'message': 'Webhook received successfully'
    })


@login_required
@csrf_exempt
def url_preview(request):
    """
    Generate URL preview (fetch metadata).

    VULNERABILITY V09 (variant): SSRF via URL preview
    """
    url = request.POST.get('url', '') or request.GET.get('url', '')

    if not url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    try:
        # VULNERABLE: Fetching arbitrary URL for preview
        response = requests.get(
            url,  # SINK
            timeout=10,
            headers={
                'User-Agent': 'VulnShop URL Preview Bot/1.0'
            }
        )

        # Extract metadata from HTML
        from html.parser import HTMLParser

        class MetaParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.title = ''
                self.in_title = False
                self.description = ''

            def handle_starttag(self, tag, attrs):
                if tag == 'title':
                    self.in_title = True
                elif tag == 'meta':
                    attrs_dict = dict(attrs)
                    if attrs_dict.get('name') == 'description':
                        self.description = attrs_dict.get('content', '')

            def handle_data(self, data):
                if self.in_title:
                    self.title += data

            def handle_endtag(self, tag):
                if tag == 'title':
                    self.in_title = False

        parser = MetaParser()
        parser.feed(response.text)

        return JsonResponse({
            'url': url,
            'title': parser.title.strip(),
            'description': parser.description,
            'status_code': response.status_code,
        })

    except requests.RequestException as e:
        return JsonResponse({'error': str(e)}, status=500)
