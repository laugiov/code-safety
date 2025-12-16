"""
Request Logging Middleware

Contains intentionally vulnerable logging for taint analysis demonstration.

Vulnerabilities:
- V14: Sensitive Data Logging (CWE-532)
"""

import logging
import json

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware:
    """
    Middleware that logs all incoming requests.

    ==========================================================================
    VULNERABILITY V14: Sensitive Data Logging
    ==========================================================================
    CWE-532: Insertion of Sensitive Information into Log File

    Taint Flow:
        Source: request.POST, request.headers, request.COOKIES
        Sink: logger.info() / logger.debug()

    Issue:
        This middleware logs sensitive data including:
        - Passwords from POST data
        - Authentication tokens from headers
        - Session cookies
        - Credit card numbers
        - Personal information

    Attack Scenario:
        1. Attacker gains access to log files
        2. Logs contain plain-text passwords and tokens
        3. Attacker uses credentials to compromise accounts

    Logs are often:
        - Stored in plain text
        - Backed up without encryption
        - Sent to centralized logging services
        - Retained for long periods
        - Accessible to many team members

    Expected Detection:
        - Pysa: SensitiveData -> LogOutput
        - CodeQL: py/sensitive-data-logging
        - Semgrep: python.lang.security.sensitive-data-logging

    ==========================================================================
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Compile list of "sensitive" field names (for demonstration)
        self.sensitive_fields = {
            'password', 'passwd', 'pwd', 'secret', 'token',
            'api_key', 'apikey', 'auth', 'authorization',
            'credit_card', 'card_number', 'cvv', 'ssn',
            'social_security', 'bank_account'
        }

    def __call__(self, request):
        # Log request start
        self._log_request(request)

        # Get response
        response = self.get_response(request)

        # Log response
        self._log_response(request, response)

        return response

    def _log_request(self, request):
        """
        Log incoming request details.

        VULNERABLE: Logs sensitive data from POST, headers, and cookies.
        """
        # =================================================================
        # VULNERABLE CODE - Sensitive Data Logging (V14)
        # =================================================================

        # VULNERABLE: Logging full request path and method
        logger.info(f"Request: {request.method} {request.path}")

        # VULNERABLE: Logging all headers (may contain Authorization tokens)
        headers = dict(request.headers)
        logger.info(f"Headers: {headers}")  # SINK - Contains auth tokens

        # VULNERABLE: Logging all POST data (contains passwords!)
        if request.method == 'POST':
            post_data = dict(request.POST)
            # Even "masking" attempts often fail
            logger.info(f"POST data: {post_data}")  # SINK - Contains passwords

        # VULNERABLE: Logging cookies (contains session tokens!)
        cookies = dict(request.COOKIES)
        logger.info(f"Cookies: {cookies}")  # SINK - Contains session IDs

        # VULNERABLE: Logging query parameters
        if request.GET:
            logger.info(f"Query params: {dict(request.GET)}")

        # VULNERABLE: Logging request body for API requests
        if request.content_type and 'json' in request.content_type:
            try:
                body = json.loads(request.body)
                logger.debug(f"JSON body: {body}")  # SINK - May contain secrets
            except (json.JSONDecodeError, ValueError):
                pass

    def _log_response(self, request, response):
        """
        Log response details.

        Less vulnerable but still may expose info.
        """
        logger.info(f"Response: {response.status_code} for {request.path}")

        # VULNERABLE: Logging response headers
        # Some apps return tokens in response headers
        logger.debug(f"Response headers: {dict(response.items())}")

    def _should_mask(self, key):
        """Check if a field should be masked."""
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self.sensitive_fields)


class VerboseLoggingMiddleware:
    """
    Even more verbose logging middleware.

    VULNERABILITY V14 (variant): Extremely detailed logging
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Log everything about the request
        self._verbose_log(request)

        response = self.get_response(request)

        return response

    def _verbose_log(self, request):
        """
        Extremely verbose request logging.

        VULNERABLE: Logs literally everything.
        """
        log_data = {
            'method': request.method,
            'path': request.path,
            'full_path': request.get_full_path(),
            'scheme': request.scheme,
            'is_secure': request.is_secure(),
            'host': request.get_host(),
            'user': str(request.user) if hasattr(request, 'user') else 'Anonymous',
            'ip': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),

            # VULNERABLE: Full header dump
            'headers': dict(request.headers),

            # VULNERABLE: Full META dump (contains sensitive env vars)
            'meta': {k: str(v) for k, v in request.META.items()
                     if not k.startswith('wsgi.')},

            # VULNERABLE: Session data
            'session': dict(request.session) if hasattr(request, 'session') else {},

            # VULNERABLE: All cookies
            'cookies': dict(request.COOKIES),
        }

        # VULNERABLE: POST data with passwords
        if request.method in ('POST', 'PUT', 'PATCH'):
            log_data['post_data'] = dict(request.POST)

            if request.body:
                try:
                    log_data['body'] = request.body.decode('utf-8')[:10000]
                except Exception:
                    log_data['body'] = '<binary data>'

        # VULNERABLE: Files information
        if request.FILES:
            log_data['files'] = {
                name: {
                    'filename': f.name,
                    'size': f.size,
                    'content_type': f.content_type,
                }
                for name, f in request.FILES.items()
            }

        # Log the complete request data
        logger.info(f"VERBOSE REQUEST LOG: {json.dumps(log_data, default=str)}")

    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')
