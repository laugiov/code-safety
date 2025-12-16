"""
Notifications Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V11: SSTI (Server-Side Template Injection)
"""

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings


@login_required
@csrf_exempt
def preview_email(request):
    """
    Preview email with custom template.

    ==========================================================================
    VULNERABILITY V11: Server-Side Template Injection (SSTI)
    ==========================================================================
    CWE-1336: Improper Neutralization of Special Elements Used in a
              Template Engine

    Taint Flow:
        Source: request.POST['template']
        Sink: Template().render()

    Attack Vectors (Django Template Engine):
        1. Read settings/secrets:
           template={{ settings.SECRET_KEY }}
           template={{ settings.DATABASES }}

        2. Access objects:
           template={{ user.password }}
           template={{ request.META }}

        3. Execute code (limited in Django, more severe in Jinja2):
           template={{ ''.__class__.__mro__[1].__subclasses__() }}

    In Django, SSTI is somewhat limited compared to Jinja2, but still
    allows reading configuration and potentially sensitive data.

    Expected Detection:
        - Pysa: UserControlled -> TemplateRendering
        - CodeQL: py/template-injection
        - Semgrep: python.django.security.audit.template-injection

    ==========================================================================
    """
    if request.method != 'POST':
        return render(request, 'notifications/email_preview.html')

    template_content = request.POST.get('template', '')
    recipient_name = request.POST.get('name', 'Customer')

    if not template_content:
        return HttpResponse('Template content is required', status=400)

    # =================================================================
    # VULNERABLE CODE - SSTI (V11)
    # =================================================================
    # SINK: User-controlled template content passed to Template()

    try:
        # VULNERABLE: Creating template from user input
        template = Template(template_content)  # SINK - SSTI

        # Create context with various objects (some sensitive)
        context = Context({
            'name': recipient_name,
            'user': request.user,
            'settings': settings,  # Exposes all settings!
            'request': request,
        })

        rendered = template.render(context)

        return HttpResponse(rendered)

    except Exception as e:
        return HttpResponse(f'Template error: {e}', status=400)


@login_required
@csrf_exempt
def custom_notification(request):
    """
    Send custom notification with user-defined template.

    VULNERABILITY V11 (variant): SSTI with JSON input
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import json

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    template_content = data.get('template', '')
    context_data = data.get('context', {})

    if not template_content:
        return JsonResponse({'error': 'Template is required'}, status=400)

    try:
        # VULNERABLE: User-controlled template
        template = Template(template_content)  # SINK

        # Add dangerous objects to context
        context_data['settings'] = settings
        context_data['user'] = request.user
        context = Context(context_data)

        rendered = template.render(context)

        return JsonResponse({
            'success': True,
            'rendered': rendered
        })

    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=400)


@login_required
def notification_settings(request):
    """Notification settings page."""
    return render(request, 'notifications/settings.html')


@login_required
@csrf_exempt
def template_editor(request):
    """
    Template editor for email templates.

    VULNERABILITY V11 (variant): Another SSTI entry point
    """
    if request.method == 'GET':
        return render(request, 'notifications/template_editor.html')

    template_name = request.POST.get('name', 'custom')
    template_content = request.POST.get('content', '')

    # Preview the template with sample data
    sample_context = {
        'name': 'John Doe',
        'email': 'john@example.com',
        'order_id': 'VS-12345678',
        'total': '$99.99',
        'user': request.user,
        'settings': settings,
    }

    try:
        # VULNERABLE: Rendering user-controlled template
        template = Template(template_content)  # SINK
        rendered = template.render(Context(sample_context))

        return JsonResponse({
            'name': template_name,
            'preview': rendered,
            'success': True
        })

    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=400)


@login_required
@csrf_exempt
def send_test_email(request):
    """
    Send test email with custom template.

    VULNERABILITY V11: SSTI before sending email
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    recipient = request.POST.get('recipient', request.user.email)
    subject = request.POST.get('subject', 'Test Email')
    template_content = request.POST.get('template', 'Hello {{ name }}!')

    try:
        # VULNERABLE: User-controlled template
        template = Template(template_content)  # SINK
        context = Context({
            'name': request.user.first_name or request.user.username,
            'user': request.user,
            'settings': settings,
        })
        body = template.render(context)

        # In a real app, would send email here
        # send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [recipient])

        return JsonResponse({
            'success': True,
            'message': f'Email would be sent to {recipient}',
            'preview': body
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
def list_templates(request):
    """List available email templates."""
    templates = [
        {'name': 'welcome', 'description': 'Welcome email for new users'},
        {'name': 'order_confirmation', 'description': 'Order confirmation email'},
        {'name': 'shipping', 'description': 'Shipping notification'},
        {'name': 'password_reset', 'description': 'Password reset email'},
    ]
    return JsonResponse({'templates': templates})


def webhook_notification(request):
    """
    Process webhook and send notification.

    Less vulnerable - uses predefined templates.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import json

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    event_type = data.get('event')
    payload = data.get('payload', {})

    # Use predefined templates based on event type
    templates = {
        'order.created': 'New order {{ order_id }} received!',
        'order.shipped': 'Order {{ order_id }} has been shipped.',
        'user.registered': 'Welcome {{ username }}!',
    }

    if event_type not in templates:
        return JsonResponse({'error': 'Unknown event type'}, status=400)

    # Safe usage - using predefined template
    template = Template(templates[event_type])
    rendered = template.render(Context(payload))

    return JsonResponse({
        'notification': rendered,
        'event': event_type
    })
