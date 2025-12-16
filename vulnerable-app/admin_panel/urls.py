"""
Admin Panel URL Configuration

Maps admin panel endpoints to views.
Contains vulnerable endpoints V05 (Command Injection) and V06 (Path Traversal).
"""

from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # System tools - V05: Command Injection
    path('system-info/', views.system_info, name='system_info'),
    path('diagnostics/', views.run_diagnostic, name='diagnostics'),
    path('execute/', views.execute_command, name='execute'),
    path('logs/', views.server_logs, name='logs'),

    # File manager - V06: Path Traversal
    path('files/', views.file_manager, name='file_manager'),
    path('files/list/', views.list_files, name='list_files'),
    path('files/view/', views.view_file, name='view_file'),
    path('files/download/', views.download_file, name='download_file'),
    path('files/delete/', views.delete_file, name='delete_file'),
]
