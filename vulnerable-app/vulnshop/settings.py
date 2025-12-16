"""
Django settings for VulnShop project.

=============================================================================
WARNING: INTENTIONALLY VULNERABLE CONFIGURATION
=============================================================================
This settings file contains deliberate security vulnerabilities for
educational and taint analysis demonstration purposes.

Vulnerabilities in this file:
- V12: Hardcoded secrets (CWE-798)
- DEBUG mode enabled
- Weak password validation
- Insecure cookie settings

DO NOT USE IN PRODUCTION
=============================================================================
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# VULNERABILITY V12: Hardcoded Secrets (CWE-798)
# =============================================================================
# Taint Analysis Note: These hardcoded credentials should be detected by
# secret scanning tools and static analyzers.

# VULNERABLE: Hardcoded secret key - should use environment variable
# CWE-798: Use of Hard-coded Credentials
SECRET_KEY = 'django-insecure-CHANGEME-but-we-didnt-haha-12345'

# VULNERABLE: Debug mode enabled in "production"
# This exposes sensitive error information
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '*']


# =============================================================================
# Application definition
# =============================================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party apps
    'rest_framework',
    # VulnShop apps
    'authentication',
    'catalog',
    'reviews',
    'cart',
    'payment',
    'profile',
    'admin_panel',
    'webhooks',
    'notifications',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # VULNERABLE: CSRF middleware is present but can be bypassed in some views
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # VULNERABILITY V14: Sensitive data logging middleware
    'middleware.logging.RequestLoggingMiddleware',
]

ROOT_URLCONF = 'vulnshop.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnshop.wsgi.application'


# =============================================================================
# Database
# =============================================================================
# VULNERABILITY V12: Hardcoded database credentials

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Example PostgreSQL config with hardcoded credentials (for demonstration)
# VULNERABLE: Hardcoded database password
DATABASES_POSTGRESQL_EXAMPLE = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'vulnshop',
        'USER': 'admin',
        'PASSWORD': 'SuperSecretPassword123!',  # CWE-798: Hardcoded credential
        'HOST': 'localhost',
        'PORT': '5432',
    }
}


# =============================================================================
# Password validation
# =============================================================================
# VULNERABLE: Weak password validation - minimal requirements

AUTH_PASSWORD_VALIDATORS = [
    # Intentionally weak - only checks minimum length of 4
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 4,  # VULNERABLE: Too short
        }
    },
    # Missing: UserAttributeSimilarityValidator
    # Missing: CommonPasswordValidator
    # Missing: NumericPasswordValidator
]


# =============================================================================
# Custom User Model
# =============================================================================

AUTH_USER_MODEL = 'authentication.User'


# =============================================================================
# Internationalization
# =============================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# =============================================================================
# Static files (CSS, JavaScript, Images)
# =============================================================================

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'


# =============================================================================
# Media files (User uploads)
# =============================================================================

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# VULNERABLE: Upload directory without proper restrictions
UPLOAD_DIR = '/app/uploads/'


# =============================================================================
# Default primary key field type
# =============================================================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# =============================================================================
# REST Framework Configuration
# =============================================================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        # VULNERABLE: Allows any access by default
        'rest_framework.permissions.AllowAny',
    ],
    # VULNERABLE: No rate limiting
    'DEFAULT_THROTTLE_CLASSES': [],
    'DEFAULT_THROTTLE_RATES': {},
}


# =============================================================================
# VULNERABILITY V12: Hardcoded API Keys and Secrets
# =============================================================================
# These should be loaded from environment variables or a secrets manager

# VULNERABLE: Hardcoded Stripe key
# NOTE: These are FAKE keys for demonstration - they follow the format but are not real
STRIPE_SECRET_KEY = 'sk_test_FAKE_KEY_FOR_DEMO_ONLY_not_a_real_key_12345'  # nosec
STRIPE_PUBLISHABLE_KEY = 'pk_test_FAKE_KEY_FOR_DEMO_ONLY_not_a_real_key_12345'  # nosec

# VULNERABLE: Hardcoded AWS credentials
# NOTE: These are AWS's official EXAMPLE keys from documentation - not real
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'  # Official AWS example key
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # Official AWS example
AWS_REGION = 'us-east-1'

# VULNERABLE: Hardcoded email credentials
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'vulnshop@example.com'
EMAIL_HOST_PASSWORD = 'EmailPassword123!'  # CWE-798

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = 'aes-256-encryption-key-1234567890abcdef'

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET_KEY = 'super-secret-jwt-key-do-not-share'


# =============================================================================
# Security Settings (Intentionally Weak)
# =============================================================================

# VULNERABLE: Cookies not secured
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

# VULNERABLE: No HSTS
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# VULNERABLE: SSL redirect disabled
SECURE_SSL_REDIRECT = False

# VULNERABLE: Content type sniffing not prevented
SECURE_CONTENT_TYPE_NOSNIFF = False

# VULNERABLE: XSS filter disabled
SECURE_BROWSER_XSS_FILTER = False


# =============================================================================
# Logging Configuration
# =============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'debug.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'DEBUG',  # VULNERABLE: Debug logging in production
    },
}
