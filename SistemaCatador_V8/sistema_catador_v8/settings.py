"""
Django settings for sistema_catador_v8 project.
Gerado e otimizado com LOG SYSTEM profissional.
"""

import os
from pathlib import Path

# Caminho base do projeto
BASE_DIR = Path(__file__).resolve().parent.parent


# ================================
# SEGURANÇA
# ================================

SECRET_KEY = 'django-insecure-77)vgruq$z#zu3k=1u^=y=sb&r_9dyq9^bs8%4pt=9z+83gr-e'

DEBUG = True   # ⚠ Em produção mude para False

ALLOWED_HOSTS = ["*"]   # ← depois configuramos certinho para produção


# ================================
# APLICATIVOS INSTALADOS
# ================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # app principal
    'accounts',
]


# ================================
# MIDDLEWARE
# ================================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


ROOT_URLCONF = 'sistema_catador_v8.urls'


# ================================
# TEMPLATES
# ================================

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],   # onde ficam os HTML
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.media",

                # === CONTEXT PROCESSOR PARA O MENU DO PROGRAMADOR ===
                "accounts.context_processors.programador_count",
            ],
        },
    },
]


WSGI_APPLICATION = 'sistema_catador_v8.wsgi.application'


# ================================
# BANCO DE DADOS
# ================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'sistemacatador_v8',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}


# ================================
# VALIDAÇÃO DE SENHAS
# ================================

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ================================
# LÍNGUA E FUSO HORÁRIO
# ================================

LANGUAGE_CODE = 'pt-br'
TIME_ZONE = 'America/Fortaleza'
USE_I18N = True
USE_TZ = True


# ================================
# ARQUIVOS ESTÁTICOS
# ================================

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]


# ================================
# ARQUIVOS DE MÍDIA
# ================================

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"


# ================================
# MODELO DE USUÁRIO PERSONALIZADO
# ================================

AUTH_USER_MODEL = "accounts.User"


# ================================
# EMAIL (recuperação de senha)
# ================================

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "naoresponda@sistemacatadorv8.com"


# ================================
# LOG SYSTEM PROFISSIONAL
# ================================

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "padrao": {
            "format": "[{levelname}] {asctime} | {message}",
            "style": "{",
        },
        "detalhado": {
            "format": (
                "[{levelname}] {asctime}\n"
                "IP: {clientip}\n"
                "Usuário: {username}\n"
                "Ação: {message}\n"
                "------------------------------"
            ),
            "style": "{",
        },
    },

    "filters": {
        "add_user_ip": {
            "()": "django.utils.log.CallbackFilter",
            "callback": lambda record: True,
        },
    },

    "handlers": {
        "arquivo": {
            "level": "INFO",
            "class": "logging.FileHandler",
            "filename": LOG_DIR / "sistema.log",
            "formatter": "padrao",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "padrao",
        },
    },

    "loggers": {
        "django": {
            "handlers": ["arquivo", "console"],
            "level": "INFO",
            "propagate": True,
        },
        "sistema": {
            "handlers": ["arquivo", "console"],
            "level": "INFO",
        },
    },
}
