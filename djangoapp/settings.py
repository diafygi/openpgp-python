import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY = os.environ['DJANGO_SECRET']
DEBUG = False

ALLOWED_HOSTS = [
    "localhost",
    "localhost:8000",
    "keyserver-sql.daylightpirates.org",
    "keyserver-sql.daylightpirates.org:8000",
    "keyserver-elasticsearch.daylightpirates.org:8000",
]

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'keys',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'keys.middleware.ReadOnlyMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

ROOT_URLCONF = 'urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get("DJANGO_DB_NAME", "openpgppythondb"),
        'USER': os.environ.get("DJANGO_DB_USER", "openpgppythonuser"),
        'PASSWORD': os.environ['DJANGO_DB_PASSWORD'],
        'HOST': os.environ.get("DJANGO_DB_HOST", "localhost"),
        'PORT': os.environ.get("DJANGO_DB_HOST", ""),
    }
}


LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
