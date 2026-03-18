from django.conf import settings as django_settings

DEFAULTS = {
    'ALLOWED_USERS': [],            # empty = superusers only; or ['alice', 'bob']
    'SUSPICIOUS_PATHS': [
        '.env', '.git', '.svn', 'wp-admin', 'wp-login',
        'phpMyAdmin', 'phpmyadmin', '/etc/passwd', '/etc/shadow',
        'config.php', '.htaccess', '.htpasswd', 'web.config',
        '.DS_Store', 'xmlrpc.php', '/proc/', 'backup.sql', 'dump.sql',
    ],
    'SENSITIVE_EXTENSIONS': [
        '.env', '.sql', '.bak', '.backup', '.dump', '.config',
        '.conf', '.key', '.pem', '.p12', '.pfx', '.log',
        '.db', '.sqlite', '.sqlite3',
    ],
    'HONEYPOT_PATHS': [
        '/wp-login.php', '/wp-admin/', '/admin/login.php',
        '/.env', '/.git/config', '/config.php',
        '/phpinfo.php', '/server-status', '/admin.php',
        '/shell.php', '/c99.php', '/r57.php',
    ],
    'BLOCK_THRESHOLD': 50,
    'RATE_LIMIT': 200,
    'RATE_LIMIT_WINDOW': 60,
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_ATTEMPT_WINDOW': 300,
    'USE_REDIS': None,              # None = auto-detect
    'USE_CELERY': None,             # None = auto-detect
    'DASHBOARD_URL': 'security-monitor/',
    'ALERT_EMAIL': None,
    'LOG_404': True,
    'LOG_500': True,
    'EXCLUDE_PATHS': ['/static/', '/media/'],
    'WHITELIST_CACHE_TTL': 300,
    'EVENT_RETENTION_DAYS': 90,
    'THREAT_SCORE_WEIGHTS': {
        'suspicious_path': 15,
        'sensitive_file': 20,
        'rate_limit': 10,
        'auth_failure': 5,
        'brute_force': 25,
        'sql_injection': 30,
        'xss_attempt': 25,
        'path_traversal': 35,
        'scanner': 20,
        'honeypot': 40,
        '404': 3,
        '500': 2,
        'csrf_failure': 15,
        'blocked_ip': 0,
    },
    'AUTO_BLOCK': False,
}


class _SecurityMonitorSettings:
    def __init__(self):
        self._cache = None

    def _load(self):
        self._cache = getattr(django_settings, 'SECURITY_MONITOR', {})

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        if self._cache is None:
            self._load()
        if name in self._cache:
            return self._cache[name]
        if name in DEFAULTS:
            return DEFAULTS[name]
        raise AttributeError(f"Invalid SECURITY_MONITOR setting: '{name}'")

    def get(self, name, default=None):
        try:
            return getattr(self, name)
        except AttributeError:
            return default


monitor_settings = _SecurityMonitorSettings()


def is_redis_available():
    if monitor_settings.USE_REDIS is False:
        return False
    try:
        backend = django_settings.CACHES.get('default', {}).get('BACKEND', '')
        if 'redis' not in backend.lower():
            return False
        from django.core.cache import cache
        cache.set('_sm_probe', 1, 1)
        return cache.get('_sm_probe') == 1
    except Exception:
        return False


def is_celery_available():
    if monitor_settings.USE_CELERY is False:
        return False
    try:
        from celery import current_app
        return current_app.configured
    except Exception:
        return False
