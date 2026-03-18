from django.apps import AppConfig


class DjangoSecurityMonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_security_monitor'
    verbose_name = 'Security Monitor'


    
    def ready(self):
        import django_security_monitor.signals  # noqa: F401 — register signal handlers