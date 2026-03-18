from functools import wraps
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from .conf import monitor_settings


def security_monitor_required(view_func):
    """
    Grants access if:
      - SECURITY_MONITOR['ALLOWED_USERS'] is set → user.username must be in that list
      - Otherwise → user must be a superuser
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            login_url = getattr(settings, 'LOGIN_URL', '/accounts/login/')
            return redirect(f"{login_url}?next={request.path}")

        allowed_users = monitor_settings.ALLOWED_USERS
        if allowed_users:
            if request.user.username not in allowed_users:
                raise PermissionDenied
        else:
            if not request.user.is_superuser:
                raise PermissionDenied

        return view_func(request, *args, **kwargs)
    return wrapper
