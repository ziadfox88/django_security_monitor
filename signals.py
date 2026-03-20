from datetime import timedelta
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models import F
from django.dispatch import receiver
from django.utils import timezone

from .models import LoginAttempt, SecurityEvent, ThreatScore
from .conf import monitor_settings


def _get_ip(request):
    if not request:
        return ''
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '')


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request, **kwargs):
    if not request:
        return
    ip = _get_ip(request)
    username = credentials.get('username', '')
    ua = request.META.get('HTTP_USER_AGENT', '')[:500]
    w = monitor_settings.THREAT_SCORE_WEIGHTS

    # ✅ Check if the failing username belongs to a superuser
    from django.contrib.auth import get_user_model
    User = get_user_model()
    is_superuser = User.objects.filter(
        username=username, is_superuser=True
    ).exists()

    LoginAttempt.objects.create(
        ip_address=ip, username=username, success=False, user_agent=ua
    )

    if monitor_settings.LOGIN_ATTEMPT_WINDOW is None:
        # If disabled, just log the single failure as an auth_failure
        failures = 0
    else:
        window_start = timezone.now() - timedelta(seconds=monitor_settings.LOGIN_ATTEMPT_WINDOW)
        failures = LoginAttempt.objects.filter(
            ip_address=ip, success=False, timestamp__gte=window_start
        ).count()

    if monitor_settings.MAX_LOGIN_ATTEMPTS is not None and failures >= monitor_settings.MAX_LOGIN_ATTEMPTS:
        SecurityEvent.objects.create(
            ip_address=ip,
            event_type='brute_force',
            severity='critical',
            path=request.path,
            method=request.method,
            user_agent=ua,
            threat_score_delta=w.get('brute_force', 25),
            extra_data={
                'username': username,
                'failures_in_window': failures,
                'superuser_test': is_superuser,  # ✅ tag it
            },
        )
        _bump_score(ip, w.get('brute_force', 25), is_superuser=is_superuser)
    else:
        SecurityEvent.objects.create(
            ip_address=ip,
            event_type='auth_failure',
            severity='medium',
            path=request.path,
            method=request.method,
            user_agent=ua,
            threat_score_delta=w.get('auth_failure', 5),
            extra_data={
                'username': username,
                'superuser_test': is_superuser,  # ✅ tag it
            },
        )
        _bump_score(ip, w.get('auth_failure', 5), is_superuser=is_superuser)



@receiver(user_logged_in)
def on_login_success(sender, user, request, **kwargs):
    if not request:
        return
    ip = _get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '')[:500]
    LoginAttempt.objects.create(
        ip_address=ip, username=user.username, success=True, user_agent=ua
    )


def _bump_score(ip, delta, is_superuser=False):
    if not ip or delta == 0:
        return
    threat, created = ThreatScore.objects.get_or_create(
        ip_address=ip, defaults={'score': delta, 'event_count': 1}
    )
    if not created:
        ThreatScore.objects.filter(pk=threat.pk).update(
            score=F('score') + delta,
            event_count=F('event_count') + 1,
        )
    threat.refresh_from_db()

    # ✅ Never auto-block a superuser
    if is_superuser:
        return

    if (
        monitor_settings.AUTO_BLOCK
        and monitor_settings.BLOCK_THRESHOLD is not None
        and threat.score >= monitor_settings.BLOCK_THRESHOLD
        and not threat.is_blocked
    ):
        from django.utils import timezone
        ThreatScore.objects.filter(pk=threat.pk).update(
            is_blocked=True,
            blocked_at=timezone.now(),
            block_reason=f'Auto-blocked: score ≥ {monitor_settings.BLOCK_THRESHOLD}',
        )


