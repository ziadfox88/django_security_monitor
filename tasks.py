"""
Celery tasks — only registered if Celery is available.
Falls back to nothing if project has no Celery.
"""
from .conf import is_celery_available

if is_celery_available():
    from celery import shared_task
    from datetime import timedelta
    from django.utils import timezone
    from django.core.mail import send_mail
    from django.conf import settings
    from .models import SecurityEvent, ThreatScore
    from .conf import monitor_settings

    @shared_task(name='security_monitor.cleanup_old_events')
    def cleanup_old_events():
        """Delete events older than EVENT_RETENTION_DAYS."""
        cutoff = timezone.now() - timedelta(days=monitor_settings.EVENT_RETENTION_DAYS)
        deleted, _ = SecurityEvent.objects.filter(timestamp__lt=cutoff).delete()
        return f"Deleted {deleted} old security events"

    @shared_task(name='security_monitor.send_critical_alert')
    def send_critical_alert(event_id):
        """Email the admin when a critical event occurs."""
        alert_email = monitor_settings.ALERT_EMAIL
        if not alert_email:
            return "No ALERT_EMAIL configured"
        try:
            event = SecurityEvent.objects.get(pk=event_id)
            send_mail(
                subject=f"[SIEM CRITICAL] {event.get_event_type_display()} from {event.ip_address}",
                message=(
                    f"IP: {event.ip_address}\n"
                    f"Path: {event.path}\n"
                    f"Type: {event.get_event_type_display()}\n"
                    f"Time: {event.timestamp}\n"
                    f"Payload: {event.payload or 'N/A'}"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[alert_email],
                fail_silently=True,
            )
            return f"Alert sent for event {event_id}"
        except SecurityEvent.DoesNotExist:
            return "Event not found"

    @shared_task(name='security_monitor.decay_threat_scores')
    def decay_threat_scores():
        """
        Gradually reduce threat scores over time so old IPs
        aren't permanently flagged.
        """
        from django.db.models import F
        cutoff = timezone.now() - timedelta(hours=24)
        updated = ThreatScore.objects.filter(
            last_event__lt=cutoff, is_blocked=False, score__gt=0
        ).update(score=F('score') * 0.9)
        return f"Decayed scores for {updated} IPs"
    # tasks.py
    @shared_task(name='security_monitor.log_pageview_async')
    def log_pageview_async(visitor_id, path, method, status_code, response_time_ms):
        from .models import PageView
        PageView.objects.create(
            visitor_id=visitor_id, path=path, method=method,
            status_code=status_code, response_time_ms=response_time_ms,
        )