import json
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .conf import monitor_settings
from .decorators import security_monitor_required
from .models import (
    HoneypotHit, IPWhitelist, LoginAttempt,
    PageView, SecurityEvent, ThreatScore, Visitor,
)


# ── helpers ──────────────────────────────────────────────────────────────────
def _now():
    return timezone.now()

def _today_start():
    return _now().replace(hour=0, minute=0, second=0, microsecond=0)


# ── Dashboard ────────────────────────────────────────────────────────────────
@security_monitor_required
def dashboard(request):
    now = _now()
    today = _today_start()
    week_ago = now - timedelta(days=7)

    # Stat cards
    stats = {
        'events_today': SecurityEvent.objects.filter(timestamp__gte=today).count(),
        'critical_today': SecurityEvent.objects.filter(
            timestamp__gte=today, severity='critical'
        ).count(),
        'blocked_ips': ThreatScore.objects.filter(is_blocked=True).count(),
        'active_threats': ThreatScore.objects.filter(
            score__gte=20, is_blocked=False
        ).count(),
        'total_visitors': Visitor.objects.count(),
        'honeypot_hits': HoneypotHit.objects.filter(timestamp__gte=today).count(),
    }

    # Recent events feed (last 30)
    recent_events = SecurityEvent.objects.select_related('user').order_by('-timestamp')[:30]

    # Top threat IPs
    top_threats = ThreatScore.objects.order_by('-score')[:15]

    # Events by type (for donut chart)
    events_by_type = list(
        SecurityEvent.objects.filter(timestamp__gte=week_ago)
        .values('event_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # Events per day for last 7 days (for line chart)
    events_per_day = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        day_end = day_start + timedelta(days=1)
        events_per_day.append({
            'date': day_start.strftime('%b %d'),
            'count': SecurityEvent.objects.filter(
                timestamp__gte=day_start, timestamp__lt=day_end
            ).count(),
        })

    # Severity breakdown (last 24h)
    severity_counts = dict(
        SecurityEvent.objects.filter(timestamp__gte=now - timedelta(hours=24))
        .values('severity')
        .annotate(c=Count('id'))
        .values_list('severity', 'c')
    )

    # Top attacked paths
    top_paths = list(
        SecurityEvent.objects.filter(timestamp__gte=week_ago)
        .values('path')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    context = {
        'stats': stats,
        'recent_events': recent_events,
        'top_threats': top_threats,
        'events_by_type_json': json.dumps(events_by_type),
        'events_per_day_json': json.dumps(events_per_day),
        'severity_counts': severity_counts,
        'top_paths': top_paths,
        'page': 'dashboard',
    }
    return render(request, 'django_security_monitor/dashboard.html', context)


# ── Events list ──────────────────────────────────────────────────────────────
@security_monitor_required
def events_list(request):
    qs = SecurityEvent.objects.select_related('user').order_by('-timestamp')

    # Filters
    severity = request.GET.get('severity')
    event_type = request.GET.get('event_type')
    ip = request.GET.get('ip', '').strip()
    days = request.GET.get('days', '7')

    try:
        days = int(days)
    except ValueError:
        days = 7

    qs = qs.filter(timestamp__gte=_now() - timedelta(days=days))

    if severity:
        qs = qs.filter(severity=severity)
    if event_type:
        qs = qs.filter(event_type=event_type)
    if ip:
        qs = qs.filter(ip_address__icontains=ip)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'event_types': SecurityEvent.EVENT_TYPES,
        'severities': SecurityEvent.SEVERITY,
        'period_options': [1, 7, 30, 90],
        'current_filters': {
            'severity': severity, 'event_type': event_type,
            'ip': ip, 'days': days,
        },
        'page': 'events',
    }
    return render(request, 'django_security_monitor/events.html', context)


# ── Threats list ─────────────────────────────────────────────────────────────
@security_monitor_required
def threats_list(request):
    qs = ThreatScore.objects.all()

    show = request.GET.get('show', 'all')
    if show == 'blocked':
        qs = qs.filter(is_blocked=True)
    elif show == 'active':
        qs = qs.filter(is_blocked=False, score__gte=10)

    paginator = Paginator(qs.order_by('-score'), 40)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'show': show,
        'page': 'threats',
    }
    return render(request, 'django_security_monitor/threats.html', context)


# ── IP detail ─────────────────────────────────────────────────────────────────
@security_monitor_required
def ip_detail(request, ip_address):
    threat, _ = ThreatScore.objects.get_or_create(ip_address=ip_address)
    events_qs = SecurityEvent.objects.filter(ip_address=ip_address)
    events = events_qs.order_by('-timestamp')[:100]
    login_attempts = LoginAttempt.objects.filter(ip_address=ip_address).order_by('-timestamp')[:20]
    honeypot_hits = HoneypotHit.objects.filter(ip_address=ip_address).order_by('-timestamp')[:10]
    visitor = Visitor.objects.filter(ip_address=ip_address).first()
    whitelisted = IPWhitelist.objects.filter(ip_address=ip_address).exists()

    # Event type breakdown for this IP
    event_breakdown = list(
        events_qs.values('event_type').annotate(count=Count('id')).order_by('-count')
    )

    context = {
        'threat': threat,
        'events': events,
        'login_attempts': login_attempts,
        'honeypot_hits': honeypot_hits,
        'visitor': visitor,
        'whitelisted': whitelisted,
        'event_breakdown_json': json.dumps(event_breakdown),
        'page': 'threats',
    }
    return render(request, 'django_security_monitor/ip_detail.html', context)


# ── Visitors ─────────────────────────────────────────────────────────────────
@security_monitor_required
def visitors_list(request):
    qs = Visitor.objects.select_related('user').order_by('-last_visit')

    ip = request.GET.get('ip', '').strip()
    if ip:
        qs = qs.filter(ip_address__icontains=ip)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'page': 'visitors',
    }
    return render(request, 'django_security_monitor/visitors.html', context)


# ── Actions (POST) ────────────────────────────────────────────────────────────
@security_monitor_required
@require_POST
def block_ip(request, ip_address):
    reason = request.POST.get('reason', 'Manually blocked by admin')
    threat, _ = ThreatScore.objects.get_or_create(ip_address=ip_address)
    ThreatScore.objects.filter(pk=threat.pk).update(
        is_blocked=True,
        blocked_at=timezone.now(),
        block_reason=reason,
    )
    messages.success(request, f"✅ {ip_address} has been blocked.")
    return redirect(request.META.get('HTTP_REFERER', 'security_monitor:threats'))


@security_monitor_required
@require_POST
def unblock_ip(request, ip_address):
    ThreatScore.objects.filter(ip_address=ip_address).update(
        is_blocked=False,
        block_reason='',
        blocked_at=None,
    )
    messages.success(request, f"✅ {ip_address} has been unblocked.")
    return redirect(request.META.get('HTTP_REFERER', 'security_monitor:threats'))


@security_monitor_required
@require_POST
def whitelist_ip(request, ip_address):
    reason = request.POST.get('reason', '')
    IPWhitelist.objects.get_or_create(
        ip_address=ip_address,
        defaults={'added_by': request.user, 'reason': reason},
    )
    # Also unblock if blocked
    ThreatScore.objects.filter(ip_address=ip_address).update(
        is_blocked=False, block_reason=''
    )
    messages.success(request, f"✅ {ip_address} has been whitelisted.")
    return redirect(request.META.get('HTTP_REFERER', 'security_monitor:threats'))


@security_monitor_required
@require_POST
def remove_whitelist(request, ip_address):
    IPWhitelist.objects.filter(ip_address=ip_address).delete()
    messages.success(request, f"🗑 {ip_address} removed from whitelist.")
    return redirect(request.META.get('HTTP_REFERER', 'security_monitor:threats'))


@security_monitor_required
@require_POST
def delete_event(request, event_id):
    SecurityEvent.objects.filter(pk=event_id).delete()
    return JsonResponse({'status': 'ok'})


# ── JSON APIs (for live polling) ──────────────────────────────────────────────
@security_monitor_required
def live_events(request):
    since_id = request.GET.get('since', 0)
    events = SecurityEvent.objects.filter(pk__gt=since_id).order_by('-timestamp')[:20]
    data = [
        {
            'id': e.pk,
            'ip': e.ip_address,
            'type': e.get_event_type_display(),
            'severity': e.severity,
            'path': e.path,
            'timestamp': e.timestamp.strftime('%H:%M:%S'),
        }
        for e in events
    ]
    return JsonResponse({'events': data})


@security_monitor_required
def stats_api(request):
    now = _now()
    today = _today_start()
    return JsonResponse({
        'events_today': SecurityEvent.objects.filter(timestamp__gte=today).count(),
        'critical_today': SecurityEvent.objects.filter(
            timestamp__gte=today, severity='critical'
        ).count(),
        'blocked_ips': ThreatScore.objects.filter(is_blocked=True).count(),
        'active_threats': ThreatScore.objects.filter(
            score__gte=20, is_blocked=False
        ).count(),
    })
