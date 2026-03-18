import os
import re
import time
import logging
from django.conf import settings as django_settings
from django.db.models import F
from django.http import HttpResponseForbidden
from django.utils import timezone

import geoip2.database
import geoip2.errors

from .models import (
    Visitor, PageView, SecurityEvent,
    ThreatScore, IPWhitelist, HoneypotHit
)
from .conf import monitor_settings, is_redis_available

logger = logging.getLogger('django_security_monitor')

# ── Attack-detection compiled patterns ──────────────────────────────────────
_SQL = re.compile(
    r"(union[\s+]+select|select[\s\S]+from|insert[\s+]+into|drop[\s+]+table|"
    r"or[\s+]+1[\s+]*=[\s+]*1|exec[\s+]*\(|xp_cmdshell|information_schema|"
    r"sleep[\s+]*\(|benchmark[\s+]*\(|load_file[\s+]*\(|extractvalue[\s+]*\()",
    re.IGNORECASE
)
_XSS = re.compile(
    r"(<script[\s>]|javascript\s*:|on\w+\s*=\s*['\"]|<iframe[\s>]|"
    r"eval\s*\(|document\.cookie|window\.location|<svg[\s\S]*?on\w+\s*=)",
    re.IGNORECASE
)
_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e|\.\.;/)",
    re.IGNORECASE
)
_SCANNER_UA = re.compile(
    r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|"
    r"wfuzz|burpsuite|metasploit|acunetix|nessus|openvas|whatweb|"
    r"hydra|medusa|w3af|skipfish|arachni|zaproxy|havij|commix)",
    re.IGNORECASE
)


class SecurityMonitorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._use_redis = is_redis_available()
        self._whitelist: set = set()
        self._whitelist_ts: float = 0.0

    def __call__(self, request):
        path = request.path

        # 1. Skip excluded paths
        if any(path.startswith(p) for p in monitor_settings.EXCLUDE_PATHS):
            return self.get_response(request)

        ip = self._get_ip(request)
        self._refresh_whitelist()

        # 2. Skip whitelisted IPs
        if ip in self._whitelist:
            return self.get_response(request)

        # 3. Superusers bypass the blocked-IP gate
        user = getattr(request, 'user', None)
        is_superuser = bool(user and user.is_authenticated and user.is_superuser)

        if not is_superuser:
            threat = self._get_threat(ip)
            if threat and threat.is_blocked:
                self._log(ip, request, 'blocked_ip', 'critical', 0)
                return HttpResponseForbidden(
                    "⛔ Your access has been suspended due to suspicious activity."
                )

        # 4. Run security analysis
        self._analyze(ip, request)

        # 5. Get response and log HTTP errors
        response = self.get_response(request)

        if response.status_code == 404 and monitor_settings.LOG_404:
            self._log(ip, request, '404', 'low',
                    monitor_settings.THREAT_SCORE_WEIGHTS.get('404', 3))
        elif response.status_code == 500 and monitor_settings.LOG_500:
            self._log(ip, request, '500', 'low',
                    monitor_settings.THREAT_SCORE_WEIGHTS.get('500', 2))

        return response


    # ── analysis ───────────────────────────────────────────────────────────
    def _analyze(self, ip, request):
        path = request.path
        path_lower = path.lower()
        ua = request.META.get('HTTP_USER_AGENT', '')
        qs = request.META.get('QUERY_STRING', '')
        full = path_lower + qs
        w = monitor_settings.THREAT_SCORE_WEIGHTS

        # 1. Honeypot
        if path in monitor_settings.HONEYPOT_PATHS:
            HoneypotHit.objects.create(
                ip_address=ip, path=path,
                user_agent=ua[:500],
                headers={k: v for k, v in request.META.items()
                         if k.startswith('HTTP_')}
            )
            self._log(ip, request, 'honeypot', 'critical', w.get('honeypot', 40))
            return  # no further checks — we already know this is bad

        # 2. Scanner UA
        if _SCANNER_UA.search(ua):
            self._log(ip, request, 'scanner', 'high', w.get('scanner', 20))

        # 3. Suspicious paths
        for sp in monitor_settings.SUSPICIOUS_PATHS:
            if sp.lower() in path_lower:
                self._log(ip, request, 'suspicious_path', 'high',
                          w.get('suspicious_path', 15))
                break

        # 4. Sensitive extensions
        for ext in monitor_settings.SENSITIVE_EXTENSIONS:
            if path_lower.endswith(ext.lower()):
                self._log(ip, request, 'sensitive_file', 'critical',
                          w.get('sensitive_file', 20))
                break

        # 5. Path traversal
        if _TRAVERSAL.search(full):
            self._log(ip, request, 'path_traversal', 'critical',
                      w.get('path_traversal', 35))

        # 6. SQL injection
        if _SQL.search(qs):
            self._log(ip, request, 'sql_injection', 'critical',
                      w.get('sql_injection', 30), payload=qs[:500])

        # 7. XSS
        if _XSS.search(qs):
            self._log(ip, request, 'xss_attempt', 'high',
                      w.get('xss_attempt', 25), payload=qs[:500])

        # 8. Rate limiting
        if self._use_redis:
            self._rate_redis(ip, request)
        else:
            self._rate_db(ip, request)

    # ── rate limiting ───────────────────────────────────────────────────────
    def _rate_redis(self, ip, request):
        from django.core.cache import cache
        key = f'sm_rl_{ip}'
        count = cache.get(key, 0)
        if count == 0:
            cache.set(key, 1, monitor_settings.RATE_LIMIT_WINDOW)
        else:
            cache.incr(key)
            if count + 1 > monitor_settings.RATE_LIMIT:
                w = monitor_settings.THREAT_SCORE_WEIGHTS
                self._log(ip, request, 'rate_limit', 'medium', w.get('rate_limit', 10))

    def _rate_db(self, ip, request):
        from datetime import timedelta
        window_start = timezone.now() - timedelta(seconds=monitor_settings.RATE_LIMIT_WINDOW)
        count = SecurityEvent.objects.filter(
            ip_address=ip, timestamp__gte=window_start
        ).count()
        if count > monitor_settings.RATE_LIMIT:
            w = monitor_settings.THREAT_SCORE_WEIGHTS
            self._log(ip, request, 'rate_limit', 'medium', w.get('rate_limit', 10))

    # ── helpers ─────────────────────────────────────────────────────────────
    def _log(self, ip, request, event_type, severity, delta, payload=''):
        user = getattr(request, 'user', None)
        if user and not user.is_authenticated:
            user = None

        # Check if superuser BEFORE creating the event
        is_superuser = bool(user and user.is_superuser)

        SecurityEvent.objects.create(
            ip_address=ip,
            user=user,
            event_type=event_type,
            severity=severity,
            path=request.path[:500],
            method=request.method,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            referer=request.META.get('HTTP_REFERER', '')[:500],
            payload=payload,
            threat_score_delta=delta,
            # ✅ tag the event so dashboard can show [TEST] label
            extra_data={'superuser_test': True} if is_superuser else {},
        )
        self._bump_score(ip, delta, is_superuser=is_superuser)


    def _bump_score(self, ip, delta, is_superuser=False):
        if delta == 0:
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

        # ✅ Never auto-block a superuser — score is tracked for testing purposes
        if is_superuser:
            return

        if (
            monitor_settings.AUTO_BLOCK
            and threat.score >= monitor_settings.BLOCK_THRESHOLD
            and not threat.is_blocked
        ):
            ThreatScore.objects.filter(pk=threat.pk).update(
                is_blocked=True,
                blocked_at=timezone.now(),
                block_reason=f'Auto-blocked: score ≥ {monitor_settings.BLOCK_THRESHOLD}',
            )



    def _get_threat(self, ip):
        try:
            return ThreatScore.objects.get(ip_address=ip)
        except ThreatScore.DoesNotExist:
            return None

    def _refresh_whitelist(self):
        ttl = monitor_settings.WHITELIST_CACHE_TTL
        if time.time() - self._whitelist_ts > ttl:
            try:
                self._whitelist = set(
                    IPWhitelist.objects.values_list('ip_address', flat=True)
                )
            except Exception:
                pass
            self._whitelist_ts = time.time()

    def _get_ip(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        xri = request.META.get('HTTP_X_REAL_IP')
        if xri:
            return xri.strip()
        return request.META.get('REMOTE_ADDR', '')


class VisitorTrackingMiddleware:
    """Your existing middleware — enhanced with response time & status tracking."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.geoip_reader = None
        geoip_path = getattr(django_settings, 'GEOIP_PATH', None)
        if geoip_path:
            db = os.path.join(geoip_path, 'GeoLite2-City.mmdb')
            try:
                self.geoip_reader = geoip2.database.Reader(db)
            except FileNotFoundError:
                pass

    def __call__(self, request):
        # 1. Skip paths that don't need visitor tracking
        skip = list(monitor_settings.EXCLUDE_PATHS) + [
            '/admin/', '/newadmin/', '/prometheus/'
        ]
        if any(request.path.startswith(p) for p in skip):
            return self.get_response(request)

        # 2. Ensure session exists
        if not request.session.session_key:
            request.session.create()
        session_key = request.session.session_key

        # 3. Get IP and UA
        ip = self._get_ip(request) or ''
        ua = request.META.get('HTTP_USER_AGENT', '')[:500]

        # 4. Get or create visitor record
        visitor, created = Visitor.objects.get_or_create(
            session_key=session_key,
            defaults={'ip_address': ip, 'user_agent': ua}
        )

        # 5. Link to auth user if logged in
        if request.user.is_authenticated and visitor.user_id != request.user.id:
            visitor.user = request.user
            visitor.save(update_fields=['user'])

        # 6. Populate location on first visit, otherwise bump count
        if created:
            self._geo(visitor, ip)
        else:
            Visitor.objects.filter(pk=visitor.pk).update(
                visit_count=F('visit_count') + 1,
                last_visit=timezone.now(),
            )

        # 7. Measure response time
        t0 = time.time()
        response = self.get_response(request)
        elapsed = int((time.time() - t0) * 1000)

        # 8. Log the page view
        PageView.objects.create(
            visitor=visitor,
            path=request.path[:500],
            method=request.method,
            status_code=response.status_code,
            response_time_ms=elapsed,
        )

        return response


    def _geo(self, visitor, ip):
        if not self.geoip_reader or not ip:
            return
        try:
            rec = self.geoip_reader.city(ip)
            visitor.location = {
                'country': rec.country.name,
                'country_code': rec.country.iso_code,
                'city': rec.city.name,
                'postal_code': rec.postal.code,
                'latitude': rec.location.latitude,
                'longitude': rec.location.longitude,
            }
            visitor.save(update_fields=['location'])
        except (geoip2.errors.AddressNotFoundError,
                geoip2.errors.GeoIP2Error, ValueError):
            pass

    def _get_ip(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        xri = request.META.get('HTTP_X_REAL_IP')
        if xri:
            return xri.strip()
        return request.META.get('REMOTE_ADDR')
