import math
from django.db import models
from django.conf import settings
from django.utils import timezone


class Visitor(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, null=True, blank=True
    )
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.CharField(max_length=45)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    first_visit = models.DateTimeField(auto_now_add=True)
    last_visit = models.DateTimeField(auto_now=True)
    visit_count = models.PositiveIntegerField(default=1)
    location = models.JSONField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['last_visit']),
        ]

    def __str__(self):
        return f"{self.ip_address} — {self.visit_count} visits"


class PageView(models.Model):
    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name='page_views')
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10, default='GET')
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]

    def __str__(self):
        return f"{self.visitor.ip_address} → {self.path}"


class SecurityEvent(models.Model):
    EVENT_TYPES = [
        ('suspicious_path', 'Suspicious Path'),
        ('sensitive_file', 'Sensitive File Access'),
        ('brute_force', 'Brute Force Attack'),
        ('rate_limit', 'Rate Limit Exceeded'),
        ('sql_injection', 'SQL Injection'),
        ('xss_attempt', 'XSS Attempt'),
        ('path_traversal', 'Path Traversal'),
        ('scanner', 'Security Scanner'),
        ('auth_failure', 'Auth Failure'),
        ('csrf_failure', 'CSRF Failure'),
        ('honeypot', 'Honeypot Triggered'),
        ('403', '403 Forbidden'),
        ('404', '404 Not Found'),
        ('500', '500 Server Error'),
        ('blocked_ip', 'Blocked IP Attempt'),
    ]
    SEVERITY = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    ip_address = models.CharField(max_length=45, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='security_events'
    )
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY, default='medium', db_index=True)
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10, default='GET')
    user_agent = models.CharField(max_length=500, blank=True)
    referer = models.CharField(max_length=500, blank=True)
    payload = models.TextField(blank=True)
    threat_score_delta = models.FloatField(default=0)
    extra_data = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.get_event_type_display()} — {self.ip_address}"


class ThreatScore(models.Model):
    ip_address = models.CharField(max_length=45, unique=True, db_index=True)
    score = models.FloatField(default=0, db_index=True)
    event_count = models.PositiveIntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_event = models.DateTimeField(auto_now=True)
    is_blocked = models.BooleanField(default=False, db_index=True)
    block_reason = models.CharField(max_length=255, blank=True)
    blocked_at = models.DateTimeField(null=True, blank=True)
    location = models.JSONField(blank=True, null=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-score']

    @property
    def risk_level(self):
        if self.score >= 80:
            return 'critical'
        if self.score >= 50:
            return 'high'
        if self.score >= 20:
            return 'medium'
        return 'low'

    @property
    def hack_probability(self):
        """Sigmoid curve: 0–100 probability this IP is malicious."""
        try:
            p = 100 / (1 + math.exp(-0.08 * (self.score - 40)))
            return round(min(100.0, max(0.0, p)), 1)
        except OverflowError:
            return 100.0

    def __str__(self):
        tag = 'BLOCKED' if self.is_blocked else self.risk_level.upper()
        return f"{self.ip_address} — Score: {self.score:.1f} [{tag}]"


class LoginAttempt(models.Model):
    ip_address = models.CharField(max_length=45, db_index=True)
    username = models.CharField(max_length=150)
    success = models.BooleanField(default=False)
    user_agent = models.CharField(max_length=500, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['username', 'timestamp']),
        ]

    def __str__(self):
        return f"{'OK' if self.success else 'FAIL'}: {self.username} @ {self.ip_address}"


class IPWhitelist(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True
    )
    reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Whitelisted: {self.ip_address}"


class HoneypotHit(models.Model):
    """Accesses to trap URLs — only scanners/bots hit these."""
    ip_address = models.CharField(max_length=45, db_index=True)
    path = models.CharField(max_length=500)
    user_agent = models.CharField(max_length=500, blank=True)
    headers = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Honeypot: {self.ip_address} → {self.path}"
