from django.contrib import admin
from .models import (
    SecurityEvent, ThreatScore, LoginAttempt,
    IPWhitelist, HoneypotHit, Visitor, PageView,
)


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'ip_address', 'event_type', 'severity', 'path', 'threat_score_delta')
    list_filter = ('severity', 'event_type')
    search_fields = ('ip_address', 'path', 'user_agent')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(ThreatScore)
class ThreatScoreAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'score', 'risk_level', 'is_blocked', 'event_count', 'last_event')
    list_filter = ('is_blocked',)
    search_fields = ('ip_address',)
    readonly_fields = ('first_seen', 'last_event')
    actions = ['block_selected', 'unblock_selected']

    @admin.action(description='Block selected IPs')
    def block_selected(self, request, queryset):
        from django.utils import timezone
        queryset.update(
            is_blocked=True,
            blocked_at=timezone.now(),
            block_reason='Manually blocked via admin',
        )

    @admin.action(description='Unblock selected IPs')
    def unblock_selected(self, request, queryset):
        queryset.update(is_blocked=False, block_reason='', blocked_at=None)


@admin.register(IPWhitelist)
class IPWhitelistAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'added_by', 'reason', 'created_at')
    search_fields = ('ip_address',)


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'ip_address', 'username', 'success', 'user_agent')
    list_filter = ('success',)
    search_fields = ('ip_address', 'username')


@admin.register(HoneypotHit)
class HoneypotHitAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'ip_address', 'path', 'user_agent')
    search_fields = ('ip_address', 'path')


@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'user', 'visit_count', 'first_visit', 'last_visit')
    search_fields = ('ip_address',)
    readonly_fields = ('first_visit', 'last_visit')
