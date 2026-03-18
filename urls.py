from django.urls import path
from . import views

app_name = 'security_monitor'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('events/', views.events_list, name='events'),
    path('threats/', views.threats_list, name='threats'),
    path('threats/<str:ip_address>/', views.ip_detail, name='ip_detail'),
    path('visitors/', views.visitors_list, name='visitors'),

    # Actions
    path('block/<str:ip_address>/', views.block_ip, name='block_ip'),
    path('unblock/<str:ip_address>/', views.unblock_ip, name='unblock_ip'),
    path('whitelist/<str:ip_address>/', views.whitelist_ip, name='whitelist_ip'),
    path('whitelist/<str:ip_address>/remove/', views.remove_whitelist, name='remove_whitelist'),
    path('events/<int:event_id>/delete/', views.delete_event, name='delete_event'),

    # JSON APIs
    path('api/live-events/', views.live_events, name='live_events'),
    path('api/stats/', views.stats_api, name='stats_api'),
]
