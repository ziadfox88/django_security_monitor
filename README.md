# 🛡️ django-security-monitor

A plug-and-play **SIEM (Security Information & Event Management)** library for Django.
Monitor threats, detect attacks, score IPs, and visualize everything in a
beautiful dark-mode dashboard — all from inside your Django project.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square)
![Django](https://img.shields.io/badge/Django-4.x%20%7C%205.x-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Redis](https://img.shields.io/badge/Redis-Optional-red?style=flat-square)
![Celery](https://img.shields.io/badge/Celery-Optional-orange?style=flat-square)

---

## 📋 Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Dashboard & URLs](#-dashboard--urls)
- [How Threat Scoring Works](#-how-threat-scoring-works)
- [Redis Support](#-redis-support)
- [Celery Support](#-celery-support)
- [GeoIP Setup](#-geoip-setup)
- [Models Reference](#-models-reference)
- [Middleware Reference](#-middleware-reference)
- [Security Settings Reference](#-security-settings-reference)
- [Management Commands](#-management-commands)
- [FAQ](#-faq)
- [License](#-license)


---

## ✨ Features

| Category            | Feature                                                      |
| ------------------- | ------------------------------------------------------------ |
| 🔍 **Detection**    | SQL Injection, XSS, Path Traversal, Scanner User-Agents      |
| 🪤 **Honeypot**     | Configurable trap URLs — only bots/scanners trigger them     |
| 🔑 **Auth**         | Brute-force login detection with per-IP failure counting     |
| 📊 **Scoring**      | Per-IP threat score with sigmoid hack-probability (0–100%)   |
| 🔒 **Blocking**     | Manual block/unblock + optional auto-block by threshold      |
| ✅ **Whitelist**    | Trusted IPs skip all detection                               |
| 🌍 **GeoIP**        | City-level geolocation via MaxMind GeoLite2 (optional)       |
| 📈 **Dashboard**    | Dark-mode SIEM UI with live feed, charts, IP drilldown       |
| ⚡ **Redis**        | Rate-limiting via Redis cache when available (auto-detected) |
| 🌿 **Celery**       | Score decay, event cleanup, email alerts (auto-detected)     |
| 🧩 **Configurable** | All thresholds, paths, and weights set in `settings.py`      |

---

## 📸 Screenshots

> Dashboard · Events Log · Threat IPs · IP Detail

<!-- ┌─────────────────────────────────────────────────────────────┐
│ 🛡 SIEM Monitor 📊 Security Dashboard ● Live │
├──────────┬──────────────────────────────────────────────────┤
│ Overview │ Events Today Critical Blocked IPs Threats │
│ Dashboard│ 142 23 7 14 │
│ ├──────────────────────────────────────────────────┤
│ Security │ [Event Types Chart] [Timeline Chart] │
│ Events ├──────────────────────────────────────────────────┤
│ Threats │ ⚡ Live Feed 🎯 Top Threat IPs │
│ │ 12:03 192.168.1.1 ... 1.2.3.4 ████░ 87% │
│ Traffic │ 12:02 45.33.32.156 ... 45.33.32 ██░░ 43% │
│ Visitors │ ... ... │
└──────────┴──────────────────────────────────────────────────┘ -->

![alt text](screenshots/Screenshot%202026-03-19%20001858.png)
![alt text](screenshots/Screenshot%202026-03-19%20003955.png)
![alt text](screenshots/Screenshot%202026-03-19%20004010.png)
![alt text](screenshots/Screenshot%202026-03-19%20004050.png)
![alt text](screenshots/Screenshot%202026-03-19%20004121.png)

---

## 📦 Requirements

- Python **3.9+**
- Django **4.0+**
- `geoip2` _(optional — for geolocation)_
- `redis` / `django-redis` _(optional — for fast rate limiting)_
- `celery` _(optional — for background tasks)_

---

## 🔧 Installation

######################################################################

### 1. Copy the app into your project

```bash
# Clone or download, then copy the folder
cp -r django_security_monitor/ /your/project/
##########################################################################
2. Install dependencies
# Required
pip install django

# Optional but recommended
pip install geoip2          # geolocation
pip install django-redis    # Redis rate limiting
pip install celery          # background tasks

###############################################################
3. Add to INSTALLED_APPS
# settings.py
INSTALLED_APPS = [
    ...
    'django_security_monitor',
]
##################################################################
4. Add middleware
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django_security_monitor.middleware.SecurityMonitorMiddleware',  # ← before sessions
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_security_monitor.middleware.VisitorTrackingMiddleware',  # ← after auth
    ...
]
#############################################################################
5. Add URLs
# urls.py (main project)
from django.urls import path, include

urlpatterns = [
    ...
    path('security-monitor/', include('django_security_monitor.urls')),
]
####################################################################################
6. Run migrations
python manage.py makemigrations django_security_monitor
python manage.py migrate
#######################################################################################
7. Visit the dashboard
http://yoursite.com/security-monitor/

### NOTE
⚠️ Only superusers can access the dashboard by default.


###############################################################################
⚡ Quick Start
Minimal settings.py addition to get running immediately:

SECURITY_MONITOR = {
    'BLOCK_THRESHOLD': 50,
    'AUTO_BLOCK': False,
    'ALERT_EMAIL': 'admin@yoursite.com',
}
That's it. Detection, scoring, and the dashboard are active.

#######################################################################
⚙️ Configuration
All configuration lives under the SECURITY_MONITOR dict in your settings.py.
Every key is optional — defaults are used for anything you omit.

SECURITY_MONITOR = {

    # ── Access Control ──────────────────────────────────────────
    # List of usernames who can access the dashboard.
    # Leave empty to allow superusers only.
    'ALLOWED_USERS': [],

    # ── Threat Detection ────────────────────────────────────────
    # URL fragments that trigger a "suspicious path" event.
    'SUSPICIOUS_PATHS': [
        '.env', '.git', '.svn', 'wp-admin', 'wp-login',
        'phpMyAdmin', '/etc/passwd', '/etc/shadow',
        '.htaccess', '.htpasswd', 'web.config', '.DS_Store',
        'xmlrpc.php', '/proc/', 'backup.sql',
    ],

    # File extensions that trigger a "sensitive file" event.
    'SENSITIVE_EXTENSIONS': [
        '.env', '.sql', '.bak', '.backup', '.dump',
        '.config', '.conf', '.key', '.pem',
        '.p12', '.pfx', '.log', '.db', '.sqlite3',
    ],

    # URLs that act as traps. Any access = instant high threat score.
    # Real users never visit these; only bots/scanners do.
    'HONEYPOT_PATHS': [
        '/wp-login.php', '/wp-admin/', '/.env',
        '/.git/config', '/phpinfo.php', '/shell.php',
        '/c99.php', '/r57.php', '/admin.php',
    ],

    # ── Auto-Blocking ────────────────────────────────────────────
    # Set to False to track threats without ever auto-blocking.
    'AUTO_BLOCK': True,

    # Threat score at which an IP is automatically blocked.
    'BLOCK_THRESHOLD': 50,

    # ── Rate Limiting ────────────────────────────────────────────
    # Max requests from one IP within RATE_LIMIT_WINDOW seconds.
    'RATE_LIMIT': 200,
    'RATE_LIMIT_WINDOW': 60,

    # ── Brute Force Detection ────────────────────────────────────
    # Failed logins before escalating to "brute_force" event.
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_ATTEMPT_WINDOW': 300,   # 5 minutes

    # ── Optional Integrations ────────────────────────────────────
    # None  = auto-detect from your CACHES / installed packages
    # True  = force enable (raises error if not installed)
    # False = force disable
    'USE_REDIS': None,
    'USE_CELERY': None,

    # ── Logging ──────────────────────────────────────────────────
    'LOG_404': True,    # Log 404 responses as low-severity events
    'LOG_500': True,    # Log 500 responses as low-severity events

    # How many days to keep events before cleanup (Celery required)
    'EVENT_RETENTION_DAYS': 90,

    # Email address for critical-event alerts (Celery required)
    'ALERT_EMAIL': None,

    # ── Paths ────────────────────────────────────────────────────
    # Paths that are completely skipped by both middlewares.
    'EXCLUDE_PATHS': ['/static/', '/media/'],

    # Whitelist cache refresh interval (seconds)
    'WHITELIST_CACHE_TTL': 300,

    # ── Scoring Weights ──────────────────────────────────────────
    # How many threat score points each event type adds.
    'THREAT_SCORE_WEIGHTS': {
        'suspicious_path':  15,
        'sensitive_file':   20,
        'rate_limit':       10,
        'auth_failure':      5,
        'brute_force':      25,
        'sql_injection':    30,
        'xss_attempt':      25,
        'path_traversal':   35,
        'scanner':          20,
        'honeypot':         40,
        '404':               3,
        '500':               2,
        'csrf_failure':     15,
    },
}


######################################################################
🖥️ Dashboard & URLs
URL	View	Description
/security-monitor/	Dashboard	Overview, charts, live feed
/security-monitor/events/	Events Log	Filterable security event list
/security-monitor/threats/	Threat IPs	IP scores with hack probability
/security-monitor/threats/<ip>/	IP Detail	Full drilldown for one IP
/security-monitor/visitors/	Visitors	All tracked visitors
/security-monitor/block/<ip>/	POST	Block an IP
/security-monitor/unblock/<ip>/	POST	Unblock an IP
/security-monitor/whitelist/<ip>/	POST	Whitelist (trust) an IP
/security-monitor/api/live-events/	JSON	Real-time event feed
/security-monitor/api/stats/	JSON	Live stat card data


########################################################################
Changing the dashboard URL prefix
# urls.py
path('my-custom-path/', include('django_security_monitor.urls')),

###########################################################################
Granting non-superuser access
SECURITY_MONITOR = {
    'ALLOWED_USERS': ['alice', 'security_team_member'],
}

#############################################################################
🧮 How Threat Scoring Works
Every suspicious action from an IP adds points to its Threat Score.
The score is converted to a Hack Probability (0–100%) using a sigmoid curve:

Probability = 100 / (1 + e^(-0.08 × (score - 40)))

############################################################################
Risk Levels
Score	Risk Level	Hack Probability
0–19	🟢 Low	         ~5%
20–49	🟡 Medium	     ~18–45%
50–79	🟠 High         ~50–83%
80+	🔴 Critical	        ~84–99%

###########################################################################
Score Examples

IP hits /.env                  → +40  (honeypot)
IP sends SQL injection payload → +30
IP fails login 5 times         → +25  (brute_force escalation)
IP scans 200+ paths in 60s     → +10  (rate limit)
Total: 105 → Probability: ~98% → Auto-blocked ✅


###########################################################################

Score Decay (Celery required)
Scores automatically decay by 10% every hour for non-blocked IPs,
so old benign misses don't permanently flag legitimate users.
###############################################################################
⚡ Redis Support
When your project uses Redis as the Django cache backend,
django-security-monitor automatically uses it for fast, atomic rate limiting.

# settings.py — example Redis cache setup
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
If Redis is not configured, rate limiting falls back to database
counting automatically — no configuration needed.

To force-disable Redis even if it's available:

SECURITY_MONITOR = {
    'USE_REDIS': False,
}

########################################################################################
🌿 Celery Support
When Celery is installed and configured, three periodic tasks become available:

Task	                                        Schedule	                                    Description
security_monitor.cleanup_old_events	            Daily 3am	                            Delete events older than EVENT_RETENTION_DAYS
security_monitor.decay_threat_scores	        Every hour	                            Reduce scores by 10% for inactive IPs
security_monitor.send_critical_alert	        On trigger	                            Email admin on critical event



Register the beat schedule:
# settings.py
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'siem-cleanup': {
        'task': 'security_monitor.cleanup_old_events',
        'schedule': crontab(hour=3, minute=0),
    },
    'siem-decay': {
        'task': 'security_monitor.decay_threat_scores',
        'schedule': crontab(minute=0),
    },
}
If Celery is not installed, all tasks are silently skipped — nothing breaks.

########################################################################################
🌍 GeoIP Setup
Geolocation enriches visitor and threat records with country, city, and coordinates.

1. Get the free MaxMind GeoLite2 database
Register at maxmind.com
and download GeoLite2-City.mmdb.
2. Place the file
your_project/
└── geoip/
    └── GeoLite2-City.mmdb   ← here

3. Configure the path
# settings.py
GEOIP_PATH = BASE_DIR / 'geoip'

If the file is missing, geolocation is silently skipped — the app
still works fully without it.


##############################################################################################

🗄️ Models Reference
SecurityEvent
Logs every detected threat or suspicious action.

| Field              | Type          | Description                           |
| ------------------ | ------------- | ------------------------------------- |
| ip_address         | CharField     | Source IP                             |
| event_type         | CharField     | One of 15 event types                 |
| severity           | CharField     | info / low / medium / high / critical |
| path               | CharField     | Requested path                        |
| method             | CharField     | HTTP method                           |
| user_agent         | CharField     | Browser/bot UA string                 |
| payload            | TextField     | Captured suspicious payload           |
| threat_score_delta | FloatField    | Points added by this event            |
| timestamp          | DateTimeField | When it happened                      |

############################################################################################
ThreatScore
Aggregated per-IP threat intelligence.

| Field            | Type         | Description                     |
| ---------------- | ------------ | ------------------------------- |
| ip_address       | CharField    | Unique IP                       |
| score            | FloatField   | Cumulative threat score         |
| hack_probability | property     | 0–100% sigmoid probability      |
| risk_level       | property     | low / medium / high / critical  |
| is_blocked       | BooleanField | Whether IP is currently blocked |
| block_reason     | CharField    | Why it was blocked              |
| location         | JSONField    | GeoIP data                      |

###############################################################################
LoginAttempt
Raw log of every login success and failure.

| Field      | Type          | Description             |
| ---------- | ------------- | ----------------------- |
| ip_address | CharField     | Source IP               |
| username   | CharField     | Attempted username      |
| success    | BooleanField  | Whether login succeeded |
| timestamp  | DateTimeField | When it happened        |

############################################################################
HoneypotHit
Every access to a configured honeypot URL.

| Field      | Type          | Description            |
| ---------- | ------------- | ---------------------- |
| ip_address | CharField     | Source IP              |
| path       | CharField     | Honeypot path accessed |
| headers    | JSONField     | Full request headers   |
| timestamp  | DateTimeField | When it happened       |

########################################################################
IPWhitelist
Trusted IPs that bypass all detection.

| Field      | Type       | Description             |
| ---------- | ---------- | ----------------------- |
| ip_address | CharField  | Trusted IP              |
| added_by   | ForeignKey | Admin user who added it |
| reason     | CharField  | Why it's trusted        |

########################################################################
Visitor
Session-based visitor tracking.
| Field       | Type                 | Description                   |
| ----------- | -------------------- | ----------------------------- |
| session_key | CharField            | Django session key            |
| ip_address  | CharField            | Visitor IP                    |
| visit_count | PositiveIntegerField | Total visits                  |
| location    | JSONField            | GeoIP enrichment              |
| user        | ForeignKey           | Linked auth user if logged in |


########################################################################
🔌 Middleware Reference
SecurityMonitorMiddleware
Place before SessionMiddleware. Runs security analysis on every request.

Detects:

SQL Injection in query strings

XSS patterns in query strings

Path traversal sequences (../, %2e%2e%2f, etc.)

Scanner user-agents (Nikto, sqlmap, Nmap, Burp Suite, etc.)

Suspicious and sensitive paths

Honeypot accesses

Rate limit violations

Blocked IP re-entry attempts

VisitorTrackingMiddleware
Place after AuthenticationMiddleware. Tracks every unique session.

Records:

Session → IP → User linkage

Visit counts and timestamps

GeoIP location on first visit

Per-request page views with response time and status code

########################################################################
SECURITY_MONITOR = {
    # Who can see the dashboard
    'ALLOWED_USERS': [],           # [] = superuser only

    # Blocking
    'AUTO_BLOCK': False,            # False = monitor only, never block
    'BLOCK_THRESHOLD': 50,         # score needed for auto-block

    # Rate limiting (per IP)
    'RATE_LIMIT': 200,             # requests allowed
    'RATE_LIMIT_WINDOW': 60,       # per this many seconds

    # Brute force
    'MAX_LOGIN_ATTEMPTS': 5,       # failures before brute_force event
    'LOGIN_ATTEMPT_WINDOW': 300,   # within this window (seconds)
}


########################################################################
❓ FAQ
Q: Does this replace Django's built-in security middleware?
No. It works alongside django.middleware.security.SecurityMiddleware.
Place Django's security middleware first, then this one.

Q: Will it slow down my site?
Minimal impact. DB writes are fast single-row operations.
With Redis enabled, rate limiting is in-memory with zero DB queries.
The EXCLUDE_PATHS setting lets you skip static/media entirely.

Q: What if I don't have GeoIP?
Everything works normally. IP location fields will simply be empty.

Q: Can I use this with a custom user model?
Yes. All user foreign keys use settings.AUTH_USER_MODEL.

Q: How do I stop a legitimate IP from being scored?
Add it to the whitelist via the dashboard or Django admin.
Whitelisted IPs skip all middleware checks entirely.

Q: Can I add my own event types?
Yes — call SecurityEvent.objects.create(...) directly from anywhere
in your code with any event_type string you choose.

########################################################################
📄 License
MIT License — free to use, modify, and distribute.

##################################################################
👤 Author
Built by Ziad Ali
```
