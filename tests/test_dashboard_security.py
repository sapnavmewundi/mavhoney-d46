#!/usr/bin/env python3
"""
Dashboard Security Tests — covers security headers, auth, session validation,
HMAC signing, config integrity, and request limits.
"""

import os
import sys
import json
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Must set env before importing app
os.environ.setdefault('HONEYPOT_ENV', 'test')


@pytest.fixture
def app():
    """Create a test Flask app."""
    from dashboard.app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    return flask_app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def auth_client(app, client):
    """Create an authenticated test client (bypass TOTP)."""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = __import__('time').time()
    return client


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Security Headers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSecurityHeaders:
    """Verify all security headers are present on responses."""

    def test_hsts_header(self, auth_client):
        resp = auth_client.get('/api/health')
        assert 'Strict-Transport-Security' in resp.headers
        assert 'max-age=31536000' in resp.headers['Strict-Transport-Security']

    def test_csp_header(self, auth_client):
        resp = auth_client.get('/api/health')
        assert 'Content-Security-Policy' in resp.headers
        csp = resp.headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert "script-src" in csp

    def test_x_frame_options(self, auth_client):
        resp = auth_client.get('/api/health')
        assert resp.headers.get('X-Frame-Options') == 'DENY'

    def test_x_content_type_options(self, auth_client):
        resp = auth_client.get('/api/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_x_xss_protection(self, auth_client):
        resp = auth_client.get('/api/health')
        assert resp.headers.get('X-XSS-Protection') == '1; mode=block'

    def test_referrer_policy(self, auth_client):
        resp = auth_client.get('/api/health')
        assert 'strict-origin' in resp.headers.get('Referrer-Policy', '')

    def test_permissions_policy(self, auth_client):
        resp = auth_client.get('/api/health')
        assert 'Permissions-Policy' in resp.headers

    def test_cache_control_on_api(self, auth_client):
        resp = auth_client.get('/api/health')
        assert 'private' in resp.headers.get('Cache-Control', '')

    def test_cache_control_no_store_on_login(self, client):
        resp = client.get('/login')
        assert 'no-store' in resp.headers.get('Cache-Control', '')


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Authentication
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAuthentication:
    """Verify auth enforcement on protected routes."""

    def test_unauthenticated_redirect(self, client):
        """Protected routes should redirect to login."""
        resp = client.get('/api/events')
        assert resp.status_code == 302
        assert '/login' in resp.headers.get('Location', '')

    def test_unauthenticated_stats(self, client):
        resp = client.get('/api/stats')
        assert resp.status_code == 302

    def test_authenticated_access(self, auth_client):
        """Authenticated client should get 200."""
        resp = auth_client.get('/api/health')
        assert resp.status_code == 200

    def test_session_expiry(self, app, client):
        """Expired sessions should redirect to login."""
        with client.session_transaction() as sess:
            sess['authenticated'] = True
            sess['login_time'] = 0  # expired (epoch time)
        resp = client.get('/api/events')
        assert resp.status_code == 302


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Session ID Validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSessionIDValidation:
    """Verify session ID path traversal prevention."""

    def test_replay_valid_session_id(self, auth_client):
        resp = auth_client.get('/api/sessions/abc123/replay')
        # 404 is fine (session may not exist) — but NOT 400
        assert resp.status_code in (200, 404)

    def test_replay_rejects_path_traversal(self, auth_client):
        # Flask resolves ../ at routing level (404), so our regex catches
        # characters that could slip through in other frameworks
        resp = auth_client.get('/api/sessions/../../etc/passwd/replay')
        assert resp.status_code in (400, 404)  # blocked at either layer

    def test_verify_rejects_path_traversal(self, auth_client):
        resp = auth_client.get('/api/sessions/../../../etc/passwd/verify')
        assert resp.status_code in (400, 404)  # blocked at either layer

    def test_replay_rejects_special_chars(self, auth_client):
        """Session IDs with shell metacharacters should be rejected."""
        resp = auth_client.get('/api/sessions/test%3Brm%20-rf/replay')
        assert resp.status_code == 400

    def test_verify_rejects_special_chars(self, auth_client):
        """Session IDs with dots/colons should be rejected."""
        resp = auth_client.get('/api/sessions/test..passwd/verify')
        assert resp.status_code == 400

    def test_verify_accepts_hyphens_underscores(self, auth_client):
        resp = auth_client.get('/api/sessions/session_abc-123/verify')
        assert resp.status_code in (200, 404)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HMAC Signing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestHMACSigning:
    """Verify HMAC is present on STIX exports."""

    def test_stix_export_has_hmac_header(self, auth_client):
        resp = auth_client.get('/api/stix_export')
        assert resp.status_code == 200
        assert 'X-HMAC-SHA256' in resp.headers
        hmac_val = resp.headers['X-HMAC-SHA256']
        assert len(hmac_val) == 64  # SHA256 hex digest

    def test_stix_export_has_signed_at(self, auth_client):
        resp = auth_client.get('/api/stix_export')
        assert 'X-Signed-At' in resp.headers

    def test_hmac_exposed_in_cors(self, auth_client):
        resp = auth_client.get('/api/stix_export')
        exposed = resp.headers.get('Access-Control-Expose-Headers', '')
        assert 'X-HMAC-SHA256' in exposed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Config Integrity
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestConfigIntegrity:
    """Verify config checksum is working."""

    def test_health_has_config_integrity(self, auth_client):
        resp = auth_client.get('/api/health')
        data = resp.get_json()
        assert 'config_integrity' in data
        assert data['config_integrity']['status'] in ('VERIFIED', 'TAMPERED')

    def test_system_status_returns_200(self, auth_client):
        resp = auth_client.get('/api/system/status')
        assert resp.status_code == 200


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Request Size Limiting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRequestLimits:
    """Verify request size limits are enforced."""

    def test_max_content_length_set(self, app):
        assert app.config['MAX_CONTENT_LENGTH'] == 1 * 1024 * 1024


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Cookie Security
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCookieSecurity:
    """Verify cookie security settings."""

    def test_httponly_cookies(self, app):
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True

    def test_samesite_cookies(self, app):
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dataset Endpoint Security
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDatasetSecurity:
    """Verify dataset endpoints require auth and block traversal."""

    def test_datasets_list_requires_auth(self, client):
        """Unauthenticated request to /api/datasets should redirect."""
        resp = client.get('/api/datasets')
        assert resp.status_code == 302
        assert '/login' in resp.headers.get('Location', '')

    def test_dataset_download_requires_auth(self, client):
        """Unauthenticated request to download should redirect."""
        resp = client.get('/api/dataset/download/test.csv')
        assert resp.status_code == 302
        assert '/login' in resp.headers.get('Location', '')

    def test_dataset_download_blocks_path_traversal(self, auth_client):
        """Path traversal in filename should return 400."""
        resp = auth_client.get('/api/dataset/download/..%2F..%2Fetc%2Fpasswd')
        assert resp.status_code in (400, 404)

