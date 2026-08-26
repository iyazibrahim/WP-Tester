import os
import unittest

# Avoid starting the monitoring background thread during unit tests.
os.environ.setdefault("DP_DISABLE_MONITORING_THREAD", "1")

from app import app
from docker.gunicorn_logging import HealthCheckFilter
from lib.branding import SERVICE_SLUG


class HealthEndpointTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_returns_ok_without_auth(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("status"), "ok")
        self.assertEqual(payload.get("service"), SERVICE_SLUG)

    def test_health_is_not_redirected_to_login(self):
        response = self.client.get("/health", follow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)


class HealthCheckFilterTest(unittest.TestCase):
    def test_filter_drops_health_probe_lines(self):
        filt = HealthCheckFilter()

        class _Record:
            def __init__(self, message: str):
                self._message = message

            def getMessage(self) -> str:
                return self._message

        self.assertFalse(filt.filter(_Record('127.0.0.1 - - [..] "GET /health HTTP/1.1" 200')))
        self.assertTrue(filt.filter(_Record('127.0.0.1 - - [..] "GET /api/auth/status HTTP/1.1" 200')))


if __name__ == "__main__":
    unittest.main()
