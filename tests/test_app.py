"""Functional and security tests for CyberMart.
Verifies application functionality, access control, and secure defaults.
"""

import os
import unittest
import tempfile
import sqlite3

# Set test database path before importing app
os.environ["DATABASE_PATH"] = ":memory:"
os.environ["EVENT_PASSWORD"] = "TEST_EVENT_PASS_2026"

from src.app import app
from src.db import init_db, get_db_connection


class CyberMartTestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for the database
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.environ["DATABASE_PATH"] = self.db_path

        # Reconfigure db path in module
        import src.db as db_mod
        db_mod.DB_PATH = self.db_path

        init_db()

        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret"
        self.client = app.test_client()

        # Unlock the event gate by default for standard functional tests
        with self.client.session_transaction() as sess:
            sess["event_authorized"] = True

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def login(self, username, password):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def logout(self):
        return self.client.get("/logout", follow_redirects=True)

    def test_event_gatekeeper_flow(self):
        """Unauthenticated clients must pass the event gate before accessing any route."""
        # Fresh test client without session cookies
        gate_client = app.test_client()

        # Attempt to access catalog without event code -> should redirect to /gate
        res = gate_client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers["Location"].startswith("/gate"))

        # Submit wrong code
        res_fail = gate_client.post(
            "/gate",
            data={"access_code": "WRONG_CODE"},
            follow_redirects=True,
        )
        self.assertIn(b"Invalid event access code", res_fail.data)

        # Submit correct event code
        res_success = gate_client.post(
            "/gate",
            data={"access_code": "TEST_EVENT_PASS_2026"},
            follow_redirects=True,
        )
        self.assertEqual(res_success.status_code, 200)
        self.assertIn(b"Event access verified", res_success.data)

        # Subsequent requests work without prompting again
        res_catalog = gate_client.get("/")
        self.assertEqual(res_catalog.status_code, 200)
        self.assertIn(b"Hardware Security Key", res_catalog.data)

    def test_catalog_loads(self):
        """Catalog page displays seed products and categories."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hardware Security Key", response.data)
        self.assertIn(b"Faraday Signal-Blocking Bag", response.data)

    def test_product_detail(self):
        """Product detail page loads with details and reviews."""
        response = self.client.get("/product/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hardware Security Key FIDO2", response.data)
        self.assertIn(b"Customer Reviews", response.data)

    def test_authentication(self):
        """Valid and invalid logins work as expected and preserve event authorization."""
        # Invalid login
        res_fail = self.login("student", "wrong_password")
        self.assertIn(b"Invalid username or password", res_fail.data)

        # Valid login
        res_success = self.login("student", "student123")
        self.assertIn(b"Welcome back", res_success.data)
        self.assertIn(b"Morgan Chen", res_success.data)

        # Logout preserves event gate
        res_logout = self.logout()
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn(b"You have been signed out", res_logout.data)

    def test_cart_and_promo_code(self):
        """Items can be added to cart and valid promo codes applied."""
        # Add item to cart
        self.client.post("/cart/add", data={"product_id": 1, "quantity": 1})

        # Apply valid promo code
        res_promo = self.client.post("/cart/apply-promo", data={"code": "WELCOME10"}, follow_redirects=True)
        self.assertIn(b"10% discount applied", res_promo.data)

        # Inactive or bogus promo code
        res_invalid = self.client.post("/cart/apply-promo", data={"code": "NONEXISTENT"}, follow_redirects=True)
        self.assertIn(b"Invalid or expired promo code", res_invalid.data)

    def test_authorization_prevents_idor(self):
        """Users cannot access another user's order receipt (prevents IDOR)."""
        # Log in as 'student' (User ID: 3)
        self.login("student", "student123")

        # Order #1 belongs to 'victim_user' (User ID: 2)
        response = self.client.get("/orders/1")

        # Should be forbidden (403)
        self.assertEqual(response.status_code, 403)

        # Admin user (User ID: 1) should be permitted to view any order
        self.logout()
        self.login("admin", "AdminPass2026!")
        admin_response = self.client.get("/orders/1")
        self.assertEqual(admin_response.status_code, 200)
        self.assertIn(b"Order Receipt #1", admin_response.data)

    def test_stored_content_escaped(self):
        """Review comments containing HTML/script tags are properly escaped."""
        self.login("student", "student123")
        xss_string = "<script>alert('test')</script>"

        # Post review containing special characters
        self.client.post(
            "/product/1/review",
            data={"rating": 5, "comment": xss_string},
            follow_redirects=True,
        )

        # View product page
        res = self.client.get("/product/1")
        self.assertEqual(res.status_code, 200)

        # In HTML response, '<script>' should be escaped to '&lt;script&gt;'
        self.assertNotIn(b"<script>alert('test')</script>", res.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;test&#39;)&lt;/script&gt;", res.data)


    def test_profile_url_parameter_idor(self):
        """Profile route uses id from URL parameter, allowing access and modification via IDOR."""
        # Log in as 'student' (User ID: 3)
        self.login("student", "student123")

        # Access /profile without id -> redirects to /profile?id=3
        res_redirect = self.client.get("/profile", follow_redirects=False)
        self.assertEqual(res_redirect.status_code, 302)
        self.assertIn("id=3", res_redirect.headers["Location"])

        # Access student's profile via ?id=3
        res_student = self.client.get("/profile?id=3")
        self.assertEqual(res_student.status_code, 200)
        self.assertIn(b"Morgan Chen", res_student.data)

        # Access victim_user's profile via ?id=2 (IDOR)
        res_victim = self.client.get("/profile?id=2")
        self.assertEqual(res_victim.status_code, 200)
        self.assertIn(b"Alex Rivera", res_victim.data)
        self.assertIn(b"456 Redwood Lane", res_victim.data)

        # Modify victim_user's profile via POST to ?id=2
        res_post = self.client.post(
            "/profile?id=2",
            data={
                "full_name": "Alex Rivera Compromised",
                "email": "compromised@cybermart.local",
                "phone": "+1 (555) 000-1111",
                "address": "Attacker Address 123",
            },
            follow_redirects=True,
        )
        self.assertEqual(res_post.status_code, 200)
        self.assertIn(b"Alex Rivera Compromised", res_post.data)
        self.assertIn(b"Attacker Address 123", res_post.data)

        # Non-existent user returns 404
        res_404 = self.client.get("/profile?id=9999")
        self.assertEqual(res_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()

