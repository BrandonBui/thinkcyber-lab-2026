# ThinkCyber Store - E-Commerce Security Training Web Application

ThinkCyber Store is a clean, modern e-commerce web application branded for the **ThinkCyber Foundation**, designed as an educational baseline for cybersecurity classes, web security workshops, and hands-on lab demonstrations.

Built with **Python (Flask)**, **SQLite**, and **Tailwind CSS**, it features realistic store flows including a product catalog, user authentication, shopping cart, promotional discount redemption, product reviews, and customer profile management.

---

## 🛠️ Architecture & Tech Stack

* **Backend Framework**: Python 3 (Flask)
* **Database**: SQLite3 (zero-dependency, file-based database)
* **Frontend**: HTML5, Jinja2 templates, styled with Tailwind CSS (CDN)
* **Session & Auth**: Flask signed client-side sessions with Werkzeug password hashing
* **Deployment**: Dockerfile and Docker Compose with Gunicorn

---

## 📁 Project Directory Structure

```text
ctf-ttx-exercise/
├── Dockerfile                  # Production container definition
├── docker-compose.yml          # Single-command local container orchestration
├── requirements.txt            # Python dependencies (Flask, Werkzeug, Gunicorn)
├── README.md                   # Setup guide and educational documentation
├── cybermart.db                # SQLite database (auto-generated on startup)
├── src/
│   ├── __init__.py
│   ├── app.py                  # Core Flask application, routing, and controllers
│   └── db.py                   # Schema initialization, connections, and seed records
├── templates/
│   ├── base.html               # Common layout, Tailwind CDN, navigation, flash alerts
│   ├── gate.html               # Site-wide event access gatekeeper page
│   ├── index.html              # Product catalog, category filter, and search
│   ├── product.html            # Product details, reviews list, and review form
│   ├── cart.html               # Shopping cart, item quantity adjuster, promo codes
│   ├── checkout.html           # Shipping address entry and simulated order placement
│   ├── orders.html             # Customer order history
│   ├── order_detail.html       # Itemized order receipt with ownership controls
│   ├── profile.html            # User account profile and settings editor
│   ├── login.html              # User login form with test credential guide
│   └── register.html           # User account registration
├── static/                     # Static assets directory
└── tests/
    └── test_app.py             # Functional and security unit tests
```

---

## 🚀 Quickstart Guide

### Option 1: Running with Docker (Recommended)

To start the application with a single command:

```bash
docker compose up --build
```

The application will be accessible at: **`http://localhost:8000`**

To stop the container:
```bash
docker compose down
```

---

### Option 2: Running Locally with Python Virtual Environment

1. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install requirements**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database**:
   ```bash
   python3 -m src.db
   ```

4. **Start the Flask development server**:
   ```bash
   python3 -m src.app
   ```

5. Open your browser and navigate to **`http://localhost:8000`**.

---

### Running the Test Suite

A comprehensive test suite is included in `tests/test_app.py` covering authentication, catalog views, promo codes, authorization barriers, and output escaping:

```bash
python3 -m unittest tests/test_app.py
```

---

## 👥 Event Access & Pre-Seeded Accounts

### 🎟️ Event Gatekeeper Passcode
To restrict cloud-hosted environments to attendees, all requests are intercepted until the event passcode is supplied:

* **Default Event Passcode**: `THINKCYBERDAY2026!`
* **Session Lifetime**: 24 hours (stored in encrypted client session cookie)
* **Customization**: Set the `EVENT_PASSWORD` environment variable in `docker-compose.yml` or your cloud deployment service.

### User Accounts

| Username | Password | Role | Purpose |
| :--- | :--- | :--- | :--- |
| `student` | `student123` | User | Default standard student test user |
| `victim_user` | `P@ssword123` | User | Customer account with existing orders & address |
| `admin` | `AdminPass2026!` | Admin | Administrative account with elevated privileges |

### Promotional Codes

| Promo Code | Discount | Description |
| :--- | :--- | :--- |
| `WELCOME10` | 10% | General new customer discount |
| `CYBERSALE25` | 25% | Seasonal promotional discount |
| `STAFF50` | 50% | Internal staff employee discount |

---

## 🛡️ Secure Design & Implementation Highlights

This codebase adheres to secure coding standards across all critical touchpoints:

### 1. SQL Injection Defense (Parameterized Queries)
* All database interactions in [`src/app.py`](file:///Users/brandonbui/Programming-Projects/ctf-ttx-exercise/src/app.py) and [`src/db.py`](file:///Users/brandonbui/Programming-Projects/ctf-ttx-exercise/src/db.py) use parameterized queries (e.g., `cursor.execute("SELECT * FROM promo_codes WHERE code = ?", (code,))`).
* User inputs are separated from query logic at the driver level, ensuring untrusted strings cannot alter SQL syntax.

### 2. Cross-Site Scripting (XSS) Defense (Context-Aware Output Escaping)
* All user-submitted content (such as product reviews, names, and comments) is rendered using Jinja2's default automatic escaping.
* Characters such as `<`, `>`, `&`, `"`, and `'` are automatically converted to their respective HTML entities before rendering in [`templates/product.html`](file:///Users/brandonbui/Programming-Projects/ctf-ttx-exercise/templates/product.html).

### 3. Broken Object Level Authorization (BOLA / IDOR)
* Order receipt lookups at `/orders/<order_id>` enforce that the requested record belongs to the logged-in user:
  ```python
  if order["user_id"] != session["user_id"] and session.get("role") != "admin":
      abort(403)
  ```
* **Lab Vulnerability (IDOR Challenge)**: The user profile route (`/profile?id=<user_id>`) retrieves and updates account records directly based on the `id` URL query parameter rather than restricting scope strictly to `session["user_id"]`, enabling students to identify and exploit an IDOR vulnerability against `victim_user`.

### 4. Cryptographic Password Hashing
* User credentials are encrypted at rest using Werkzeug's secure hashing functions (`generate_password_hash` with PBKDF2 / scrypt), ensuring raw passwords are never stored in plaintext.
