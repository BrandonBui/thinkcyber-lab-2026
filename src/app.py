"""CyberMart e-commerce web application.
Built with Flask, SQLite, and secure coding practices.
"""

import os
from datetime import timedelta
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

import json
from .db import get_db_connection, init_db
from .sast_data import FINDINGS, get_sast_stats

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
)

app.secret_key = os.environ.get("SECRET_KEY", "cybermart-insecure-dev-key-change-in-prod-2026")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
EVENT_PASSWORD = os.environ.get("EVENT_PASSWORD", "THINKCYBERDAY2026!")


@app.route("/robots.txt")
def robots_txt():
    """Tells search engine crawlers and bots not to index or crawl the exercise site."""
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}


@app.before_request
def require_event_access():
    """Restricts access across the entire application until the event password is provided."""
    # Allow static assets, gatekeeper endpoint, and robots.txt
    if request.endpoint in {"gate", "static", "robots_txt"} or request.path.startswith("/static/"):
        return None

    # Fast-fail scanner noise (e.g. /wp-admin, /.env, /.git) before touching templates or redirects
    if request.endpoint is None:
        abort(404)

    if not session.get("event_authorized"):
        return redirect(url_for("gate", next=request.path))


def login_required(f):
    """Decorator to enforce authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_global_data():
    """Provides common data to all templates (cart count, categories, auth state)."""
    # Skip database lookups for unauthenticated gate visits or static asset calls to save compute
    if not session.get("event_authorized") or request.endpoint in {"gate", "static", "robots_txt"}:
        return {
            "cart_count": 0,
            "current_user": None,
            "categories": [],
        }

    cart = session.get("cart", {})
    cart_count = sum(cart.values())

    current_user = None
    if "user_id" in session:
        conn = get_db_connection()
        user = conn.execute(
            "SELECT id, username, email, full_name, role FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
        conn.close()
        if user:
            current_user = dict(user)

    conn = get_db_connection()
    categories_rows = conn.execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
    conn.close()
    categories = [r["category"] for r in categories_rows]

    return {
        "cart_count": cart_count,
        "current_user": current_user,
        "categories": categories,
    }


# ==========================================
# Event Gatekeeper Route
# ==========================================

@app.route("/gate", methods=["GET", "POST"])
def gate():
    if session.get("event_authorized"):
        return redirect(url_for("index"))

    if request.method == "POST":
        access_code = request.form.get("access_code", "").strip()
        expected_code = os.environ.get("EVENT_PASSWORD", "THINKCYBERDAY2026!")

        if access_code == expected_code:
            session.permanent = True
            session["event_authorized"] = True
            flash("Event access verified. Welcome to ThinkCyber Store!", "success")

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("/gate"):
                return redirect(next_url)
            return redirect(url_for("index"))

        flash("Invalid event access code. Please check with your instructor.", "error")

    return render_template("gate.html")


# ==========================================
# Authentication Routes
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        # Secure: Parameterized query prevents SQL injection
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            event_auth = session.get("event_authorized", True)
            session.clear()
            session.permanent = True
            session["event_authorized"] = event_auth
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['full_name']}!", "success")

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("index"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not full_name or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html")

        conn = get_db_connection()
        # Secure: Parameterized check for existing username or email
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()

        if existing:
            conn.close()
            flash("Username or email already taken.", "error")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, email, full_name, role)
            VALUES (?, ?, ?, ?, 'user')
            """,
            (username, hashed_password, email, full_name),
        )
        new_user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        event_auth = session.get("event_authorized", True)
        session.clear()
        session.permanent = True
        session["event_authorized"] = event_auth
        session["user_id"] = new_user_id
        session["username"] = username
        session["role"] = "user"
        flash("Registration successful! Welcome to ThinkCyber Store.", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    event_auth = session.get("event_authorized", True)
    session.clear()
    session.permanent = True
    session["event_authorized"] = event_auth
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


# ==========================================
# Catalog & Product Routes
# ==========================================

@app.route("/")
def index():
    category = request.args.get("category", "").strip()
    query = request.args.get("q", "").strip()

    conn = get_db_connection()
    sql = "SELECT * FROM products WHERE 1=1"
    params = []

    # Secure: Dynamic queries constructed safely using parameter placeholders
    if category:
        sql += " AND category = ?"
        params.append(category)

    if query:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        search_pattern = f"%{query}%"
        params.extend([search_pattern, search_pattern])

    sql += " ORDER BY id DESC"
    products = conn.execute(sql, params).fetchall()
    conn.close()

    return render_template(
        "index.html",
        products=products,
        current_category=category,
        search_query=query,
    )


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute(
        "SELECT * FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()

    if not product:
        conn.close()
        abort(404)

    # Secure: Parameterized join query to fetch reviews and usernames
    reviews = conn.execute(
        """
        SELECT r.*, u.username, u.full_name
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = ?
        ORDER BY r.created_at DESC
        """,
        (product_id,),
    ).fetchall()
    conn.close()

    avg_rating = 0
    if reviews:
        avg_rating = round(sum(r["rating"] for r in reviews) / len(reviews), 1)

    return render_template(
        "product.html",
        product=product,
        reviews=reviews,
        avg_rating=avg_rating,
    )


@app.route("/product/<int:product_id>/review", methods=["POST"])
@login_required
def add_review(product_id):
    rating = request.form.get("rating", type=int)
    comment = request.form.get("comment", "").strip()

    if not rating or rating < 1 or rating > 5:
        flash("Please provide a valid rating between 1 and 5.", "error")
        return redirect(url_for("product_detail", product_id=product_id))

    if not comment:
        flash("Review comment cannot be empty.", "error")
        return redirect(url_for("product_detail", product_id=product_id))

    conn = get_db_connection()
    product = conn.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        conn.close()
        abort(404)

    # Secure: Parameterized insert ensures review text is stored as pure data
    conn.execute(
        """
        INSERT INTO reviews (product_id, user_id, rating, comment)
        VALUES (?, ?, ?, ?)
        """,
        (product_id, session["user_id"], rating, comment),
    )
    conn.commit()
    conn.close()

    flash("Your review has been submitted successfully!", "success")
    return redirect(url_for("product_detail", product_id=product_id))


# ==========================================
# Shopping Cart & Promo Routes
# ==========================================

@app.route("/cart")
def view_cart():
    cart = session.get("cart", {})
    cart_items = []
    subtotal = 0.0

    if cart:
        conn = get_db_connection()
        # Retrieve product details for items in cart
        placeholders = ",".join("?" for _ in cart.keys())
        product_ids = [int(pid) for pid in cart.keys()]
        rows = conn.execute(
            f"SELECT * FROM products WHERE id IN ({placeholders})",
            product_ids,
        ).fetchall()
        conn.close()

        products_by_id = {str(p["id"]): p for p in rows}
        for pid_str, quantity in cart.items():
            if pid_str in products_by_id:
                product = products_by_id[pid_str]
                line_total = product["price"] * quantity
                subtotal += line_total
                cart_items.append({
                    "product": product,
                    "quantity": quantity,
                    "line_total": line_total,
                })

    promo_code = session.get("promo_code")
    discount = 0.0
    discount_percent = 0

    if promo_code and subtotal > 0:
        conn = get_db_connection()
        # Secure: Parameterized query checks promo validity
        promo = conn.execute(
            "SELECT * FROM promo_codes WHERE code = ? AND is_active = 1",
            (promo_code,),
        ).fetchone()
        conn.close()

        if promo:
            discount_percent = promo["discount_percent"]
            discount = round((subtotal * discount_percent) / 100.0, 2)
        else:
            session.pop("promo_code", None)
            promo_code = None

    total = max(0.0, round(subtotal - discount, 2))

    return render_template(
        "cart.html",
        cart_items=cart_items,
        subtotal=subtotal,
        discount=discount,
        discount_percent=discount_percent,
        promo_code=promo_code,
        total=total,
    )


@app.route("/cart/add", methods=["POST"])
def add_to_cart():
    product_id = request.form.get("product_id", type=int)
    quantity = request.form.get("quantity", default=1, type=int)

    if not product_id or quantity <= 0:
        flash("Invalid item or quantity.", "error")
        return redirect(url_for("index"))

    conn = get_db_connection()
    product = conn.execute("SELECT id, name FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()

    if not product:
        abort(404)

    cart = session.get("cart", {})
    pid_str = str(product_id)
    cart[pid_str] = cart.get(pid_str, 0) + quantity
    session["cart"] = cart
    session.modified = True

    flash(f"Added {product['name']} to cart.", "success")
    return redirect(request.referrer or url_for("view_cart"))


@app.route("/cart/update", methods=["POST"])
def update_cart():
    action = request.form.get("action")
    product_id = request.form.get("product_id")
    cart = session.get("cart", {})

    if product_id in cart:
        if action == "increase":
            cart[product_id] += 1
        elif action == "decrease":
            cart[product_id] -= 1
            if cart[product_id] <= 0:
                del cart[product_id]
        elif action == "remove":
            del cart[product_id]

    session["cart"] = cart
    session.modified = True
    return redirect(url_for("view_cart"))


@app.route("/cart/apply-promo", methods=["POST"])
def apply_promo():
    code = request.form.get("code", "").strip().upper()

    if not code:
        flash("Please enter a promo code.", "warning")
        return redirect(url_for("view_cart"))

    conn = get_db_connection()
    sql = f"SELECT * FROM promo_codes WHERE code = '{code}' AND is_active = 1"
    promo = conn.execute(sql).fetchone()
    conn.close()

    if promo:
        session["promo_code"] = promo["code"]
        flash(f"Promo code '{promo['code']}' applied! {promo['discount_percent']}% off.", "success")
    else:
        flash("Invalid or expired promo code.", "error")

    return redirect(url_for("view_cart"))


@app.route("/cart/remove-promo", methods=["POST"])
def remove_promo():
    session.pop("promo_code", None)
    flash("Promo code removed.", "info")
    return redirect(url_for("view_cart"))


# ==========================================
# Checkout & Order Routes
# ==========================================

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("index"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    placeholders = ",".join("?" for _ in cart.keys())
    product_ids = [int(pid) for pid in cart.keys()]
    rows = conn.execute(
        f"SELECT * FROM products WHERE id IN ({placeholders})",
        product_ids,
    ).fetchall()

    products_by_id = {str(p["id"]): p for p in rows}
    cart_items = []
    subtotal = 0.0

    for pid_str, quantity in cart.items():
        if pid_str in products_by_id:
            p = products_by_id[pid_str]
            line_total = p["price"] * quantity
            subtotal += line_total
            cart_items.append({
                "product": p,
                "quantity": quantity,
                "line_total": line_total,
            })

    promo_code = session.get("promo_code")
    discount = 0.0
    if promo_code:
        promo = conn.execute(
            "SELECT * FROM promo_codes WHERE code = ? AND is_active = 1",
            (promo_code,),
        ).fetchone()
        if promo:
            discount = round((subtotal * promo["discount_percent"]) / 100.0, 2)

    total = max(0.0, round(subtotal - discount, 2))

    if request.method == "POST":
        shipping_address = request.form.get("shipping_address", "").strip()
        if not shipping_address:
            conn.close()
            flash("Shipping address is required.", "error")
            return render_template(
                "checkout.html",
                user=user,
                cart_items=cart_items,
                subtotal=subtotal,
                discount=discount,
                total=total,
                promo_code=promo_code,
            )

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO orders (user_id, subtotal, discount, total, promo_code, shipping_address, status)
            VALUES (?, ?, ?, ?, ?, ?, 'Completed')
            """,
            (session["user_id"], subtotal, discount, total, promo_code, shipping_address),
        )
        order_id = cursor.lastrowid

        for item in cart_items:
            cursor.execute(
                """
                INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (order_id, item["product"]["id"], item["product"]["name"], item["product"]["price"], item["quantity"]),
            )

        conn.commit()
        conn.close()

        # Clear cart and promo
        session.pop("cart", None)
        session.pop("promo_code", None)

        flash(f"Order #{order_id} placed successfully!", "success")
        return redirect(url_for("order_detail", order_id=order_id))

    conn.close()
    return render_template(
        "checkout.html",
        user=user,
        cart_items=cart_items,
        subtotal=subtotal,
        discount=discount,
        total=total,
        promo_code=promo_code,
    )


@app.route("/orders")
@login_required
def orders_list():
    conn = get_db_connection()
    # Secure: Restricts query strictly to the authenticated user's ID
    orders = conn.execute(
        """
        SELECT * FROM orders
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()

    return render_template("orders.html", orders=orders)


@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    conn = get_db_connection()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()

    if not order:
        conn.close()
        abort(404)

    # Secure Authorization Check (Prevents IDOR):
    # Only allow the user who owns the order or a user with the 'admin' role to view it.
    if order["user_id"] != session["user_id"] and session.get("role") != "admin":
        conn.close()
        abort(403)

    items = conn.execute(
        "SELECT * FROM order_items WHERE order_id = ?",
        (order_id,),
    ).fetchall()
    customer = conn.execute("SELECT * FROM users WHERE id = ?", (order["user_id"],)).fetchone()
    conn.close()

    return render_template(
        "order_detail.html",
        order=order,
        items=items,
        customer=customer,
    )


# ==========================================
# Profile Management
# ==========================================

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = request.args.get("id", type=int)
    if not user_id:
        user_id = request.form.get("id", type=int)

    # If no id parameter is supplied, redirect to the logged-in user's profile with ?id=
    if not user_id:
        return redirect(url_for("profile", id=session["user_id"]))

    conn = get_db_connection()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()

        if not full_name or not email:
            flash("Full name and email are required.", "error")
        else:
            # IDOR Lab: Parameterized update targeting user_id from the URL query parameter
            conn.execute(
                """
                UPDATE users
                SET full_name = ?, email = ?, address = ?, phone = ?
                WHERE id = ?
                """,
                (full_name, email, address, phone, user_id),
            )
            conn.commit()
            flash("Profile updated successfully.", "success")

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)

    recent_orders = conn.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
        (user_id,),
    ).fetchall()
    conn.close()

    return render_template(
        "profile.html",
        user=user,
        recent_orders=recent_orders,
    )


# ==========================================
# ThinkCyber CodeGuard SAST Dashboard
# ==========================================

@app.route("/security-scanner")
@app.route("/sast")
def sast_dashboard():
    stats = get_sast_stats()
    return render_template(
        "sast.html",
        findings=FINDINGS,
        stats=stats,
    )


@app.route("/security-scanner/finding/<finding_id>")
@app.route("/sast/finding/<finding_id>")
def sast_finding_detail(finding_id):
    normalized_id = finding_id.strip().upper()
    finding_idx = next(
        (i for i, f in enumerate(FINDINGS) if f["id"].upper() == normalized_id),
        None,
    )
    if finding_idx is None:
        abort(404)

    finding = FINDINGS[finding_idx]
    prev_finding = FINDINGS[(finding_idx - 1) % len(FINDINGS)]
    next_finding = FINDINGS[(finding_idx + 1) % len(FINDINGS)]
    stats = get_sast_stats()

    return render_template(
        "sast_finding.html",
        finding=finding,
        findings=FINDINGS,
        finding_index=finding_idx + 1,
        total_findings=len(FINDINGS),
        prev_finding=prev_finding,
        next_finding=next_finding,
        stats=stats,
    )



# ==========================================
# Application Entry Point
# ==========================================

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

