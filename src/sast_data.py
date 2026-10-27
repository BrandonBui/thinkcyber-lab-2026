"""Hardcoded SAST vulnerability dataset and helper utilities for ThinkCyber CodeGuard.
Deterministic ground truth matching the ThinkCyber Store codebase.
"""

FINDINGS = [
    {
        "id": "TC-SAST-001",
        "title": "SQL Injection in Promo Code Lookup",
        "severity": "CRITICAL",
        "severity_rank": 1,
        "cvss": 9.8,
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "file": "src/app.py",
        "lines": "441-460",
        "vulnerable_lines": [450],
        "endpoint": "POST /cart/apply-promo",
        "endpoint_method": "POST",
        "endpoint_path": "/cart/apply-promo",
        "status": "Open",
        "introduced_commit": "a8f42c1",
        "summary": "User promo code input is pasted directly into a SQL query string, allowing attackers to manipulate the database query.",
        "what_is_it": (
            "SQL Injection (SQLi) happens when an application takes text typed by a user and inserts it directly "
            "into a database command (SQL query). Instead of treating the user's input strictly as a plain promo code word, "
            "the database can be tricked into running extra SQL commands included inside the input."
        ),
        "why_vulnerable": (
            "On line 443, the app reads whatever the user typed into the promo code box (`code`). Then on line 450, "
            "it builds the SQL query using a Python f-string: `f\"SELECT * FROM promo_codes WHERE code = '{code}' AND is_active = 1\"`. "
            "Because `code` is wrapped in single quotes without parameterization (`?`), typing a single quote (`'`) in the promo box "
            "breaks out of the data field and lets the user inject their own SQL conditions (such as `OR 1=1`)."
        ),
        "source_to_sink": [
            {
                "step": 1,
                "type": "Source (User Input)",
                "location": "src/app.py:443",
                "code": "code = request.form.get(\"code\", \"\").strip().upper()",
                "detail": "Untrusted text enters the application from the Promo Code input field."
            },
            {
                "step": 2,
                "type": "Unsafe String Formatting",
                "location": "src/app.py:450",
                "code": "sql = f\"SELECT * FROM promo_codes WHERE code = '{code}' AND is_active = 1\"",
                "detail": "The user's input is pasted directly into the raw SQL query string without escaping or parameter binding."
            },
            {
                "step": 3,
                "type": "Sink (Database Execution)",
                "location": "src/app.py:451",
                "code": "promo = conn.execute(sql).fetchone()",
                "detail": "SQLite runs the modified SQL command, executing any injected SQL logic."
            }
        ],
        "vulnerable_code": [
            {"num": 441, "text": "@app.route(\"/cart/apply-promo\", methods=[\"POST\"])", "vuln": False},
            {"num": 442, "text": "def apply_promo():", "vuln": False},
            {"num": 443, "text": "    code = request.form.get(\"code\", \"\").strip().upper()", "vuln": False, "tag": "SOURCE"},
            {"num": 444, "text": "", "vuln": False},
            {"num": 445, "text": "    if not code:", "vuln": False},
            {"num": 446, "text": "        flash(\"Please enter a promo code.\", \"warning\")", "vuln": False},
            {"num": 447, "text": "        return redirect(url_for(\"view_cart\"))", "vuln": False},
            {"num": 448, "text": "", "vuln": False},
            {"num": 449, "text": "    conn = get_db_connection()", "vuln": False},
            {"num": 450, "text": "    sql = f\"SELECT * FROM promo_codes WHERE code = '{code}' AND is_active = 1\"", "vuln": True, "tag": "VULNERABLE SINK"},
            {"num": 451, "text": "    promo = conn.execute(sql).fetchone()", "vuln": True},
            {"num": 452, "text": "    conn.close()", "vuln": False},
            {"num": 453, "text": "", "vuln": False},
            {"num": 454, "text": "    if promo:", "vuln": False},
            {"num": 455, "text": "        session[\"promo_code\"] = promo[\"code\"]", "vuln": False},
            {"num": 456, "text": "        flash(f\"Promo code '{promo['code']}' applied! {promo['discount_percent']}% off.\", \"success\")", "vuln": False},
        ],
        "reproduction_steps": [
            {
                "step": 1,
                "title": "Add an item to your cart",
                "detail": "Open the ThinkCyber Store home page (`/`), pick any product, and click \"Add to Cart\"."
            },
            {
                "step": 2,
                "title": "Go to the Shopping Cart page",
                "detail": "Click \"Cart\" in the top navigation bar (`/cart`) and locate the \"Promo Code\" input box on the right."
            },
            {
                "step": 3,
                "title": "Enter a SQL Injection payload",
                "detail": "Paste the following payload into the Promo Code field and click \"Apply\":",
                "payload": "' OR 1=1 ORDER BY discount_percent DESC --"
            }
        ],
        "validation_result": (
            "True Positive Confirmed: Even though you did not enter a real promo code name, the database query evaluates "
            "`1=1` as true, sorts all promo codes by highest discount first, and automatically applies the hidden internal "
            "`STAFF50` promo code (50% off) to your cart!"
        ),
    },
    {
        "id": "TC-SAST-002",
        "title": "Stored Cross-Site Scripting (XSS) in Product Reviews",
        "severity": "HIGH",
        "severity_rank": 2,
        "cvss": 8.2,
        "category": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "file": "templates/product.html",
        "lines": "128-136",
        "vulnerable_lines": [133],
        "endpoint": "GET /product/<int:product_id>",
        "endpoint_method": "GET",
        "endpoint_path": "/product/<int:product_id>",
        "status": "Open",
        "introduced_commit": "a8f42c1",
        "summary": "Customer product reviews are rendered with HTML escaping turned off, allowing injected JavaScript to run in visitors' browsers.",
        "what_is_it": (
            "Stored Cross-Site Scripting (XSS) happens when an application saves user input (like a product review) in the "
            "database and later displays it on a web page without converting special HTML characters (like `<` and `>`). "
            "If a user submits `<script>` tags in a review, the browser mistakes the review text for real website code and runs it."
        ),
        "why_vulnerable": (
            "By default, the Jinja2 template engine automatically escapes user text so HTML tags are displayed harmlessly on screen. "
            "However, on line 133 of `templates/product.html`, the developer added the `| safe` filter: `{{ review.comment | safe }}`. "
            "This filter explicitly disables Jinja2's built-in protection and tells the browser to execute any HTML or JavaScript inside the review."
        ),
        "source_to_sink": [
            {
                "step": 1,
                "type": "Source (User Input)",
                "location": "src/app.py:295",
                "code": "comment = request.form.get(\"comment\", \"\").strip()",
                "detail": "User submits a product review comment through the review form."
            },
            {
                "step": 2,
                "type": "Database Storage",
                "location": "src/app.py:314",
                "code": "INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)",
                "detail": "The raw comment (including any HTML/JS tags) is saved in the `reviews` table."
            },
            {
                "step": 3,
                "type": "Sink (Unescaped HTML Output)",
                "location": "templates/product.html:133",
                "code": "<p ...>{{ review.comment | safe }}</p>",
                "detail": "The `| safe` filter disables HTML escaping, causing the browser to execute injected `<script>` tags."
            }
        ],
        "vulnerable_code": [
            {"num": 128, "text": "                    </div>", "vuln": False},
            {"num": 129, "text": "                    <span class=\"text-[10px] text-[#96CFF1]/70\">{{ review.created_at }}</span>", "vuln": False},
            {"num": 130, "text": "                </div>", "vuln": False},
            {"num": 131, "text": "            </div>", "vuln": False},
            {"num": 132, "text": "            <!-- Customer review comment rendered below -->", "vuln": False},
            {"num": 133, "text": "            <p class=\"text-xs text-[#C0E8FF] leading-relaxed whitespace-pre-wrap\">{{ review.comment | safe }}</p>", "vuln": True, "tag": "VULNERABLE SINK"},
            {"num": 134, "text": "        </div>", "vuln": False},
            {"num": 135, "text": "        {% endfor %}", "vuln": False},
            {"num": 136, "text": "    </div>", "vuln": False}
        ],
        "reproduction_steps": [
            {
                "step": 1,
                "title": "Sign in to the store",
                "detail": "Go to `/login` and sign in with the student lab account: username `student` and password `student123`."
            },
            {
                "step": 2,
                "title": "Open any product page",
                "detail": "Click on any product (for example, `/product/1`) and scroll down to the \"Write a Review\" form."
            },
            {
                "step": 3,
                "title": "Submit a review containing JavaScript",
                "detail": "Select any star rating, paste the following script into the Comment box, and click \"Submit Review\":",
                "payload": "<script>alert('XSS Confirmed!')</script>"
            }
        ],
        "validation_result": (
            "True Positive Confirmed: As soon as the page reloads, your browser executes the injected `<script>` tag and pops up "
            "an alert box saying \"XSS Confirmed!\". Every user who views this product page will also run this script."
        ),
    },
    {
        "id": "TC-SAST-003",
        "title": "Insecure Direct Object Reference (IDOR) in User Profile",
        "severity": "HIGH",
        "severity_rank": 3,
        "cvss": 8.1,
        "category": "Broken Access Control (IDOR)",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "file": "src/app.py",
        "lines": "628-662",
        "vulnerable_lines": [631, 657, 662],
        "endpoint": "GET, POST /profile?id=<user_id>",
        "endpoint_method": "GET, POST",
        "endpoint_path": "/profile?id=<user_id>",
        "status": "Open",
        "introduced_commit": "a8f42c1",
        "summary": "The `/profile` page loads and updates whichever user ID is passed in the `?id=` URL parameter without checking if it belongs to the logged-in user.",
        "what_is_it": (
            "An Insecure Direct Object Reference (IDOR) happens when an application uses a user-supplied identifier (like `?id=3` in the URL) "
            "to look up a database record, but forgets to check if the currently logged-in user actually has permission to view or edit that record."
        ),
        "why_vulnerable": (
            "Although `/profile` checks that you are logged in (`@login_required`), line 631 reads the account ID directly from the URL query parameter: "
            "`user_id = request.args.get(\"id\", type=int)`. Lines 657 and 662 then use that `user_id` to update or view the user record in the database, "
            "never checking whether `user_id` matches the logged-in user's own `session[\"user_id\"]`."
        ),
        "source_to_sink": [
            {
                "step": 1,
                "type": "Source (URL Parameter)",
                "location": "src/app.py:631",
                "code": "user_id = request.args.get(\"id\", type=int)",
                "detail": "The app reads the target `user_id` directly from the `?id=` parameter in the browser URL."
            },
            {
                "step": 2,
                "type": "Missing Ownership Check",
                "location": "src/app.py:635",
                "code": "# Missing check: if user_id != session[\"user_id\"]: abort(403)",
                "detail": "The code never verifies that the requested `user_id` belongs to the logged-in user."
            },
            {
                "step": 3,
                "type": "Sink (Unauthorized Read / Write)",
                "location": "src/app.py:657 & 662",
                "code": "SELECT * FROM users WHERE id = ?  /  UPDATE users ... WHERE id = ?",
                "detail": "The database returns or overwrites another user's private profile based on the URL parameter."
            }
        ],
        "vulnerable_code": [
            {"num": 628, "text": "@app.route(\"/profile\", methods=[\"GET\", \"POST\"])", "vuln": False},
            {"num": 629, "text": "@login_required", "vuln": False},
            {"num": 630, "text": "def profile():", "vuln": False},
            {"num": 631, "text": "    user_id = request.args.get(\"id\", type=int)", "vuln": True, "tag": "SOURCE"},
            {"num": 632, "text": "    if not user_id:", "vuln": False},
            {"num": 633, "text": "        user_id = request.form.get(\"id\", type=int)", "vuln": False},
            {"num": 634, "text": "", "vuln": False},
            {"num": 635, "text": "    if not user_id:", "vuln": False},
            {"num": 636, "text": "        return redirect(url_for(\"profile\", id=session[\"user_id\"]))", "vuln": False},
            {"num": 637, "text": "", "vuln": False},
            {"num": 638, "text": "    conn = get_db_connection()", "vuln": False},
            {"num": 651, "text": "            conn.execute(", "vuln": False},
            {"num": 652, "text": "                \"\"\"UPDATE users", "vuln": False},
            {"num": 653, "text": "                SET full_name = ?, email = ?, address = ?, phone = ?", "vuln": False},
            {"num": 654, "text": "                WHERE id = ?\"\"\",", "vuln": False},
            {"num": 657, "text": "                (full_name, email, address, phone, user_id),", "vuln": True, "tag": "VULNERABLE SINK"},
            {"num": 658, "text": "            )", "vuln": False},
            {"num": 662, "text": "    user = conn.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,)).fetchone()", "vuln": True, "tag": "VULNERABLE SINK"}
        ],
        "reproduction_steps": [
            {
                "step": 1,
                "title": "Sign in as the student user",
                "detail": "Go to `/login` and sign in with username `student` and password `student123`."
            },
            {
                "step": 2,
                "title": "Open your Profile page",
                "detail": "Click on your username in the top-right navigation bar. Notice the browser URL is `/profile?id=3`."
            },
            {
                "step": 3,
                "title": "Change the ID parameter in the URL",
                "detail": "Change the URL in your browser address bar to another user's ID (such as `2` or `1`) and press Enter:",
                "payload": "/profile?id=2"
            }
        ],
        "validation_result": (
            "True Positive Confirmed: The page displays the private profile, email, home shipping address, phone number, "
            "and order history of another customer (`Alex Rivera` at `id=2`, or `System Administrator` at `id=1`), and even lets you modify their account info!"
        ),
    },
    {
        "id": "TC-SAST-004",
        "title": "Reflected Cross-Site Scripting (XSS) in Catalog Search",
        "severity": "HIGH",
        "severity_rank": 4,
        "cvss": 7.5,
        "category": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "file": "templates/index.html",
        "lines": "65-73",
        "vulnerable_lines": [68],
        "endpoint": "GET /?q=<search_query>",
        "endpoint_method": "GET",
        "endpoint_path": "/?q=<search_query>",
        "status": "Open",
        "introduced_commit": "a8f42c1",
        "summary": "The catalog search query is reflected directly into the 'Results for' heading with HTML escaping disabled, allowing arbitrary JavaScript execution via crafted search URLs.",
        "what_is_it": (
            "Reflected Cross-Site Scripting (XSS) occurs when an application takes untrusted user input from an HTTP request "
            "(such as a URL query parameter like `?q=`) and immediately echoes it back into the HTML page without proper escaping. "
            "If an attacker tricks a user into clicking a link with `<script>` tags in the search parameter, the victim's browser executes the attacker's script."
        ),
        "why_vulnerable": (
            "In `src/app.py` (line 228), the application reads the `q` query parameter from the URL (`query = request.args.get(\"q\", \"\").strip()`) "
            "and passes it to `templates/index.html` as `search_query`. On line 68 of `templates/index.html`, the template renders "
            "`Results for <span class=\"text-[#ACE3FA]\">\"{{ search_query | safe }}\"</span>`. The `| safe` filter explicitly bypasses Jinja2's automatic HTML escaping, "
            "causing the browser to interpret any HTML or JavaScript in the search term as active code."
        ),
        "source_to_sink": [
            {
                "step": 1,
                "type": "Source (URL Query Parameter)",
                "location": "src/app.py:228",
                "code": "query = request.args.get(\"q\", \"\").strip()",
                "detail": "Untrusted input enters the application from the `?q=` URL parameter when a user searches the catalog."
            },
            {
                "step": 2,
                "type": "Template Context Propagation",
                "location": "src/app.py:248-253",
                "code": "return render_template(\"index.html\", ..., search_query=query)",
                "detail": "The raw `query` string is passed directly into the Jinja2 template context as `search_query`."
            },
            {
                "step": 3,
                "type": "Sink (Unescaped HTML Output)",
                "location": "templates/index.html:68",
                "code": "Results for <span class=\"text-[#ACE3FA]\">\"{{ search_query | safe }}\"</span>",
                "detail": "The `| safe` filter disables Jinja2 HTML entity encoding, reflecting raw HTML/JavaScript directly into the DOM."
            }
        ],
        "vulnerable_code": [
            {"num": 65, "text": "{% if search_query %}", "vuln": False},
            {"num": 66, "text": "<div class=\"mb-6 flex items-center justify-between\">", "vuln": False},
            {"num": 67, "text": "    <h2 class=\"text-lg font-bold text-white\">", "vuln": False},
            {"num": 68, "text": "        Results for <span class=\"text-[#ACE3FA]\">\"{{ search_query | safe }}\"</span>", "vuln": True, "tag": "VULNERABLE SINK"},
            {"num": 69, "text": "        <span class=\"ml-2 text-xs font-normal text-[#96CFF1]\">({{ products|length }} {{ 'result' if products|length == 1", "vuln": False},
            {"num": 70, "text": "            else 'results' }})</span>", "vuln": False},
            {"num": 71, "text": "    </h2>", "vuln": False},
            {"num": 72, "text": "</div>", "vuln": False},
            {"num": 73, "text": "{% endif %}", "vuln": False}
        ],
        "reproduction_steps": [
            {
                "step": 1,
                "title": "Open the ThinkCyber Store catalog",
                "detail": "Navigate to the store home page (`/`) and locate the search input box on the right side above the product grid."
            },
            {
                "step": 2,
                "title": "Submit a JavaScript payload in the search bar",
                "detail": "Paste the following XSS payload into the search box and click \"Search\" (or visit `/?q=<script>alert('Reflected XSS!')</script>`):",
                "payload": "<script>alert('Reflected XSS!')</script>"
            }
        ],
        "validation_result": (
            "True Positive Confirmed: When the search results page loads, the search term is reflected unescaped inside the "
            "\"Results for\" heading and the browser immediately executes the `<script>` tag, popping up an alert box with \"Reflected XSS!\"."
        ),
    }
]


def get_sast_stats():
    """Computes aggregate SAST security posture metrics."""
    total = len(FINDINGS)
    critical = sum(1 for f in FINDINGS if f["severity"] == "CRITICAL")
    high = sum(1 for f in FINDINGS if f["severity"] == "HIGH")
    medium = sum(1 for f in FINDINGS if f["severity"] == "MEDIUM")
    low = sum(1 for f in FINDINGS if f["severity"] == "LOW")

    # Security Posture Score calculation (e.g. 42 / 100 - At Risk)
    score = 42
    rating = "At Risk"

    files = sorted(list(set(f["file"] for f in FINDINGS)))
    categories = sorted(list(set(f["category"] for f in FINDINGS)))

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "score": score,
        "rating": rating,
        "files": files,
        "categories": categories,
        "repo": "thinkcyber-org/thinkcyber-store",
        "branch": "main",
        "commit": "a8f42c1",
        "scanner_version": "v2.14.0-sast",
    }
