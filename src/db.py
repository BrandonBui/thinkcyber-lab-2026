"""Database management and initialization for CyberMart.
Provides helper functions for database connections and pre-populates initial seed data.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "..", "cybermart.db"))


def get_db_connection():
    """Returns a SQLite connection configured with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes database schema and populates seed records if empty."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        address TEXT,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL,
        category TEXT NOT NULL,
        image_url TEXT NOT NULL,
        stock INTEGER NOT NULL DEFAULT 50,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS promo_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        discount_percent INTEGER NOT NULL,
        description TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subtotal REAL NOT NULL,
        discount REAL NOT NULL DEFAULT 0.0,
        total REAL NOT NULL,
        promo_code TEXT,
        shipping_address TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        unit_price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    """)

    # Seed users if none exist
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] == 0:
        seed_users = [
            (
                "admin",
                generate_password_hash("AdminPass2026!"),
                "admin@cybermart.local",
                "System Administrator",
                "100 Security Blvd, Suite 400, Cyber City, CC 94016",
                "+1 (555) 019-2831",
                "admin",
            ),
            (
                "victim_user",
                generate_password_hash("P@ssword123"),
                "victim@cybermart.local",
                "Alex Rivera",
                "456 Redwood Lane, Apt 2B, Sunnyvale, CA 94086",
                "+1 (555) 014-9921",
                "user",
            ),
            (
                "student",
                generate_password_hash("student123"),
                "student@cybermart.local",
                "Morgan Chen",
                "789 University Ave, Dorm 312, Berkeley, CA 94720",
                "+1 (555) 018-7744",
                "user",
            ),
        ]
        cursor.executemany(
            """
            INSERT INTO users (username, password_hash, email, full_name, address, phone, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            seed_users,
        )

    # Seed products if fewer than 32 exist
    cursor.execute("SELECT COUNT(*) as count FROM products")
    if cursor.fetchone()["count"] < 32:
        seed_products = [
            (
                "Hardware Security Key FIDO2",
                "hardware-security-key-fido2",
                "Rugged NFC and USB-C dual-interface hardware authentication key with tamper-evident casing.",
                49.99,
                "Security",
                "https://images.unsplash.com/photo-1618042164219-62c820f10723?auto=format&fit=crop&w=600&q=80",
                45,
            ),
            (
                "Faraday Signal-Blocking Bag",
                "faraday-signal-blocking-bag",
                "Military-grade dual-layer shielding bag designed to attenuate cellular, Wi-Fi, and RFID signals.",
                24.99,
                "Privacy",
                "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=600&q=80",
                80,
            ),
            (
                "ThinkCyber Stealth Tactical Hoodie",
                "thinkcyber-stealth-tactical-hoodie",
                "Water-resistant heavyweight cotton hoodie with concealed internal pockets and zip-up collar.",
                65.00,
                "Apparel",
                "https://images.unsplash.com/photo-1556905055-8f358a7a47b2?auto=format&fit=crop&w=600&q=80",
                30,
            ),
            (
                "Hardware-Encrypted NVMe SSD 1TB",
                "hardware-encrypted-nvme-ssd-1tb",
                "PCIe Gen4 solid-state drive featuring on-board AES-256 XTS hardware cryptographic controller.",
                129.99,
                "Hardware",
                "https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=600&q=80",
                25,
            ),
            (
                "Privacy Webcam Shutter Pack (3x)",
                "privacy-webcam-shutter-pack",
                "Ultra-thin physical sliders compatible with laptops, tablets, and external monitors.",
                11.99,
                "Privacy",
                "https://images.unsplash.com/photo-1588508065123-287b28e013da?auto=format&fit=crop&w=600&q=80",
                120,
            ),
            (
                "Mechanical Keyboard - Stealth Edition",
                "mechanical-keyboard-stealth-edition",
                "Compact tenkeyless mechanical keyboard with sound-dampened silent switches and matte black PBT keycaps.",
                119.00,
                "Hardware",
                "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=80",
                18,
            ),
            (
                "RFID Blocking Carbon Fiber Cardholder",
                "rfid-blocking-carbon-fiber-cardholder",
                "Aerospace-grade carbon fiber minimalist wallet with spring-steel money clip and RFID defense.",
                29.99,
                "Accessories",
                "https://images.unsplash.com/photo-1627123424574-724758594e93?auto=format&fit=crop&w=600&q=80",
                60,
            ),
            (
                "ThinkCyber Binary Knit Socks",
                "thinkcyber-binary-knit-socks",
                "Combed cotton crew socks woven with decorative ASCII / binary sequences. Comfortable and durable.",
                14.50,
                "Apparel",
                "https://images.unsplash.com/photo-1586350977771-b3b0abd50c82?auto=format&fit=crop&w=600&q=80",
                95,
            ),
            (
                "USB Data Blocker Adapter (2-Pack)",
                "usb-data-blocker-adapter-2pack",
                "Prevents accidental data exchange or juice-jacking attacks when charging devices at public USB kiosks.",
                16.99,
                "Security",
                "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=600&q=80",
                110,
            ),
            (
                "Biometric Fingerprint FIDO2 Security Key",
                "biometric-fingerprint-fido2-key",
                "Passwordless hardware authenticator with integrated capacitive fingerprint sensor for Touch-to-Sign MFA.",
                79.99,
                "Security",
                "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=600&q=80",
                35,
            ),
            (
                "Hardware Write-Blocker Forensics Bridge",
                "hardware-write-blocker-forensics-bridge",
                "Portable USB 3.2 to SATA/NVMe read-only controller ensuring evidentiary integrity during incident response.",
                189.00,
                "Security",
                "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=600&q=80",
                15,
            ),
            (
                "Physical RJ45 Port Lockout Kit (10x)",
                "physical-rj45-port-lockout-kit",
                "Tamper-resistant physical blockers with security key to prevent unauthorized Ethernet switch connections.",
                28.50,
                "Security",
                "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=600&q=80",
                65,
            ),
            (
                "Air-Gapped Cold Storage Seed Vault",
                "air-gapped-cold-storage-seed-vault",
                "Fireproof and waterproof titanium recovery phrase stamping plates rated up to 3000°F.",
                84.00,
                "Security",
                "https://images.unsplash.com/photo-1639762681485-074b7f938ba0?auto=format&fit=crop&w=600&q=80",
                40,
            ),
            (
                "Multi-Band RF Bug & Hidden Camera Detector",
                "multi-band-rf-bug-camera-detector",
                "Handheld spectrum analyzer sweeping 1MHz–8GHz to locate rogue transmitters, GPS trackers, and pinhole lenses.",
                95.00,
                "Privacy",
                "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=600&q=80",
                28,
            ),
            (
                "14-Inch Anti-Spy Privacy Screen Filter",
                "14-inch-anti-spy-privacy-screen-filter",
                "Micro-louver magnetic laptop filter restricting viewing angles to +/- 30 degrees against visual shoulder surfing.",
                39.99,
                "Privacy",
                "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?auto=format&fit=crop&w=600&q=80",
                55,
            ),
            (
                "3.5mm & USB-C Microphone Hardware Killswitch",
                "microphone-hardware-killswitch",
                "Dummy audio circuit terminator that physically disconnects internal microphone lines from OS audio drivers.",
                18.50,
                "Privacy",
                "https://images.unsplash.com/photo-1590602847861-f357a9332bbc?auto=format&fit=crop&w=600&q=80",
                90,
            ),
            (
                "Faraday XL Laptop & Tablet Shielding Sleeve",
                "faraday-xl-laptop-shielding-sleeve",
                "Zero-signal tactical sleeve accommodating up to 16-inch laptops, blocking Bluetooth, Wi-Fi, 5G, and GPS.",
                64.99,
                "Privacy",
                "https://images.unsplash.com/photo-1548036328-c9fa89d128fa?auto=format&fit=crop&w=600&q=80",
                42,
            ),
            (
                "Infrared Anti-Surveillance Privacy Eyewear",
                "infrared-anti-surveillance-eyewear",
                "Optical frames engineered to reflect near-infrared spectra and disrupt unauthorized automated facial profiling.",
                54.00,
                "Privacy",
                "https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=600&q=80",
                32,
            ),
            (
                "Dual-Band Wi-Fi 6 Packet Capture Adapter",
                "dual-band-wifi-6-packet-capture-adapter",
                "High-gain USB 3.0 wireless network interface supporting monitor mode, packet injection, and 802.11ax analysis.",
                59.99,
                "Hardware",
                "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=600&q=80",
                48,
            ),
            (
                "Open-Source Travel VPN & Tor Router",
                "open-source-travel-vpn-tor-router",
                "Pocket-sized dual-band gigabit router pre-configured with WireGuard, OpenVPN, and DNS-over-HTTPS.",
                89.99,
                "Hardware",
                "https://images.unsplash.com/photo-1606904825846-647eb07f5be2?auto=format&fit=crop&w=600&q=80",
                38,
            ),
            (
                "Keypad PIN-Authenticated USB Flash Drive 256GB",
                "keypad-pin-usb-flash-drive-256gb",
                "OS-independent hardware-encrypted flash storage with physical polymer keypad and brute-force auto-wipe.",
                99.50,
                "Hardware",
                "https://images.unsplash.com/photo-1618042164219-62c820f10723?auto=format&fit=crop&w=600&q=80",
                50,
            ),
            (
                "Portable Gigabit Passive Network Tap",
                "portable-gigabit-passive-network-tap",
                "Inline RJ45 throwing star and aggregator tap for non-intrusive full-duplex Wireshark traffic inspection.",
                74.00,
                "Hardware",
                "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=600&q=80",
                22,
            ),
            (
                "Software Defined Radio (SDR) Transceiver Kit",
                "software-defined-radio-sdr-kit",
                "Wideband 500kHz–1.7GHz TCXO receiver with telescopic dipole antenna set for RF protocol research.",
                44.99,
                "Hardware",
                "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=600&q=80",
                60,
            ),
            (
                "USB-C Serial UART & JTAG Debug Probe",
                "usb-c-serial-uart-jtag-debug-probe",
                "Isolated multi-voltage hardware interface for embedded firmware extraction, UART consoles, and SPI/I2C.",
                36.00,
                "Hardware",
                "https://images.unsplash.com/photo-1555664424-778a1e5e1b48?auto=format&fit=crop&w=600&q=80",
                45,
            ),
            (
                "ThinkCyber Foundation Embroidered Snapback Cap",
                "thinkcyber-embroidered-snapback-cap",
                "Structured 6-panel navy twill cap featuring 3D puffed cyan ThinkCyber hexagon logo embroidery.",
                26.00,
                "Apparel",
                "https://images.unsplash.com/photo-1588850561407-ed78c282e89b?auto=format&fit=crop&w=600&q=80",
                75,
            ),
            (
                "ThinkCyber 'Zero Trust' Graphic Tee",
                "thinkcyber-zero-trust-graphic-tee",
                "Ultra-soft ringspun cotton t-shirt in deep navy with minimalist 'Never Trust, Always Verify' chest print.",
                24.00,
                "Apparel",
                "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=600&q=80",
                100,
            ),
            (
                "ThinkCyber Red vs. Blue Team Reversible Beanie",
                "thinkcyber-red-blue-reversible-beanie",
                "Ribbed merino-blend knit beanie ideal for cold server rooms and late-night CTF competitions.",
                22.00,
                "Apparel",
                "https://images.unsplash.com/photo-1576871337632-b9aef4c17ab9?auto=format&fit=crop&w=600&q=80",
                85,
            ),
            (
                "ThinkCyber Softshell Cyber Range Jacket",
                "thinkcyber-softshell-cyber-range-jacket",
                "Breathable windproof tactical jacket with zippered cable routing ports and ThinkCyber Foundation badge.",
                88.00,
                "Apparel",
                "https://images.unsplash.com/photo-1551028719-00167b16eac5?auto=format&fit=crop&w=600&q=80",
                25,
            ),
            (
                "ThinkCyber Hex-Grid Desk Mat (XXL)",
                "thinkcyber-hex-grid-desk-mat-xxl",
                "900x400mm micro-textured cloth workstation mat printed with common Linux, Nmap, and Wireshark cheat sheets.",
                32.99,
                "Accessories",
                "https://images.unsplash.com/photo-1618384887929-16ec33fab9ef?auto=format&fit=crop&w=600&q=80",
                70,
            ),
            (
                "Insulated Stainless Steel Terminal Tumbler 20oz",
                "insulated-stainless-terminal-tumbler",
                "Double-wall vacuum insulated tumbler in matte navy laser-etched with the ThinkCyber Foundation emblem.",
                27.50,
                "Accessories",
                "https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?auto=format&fit=crop&w=600&q=80",
                90,
            ),
            (
                "64-Piece Precision Security Bit Driver Set",
                "64-piece-precision-security-driver-set",
                "CNC-machined aluminum driver handle with magnetic S2 steel Torx Security, Pentalobe, and Tri-wing bits.",
                38.99,
                "Accessories",
                "https://images.unsplash.com/photo-1581092160607-ee22621dd758?auto=format&fit=crop&w=600&q=80",
                50,
            ),
            (
                "Holographic CTF Sticker & Morale Patch Pack",
                "holographic-ctf-sticker-patch-pack",
                "Set of 12 die-cut vinyl laptop decals and 2 hook-and-loop embroidered ThinkCyber achievement patches.",
                12.99,
                "Accessories",
                "https://images.unsplash.com/photo-1572375992501-4b0892d50c69?auto=format&fit=crop&w=600&q=80",
                150,
            ),
        ]
        cursor.executemany(
            """
            INSERT OR IGNORE INTO products (name, slug, description, price, category, image_url, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            seed_products,
        )

    # Seed promo codes if none exist
    cursor.execute("SELECT COUNT(*) as count FROM promo_codes")
    if cursor.fetchone()["count"] == 0:
        seed_promos = [
            ("WELCOME10", 10, "10% off for all new shoppers", 1),
            ("CYBERSALE25", 25, "25% discount on store items", 1),
            ("STAFF50", 50, "Internal staff employee discount", 1),
        ]
        cursor.executemany(
            """
            INSERT INTO promo_codes (code, discount_percent, description, is_active)
            VALUES (?, ?, ?, ?)
            """,
            seed_promos,
        )

    # Seed sample reviews if none exist
    cursor.execute("SELECT COUNT(*) as count FROM reviews")
    if cursor.fetchone()["count"] == 0:
        seed_reviews = [
            (
                1,  # Hardware Security Key
                2,  # victim_user
                5,
                "Works seamlessly with Linux and macOS. Setup took less than two minutes.",
            ),
            (
                1,  # Hardware Security Key
                3,  # student
                4,
                "Great build quality. USB-C feels sturdy on my laptop.",
            ),
            (
                3,  # Stealth Tactical Hoodie
                2,  # victim_user
                5,
                "Comfortable fabric and the internal pockets are genuinely useful.",
            ),
        ]
        cursor.executemany(
            """
            INSERT INTO reviews (product_id, user_id, rating, comment)
            VALUES (?, ?, ?, ?)
            """,
            seed_reviews,
        )

    # Seed sample order for victim_user if none exist
    cursor.execute("SELECT COUNT(*) as count FROM orders")
    if cursor.fetchone()["count"] == 0:
        cursor.execute(
            """
            INSERT INTO orders (user_id, subtotal, discount, total, promo_code, shipping_address, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                2,
                74.98,
                7.50,
                67.48,
                "WELCOME10",
                "456 Redwood Lane, Apt 2B, Sunnyvale, CA 94086",
                "Delivered",
            ),
        )
        order_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity)
            VALUES (?, ?, ?, ?, ?)
            """,
            (order_id, 1, "Hardware Security Key FIDO2", 49.99, 1),
        )
        cursor.execute(
            """
            INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity)
            VALUES (?, ?, ?, ?, ?)
            """,
            (order_id, 2, "Faraday Signal-Blocking Bag", 24.99, 1),
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)
