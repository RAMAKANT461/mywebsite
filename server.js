const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

/* ================= Middleware ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* ================= MySQL Connection ================= */
const db = mysql.createConnection({
    host: process.env.MYSQLHOST,          // crossover.proxy.rlwy.net (internal/private)
    user: process.env.MYSQLUSER,          // root
    password: process.env.MYSQLPASSWORD,  // root password
    database: process.env.MYSQLDATABASE,  // railway
    port: process.env.MYSQLPORT,          // 3306
    ssl: { rejectUnauthorized: true }
});

db.connect(err => {
    if (err) {
        console.error("❌ MySQL Connection Error:", err.message);
    } else {
        console.log("✅ MySQL Connected to database:", process.env.MYSQLDATABASE);
    }
});

/* ================= Routes ================= */

// Default page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
    try {
        const { fullname, email, username, password, cpassword } = req.body;

        if (!fullname || !email || !username || !password || !cpassword) {
            return res.json({ success: false, message: "All fields required" });
        }

        if (password !== cpassword) {
            return res.json({ success: false, message: "Password mismatch" });
        }

        // Check existing user
        db.query(
            "SELECT id FROM USER_LISTS WHERE username = ? OR email = ?",
            [username, email],
            async (err, rows) => {
                if (err) {
                    console.error("❌ SELECT error:", err);
                    return res.json({ success: false, message: "Database error" });
                }

                if (rows.length > 0) {
                    return res.json({ success: false, message: "User already exists" });
                }

                // Insert new user
                const hash = await bcrypt.hash(password, 10);

                db.query(
                    "INSERT INTO USER_LISTS (fullname, email, username, password) VALUES (?,?,?,?)",
                    [fullname, email, username, hash],
                    err => {
                        if (err) {
                            console.error("❌ INSERT error:", err);
                            return res.json({ success: false, message: "Signup failed" });
                        }

                        res.json({ success: true, message: "Signup successful" });
                    }
                );
            }
        );
    } catch (e) {
        console.error("❌ Server error:", e);
        res.json({ success: false, message: "Server error" });
    }
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Missing credentials" });
    }

    db.query(
        "SELECT * FROM USER_LISTS WHERE username = ?",
        [username],
        async (err, rows) => {
            if (err) {
                console.error("❌ LOGIN SELECT error:", err);
                return res.json({ success: false, message: "Database error" });
            }

            if (rows.length === 0) {
                return res.json({ success: false, message: "Invalid username or password" });
            }

            const ok = await bcrypt.compare(password, rows[0].password);

            if (!ok) {
                return res.json({ success: false, message: "Invalid username or password" });
            }

            res.json({ success: true, message: "Login successful" });
        }
    );
});

/* ================= Server Start ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
