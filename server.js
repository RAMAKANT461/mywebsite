const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

/* ================= Middleware ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* ================= MySQL POOL (IMPORTANT FIX) ================= */
const db = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Optional: test pool once
db.query("SELECT 1", err => {
    if (err) {
        console.error("❌ MySQL Pool Error:", err.message);
    } else {
        console.log("✅ MySQL Pool Ready");
    }
});

/* ================= Routes ================= */

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
    const { fullname, email, username, password, cpassword } = req.body;

    if (!fullname || !email || !username || !password || !cpassword) {
        return res.json({ success: false, message: "All fields required" });
    }

    if (password !== cpassword) {
        return res.json({ success: false, message: "Password mismatch" });
    }

    // STEP 1: check existing user
    db.query(
        "SELECT id FROM USER_LISTS WHERE username = ? OR email = ?",
        [username, email],
        async (err, rows) => {
            if (err) {
                console.error("❌ SELECT Error:", err);
                return res.json({ success: false, message: "Database error" });
            }

            if (rows.length > 0) {
                return res.json({ success: false, message: "User already exists" });
            }

            // STEP 2: insert user
            const hash = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO USER_LISTS (fullname, email, username, password) VALUES (?,?,?,?)",
                [fullname, email, username, hash],
                err => {
                    if (err) {
                        console.error("❌ INSERT Error:", err);
                        return res.json({ success: false, message: "Signup failed" });
                    }

                    res.json({ success: true, message: "Signup successful" });
                }
            );
        }
    );
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
                console.error("❌ LOGIN Error:", err);
                return res.json({ success: false, message: "Database error" });
            }

            if (rows.length === 0) {
                return res.json({ success: false, message: "Invalid username or password" });
            }

            const ok = await bcrypt.compare(password, rows[0].password);
            res.json({ success: ok });
        }
    );
});

/* ================= Server ================= */
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
