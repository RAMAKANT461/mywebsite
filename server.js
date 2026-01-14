const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* ===================== DB CONNECTION ===================== */
const db = mysql.createConnection({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE, // 👉 MUST be RLY_ID_DATABASE
    port: process.env.MYSQLPORT,
    ssl: { rejectUnauthorized: true }
});

db.connect(err => {
    if (err) {
        console.error("❌ MySQL Connection Failed:", err);
    } else {
        console.log("✅ MySQL Connected Successfully");
    }
});

/* ===================== ROUTES ===================== */

// Home
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ===================== SIGNUP ===================== */
app.post("/signup", async (req, res) => {
    try {
        const { fullname, email, username, password, cpassword } = req.body;

        // Validation
        if (!fullname || !email || !username || !password || !cpassword) {
            return res.json({ success: false, message: "All fields required" });
        }

        if (password !== cpassword) {
            return res.json({ success: false, message: "Password mismatch" });
        }

        // STEP 1: Check if user already exists
        db.query(
            "SELECT id FROM USER_LISTS WHERE username = ? OR email = ?",
            [username, email],
            async (err, rows) => {
                if (err) {
                    console.error("❌ SELECT ERROR:", err);
                    return res.json({ success: false, message: "Database error" });
                }

                if (rows.length > 0) {
                    return res.json({ success: false, message: "User already exists" });
                }

                // STEP 2: Insert new user
                const hash = await bcrypt.hash(password, 10);

                db.query(
                    "INSERT INTO USER_LISTS (fullname, email, username, password) VALUES (?,?,?,?)",
                    [fullname, email, username, hash],
                    err => {
                        if (err) {
                            console.error("❌ INSERT ERROR:", err);
                            return res.json({ success: false, message: "Signup failed" });
                        }

                        res.json({
                            success: true,
                            message: "Signup successful"
                        });
                    }
                );
            }
        );
    } catch (e) {
        console.error("❌ SERVER ERROR:", e);
        res.json({ success: false, message: "Server error" });
    }
});

/* ===================== LOGIN ===================== */
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
                console.error("❌ LOGIN SELECT ERROR:", err);
                return res.json({ success: false, message: "Database error" });
            }

            if (rows.length === 0) {
                return res.json({ success: false, message: "Invalid username or password" });
            }

            const ok = await bcrypt.compare(password, rows[0].password);

            if (!ok) {
                return res.json({ success: false, message: "Invalid username or password" });
            }

            res.json({
                success: true,
                message: "Login successful"
            });
        }
    );
});

/* ===================== SERVER START ===================== */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
