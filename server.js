const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* ================= DEBUG: ENV CHECK ================= */
console.log("🔎 ENV CHECK START");
console.log("MYSQLHOST =", process.env.MYSQLHOST);
console.log("MYSQLUSER =", process.env.MYSQLUSER);
console.log("MYSQLDATABASE =", process.env.MYSQLDATABASE);
console.log("MYSQLPORT =", process.env.MYSQLPORT);
console.log("🔎 ENV CHECK END");

/* ================= MYSQL POOL ================= */
const db = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    ssl: false,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
});

/* ================= DEBUG: TEST CONNECTION ================= */
db.query("SELECT DATABASE() AS db", (err, rows) => {
    if (err) {
        console.error("❌ DB TEST FAILED:", err);
    } else {
        console.log("✅ CONNECTED TO DATABASE:", rows[0].db);
    }
});

/* ================= ROUTES ================= */

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ================= SIGNUP (DEBUG) ================= */
app.post("/signup", async (req, res) => {
    console.log("📥 /signup BODY =", req.body);

    const { fullname, email, username, password, cpassword } = req.body;

    if (!fullname || !email || !username || !password || !cpassword) {
        return res.json({
            success: false,
            message: "VALIDATION FAILED",
            debug: "One or more fields missing"
        });
    }

    if (password !== cpassword) {
        return res.json({
            success: false,
            message: "PASSWORD MISMATCH"
        });
    }

    /* ---------- DEBUG SELECT ---------- */
    const checkSql = "SELECT id FROM USER_LISTS WHERE username = ? OR email = ?";
    console.log("🔎 SQL CHECK =", checkSql, [username, email]);

    db.query(checkSql, [username, email], async (err, rows) => {
        if (err) {
            console.error("🔥 SELECT ERROR =", err);
            return res.json({
                success: false,
                step: "SELECT",
                code: err.code,
                errno: err.errno,
                sqlMessage: err.sqlMessage
            });
        }

        console.log("🔎 SELECT RESULT =", rows);

        if (rows.length > 0) {
            return res.json({
                success: false,
                message: "USER EXISTS"
            });
        }

        /* ---------- DEBUG INSERT ---------- */
        const hash = await bcrypt.hash(password, 10);

        const insertSql =
            "INSERT INTO USER_LISTS (fullname,email,username,password) VALUES (?,?,?,?)";

        console.log("📝 SQL INSERT =", insertSql, [
            fullname,
            email,
            username,
            hash
        ]);

        db.query(insertSql, [fullname, email, username, hash], (err, result) => {
            if (err) {
                console.error("🔥 INSERT ERROR =", err);
                return res.json({
                    success: false,
                    step: "INSERT",
                    code: err.code,
                    errno: err.errno,
                    sqlMessage: err.sqlMessage
                });
            }

            console.log("✅ INSERT OK =", result);
            res.json({
                success: true,
                message: "SIGNUP SUCCESS"
            });
        });
    });
});

/* ================= LOGIN (DEBUG) ================= */
app.post("/login", (req, res) => {
    console.log("📥 /login BODY =", req.body);

    const { username, password } = req.body;

    const sql = "SELECT * FROM USER_LISTS WHERE username = ?";
    console.log("🔎 LOGIN SQL =", sql, [username]);

    db.query(sql, [username], async (err, rows) => {
        if (err) {
            console.error("🔥 LOGIN SELECT ERROR =", err);
            return res.json({
                success: false,
                step: "LOGIN_SELECT",
                code: err.code,
                sqlMessage: err.sqlMessage
            });
        }

        if (rows.length === 0) {
            return res.json({
                success: false,
                message: "INVALID USER"
            });
        }

        const ok = await bcrypt.compare(password, rows[0].password);

        res.json({
            success: ok,
            message: ok ? "LOGIN OK" : "WRONG PASSWORD"
        });
    });
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log("🚀 SERVER STARTED ON PORT", PORT);
});
