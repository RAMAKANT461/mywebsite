const express = require("express");
const session = require("express-session");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: "mySecretKey123",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false   // Railway HTTP
    }
}));

/* ===== PUBLIC ONLY ===== */
app.use(express.static(path.join(__dirname, "public")));

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

/* ================= AUTH MIDDLEWARE ================= */
function checkAuth(req, res, next) {
    if (req.session && req.session.user) {
        next();
    } else {
        res.redirect("/login.html");
    }
}

/* ================= ROUTES ================= */

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {

    const { fullname, email, username, password, cpassword } = req.body;

    if (password !== cpassword) {
        return res.json({ success: false, message: "PASSWORD MISMATCH" });
    }

    const checkSql = "SELECT id FROM USER_LISTS WHERE username = ? OR email = ?";

    db.query(checkSql, [username, email], async (err, rows) => {
        if (rows.length > 0) {
            return res.json({ success: false, message: "USER EXISTS" });
        }

        const hash = await bcrypt.hash(password, 10);

        const insertSql =
            "INSERT INTO USER_LISTS (fullname,email,username,password) VALUES (?,?,?,?)";

        db.query(insertSql, [fullname, email, username, hash], (err) => {
            if (err) {
                return res.json({ success: false, message: "INSERT ERROR" });
            }
            res.json({ success: true, message: "SIGNUP SUCCESS" });
        });
    });
});

/* ================= LOGIN (FIXED) ================= */
app.post("/login", (req, res) => {
    console.log("📥 /login BODY =", req.body);

    const { username, password } = req.body;

    const sql = "SELECT * FROM USER_LISTS WHERE username = ?";
    console.log("🔎 LOGIN SQL =", sql, [username]);

    db.query(sql, [username], async (err, rows) => {

        if (err) {
            console.error("🔥 LOGIN ERROR =", err);
            return res.json({ success: false });
        }

        if (rows.length === 0) {
            console.log("❌ USER NOT FOUND");
            return res.json({ success: false });
        }

        console.log("✅ USER FOUND =", rows[0].username);

        const match = await bcrypt.compare(password, rows[0].password);

        console.log("🔐 PASSWORD MATCH =", match);

        if (!match) {
            return res.json({ success: false });
        }

        /* 🔥🔥 MAIN FIX 🔥🔥 */
        req.session.user = {
            id: rows[0].id,
            username: rows[0].username
        };

        console.log("✅ SESSION SET =", req.session.user);

        res.json({ success: true });
    });
});


/* ================= PROTECTED PAGE ================= */
app.get("/main_menu.html", checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "protected", "main_menu.html"));
});

/* ================= LOGOUT ================= */
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log("🚀 SERVER STARTED ON PORT", PORT);
});
