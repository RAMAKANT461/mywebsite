const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const db = mysql.createConnection({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    ssl: { rejectUnauthorized: true }
});

db.connect(err => {
    if (err) {
        console.error("MySQL error:", err.message);
    } else {
        console.log("MySQL Connected");
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/signup", async (req, res) => {
    try {
        const { fullname, email, username, password, cpassword } = req.body;

        if (!fullname || !email || !username || !password) {
            return res.json({ success: false, message: "All fields required" });
        }

        if (password !== cpassword) {
            return res.json({ success: false, message: "Password mismatch" });
        }

        const hash = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO USER_LISTS (fullname,email,username,password) VALUES (?,?,?,?)",
            [fullname, email, username, hash],
            err => {
                if (err) {
                    return res.json({ success: false, message: "User already exists" });
                }
                res.json({ success: true, message: "Signup successful" });
            }
        );
    } catch (e) {
        res.json({ success: false, message: "Server error" });
    }
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query(
        "SELECT * FROM USER_LISTS WHERE username = ?",
        [username],
        async (err, rows) => {
            if (err || rows.length === 0) {
                return res.json({ success: false });
            }

            const ok = await bcrypt.compare(password, rows[0].password);
            res.json({ success: ok });
        }
    );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});

