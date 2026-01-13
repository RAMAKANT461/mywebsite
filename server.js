const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// ================= MIDDLEWARE =================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 👉 PUBLIC folder serve karo
app.use(express.static(path.join(__dirname, "public")));

// ================= MYSQL =================
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
    console.error("❌ MySQL error:", err.message);
  } else {
    console.log("✅ MySQL Connected");
  }
});

// ================= ROUTES =================

// 🔑 ROOT ROUTE (THIS FIXES Cannot GET /)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// ---------------- SIGNUP ----------------
app.post("/signup", async (req, res) => {
  const { fullname, email, username, password, cpassword } = req.body;

  if (!fullname || !email || !username || !password) {
    return res.json({ success: false, message: "All fields required" });
  }

  if (password !== cpassword) {
    return res.json({ success: false, message: "Password mismatch" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (fullname,email,username,password) VALUES (?,?,?,?)",
    [fullname, email, username, hash],
    err => {
      if (err) {
        return res.json({ success: false, message: "User already exists" });
      }
      res.json({ success: true, message: "Signup successful" });
    }
  );
});

// ---------------- LOGIN ----------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE username=?",
    [username],
    async (err, rows) => {
      if (rows.length === 0) {
        return res.json({ success: false });
      }

      const
