const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs"); // Railway-safe
const path = require("path");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

/* ================= MYSQL ================= */
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
    console.error("MySQL connection error:", err.message);
  } else {
    console.log("MySQL Connected");
  }
});

/* ================= ROUTES ================= */

// ROOT ROUTE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// SIGNUP
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
      "INSERT INTO users


