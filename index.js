// ---------------- IMPORTS ----------------
require('dotenv').config();          // load env variables first
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");     // declare Pool only once
const bcrypt = require("bcrypt");

// ---------------- EXPRESS APP ----------------
const app = express();
app.use(cors());
app.use(express.json());

// ---------------- DATABASE CONNECTION ----------------
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
});

// ---------------- ROUTES ----------------

// Root route
app.get("/", (req, res) => {
  res.send("School Management Backend is running!");
});

// ---------------- REGISTER ----------------
// Users register, goes to 'registration' table pending approval
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO registration (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, role, approved",
      [username, email, hashedPassword]
    );
    res.json({
      message: "Registration submitted! Pending admin approval.",
      registration: result.rows[0],
    });
  } catch (e) {
    console.error("Register Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- APPROVE REGISTRATION ----------------
app.post("/approve-registration/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const reg = await pool.query("SELECT * FROM registration WHERE id=$1", [id]);
    if (!reg.rows.length) return res.status(404).json({ error: "Registration not found" });

    const user = reg.rows[0];

    // Add to main users table
    await pool.query(
      "INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)",
      [user.username, user.email, user.password, user.role]
    );

    // Mark as approved in registration table
    await pool.query("UPDATE registration SET approved=true WHERE id=$1", [id]);

    res.json({ message: "User approved and added to users table" });
  } catch (e) {
    console.error("Approval Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- CHECK PENDING REGISTRATION ----------------
app.get("/check-registration/:usernameOrEmail", async (req, res) => {
  const { usernameOrEmail } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM registration WHERE (username=$1 OR email=$1) AND approved=false",
      [usernameOrEmail]
    );
    res.json({ pending: result.rows.length > 0 });
  } catch (e) {
    console.error("Check Registration Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- LOGIN ----------------
app.post("/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password)
    return res.status(400).json({ error: "Username/email and password required" });

  try {
    // Check main users table
    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1 OR email=$1",
      [usernameOrEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- ADMIN LOGIN ----------------
app.post("/admin-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password)
    return res.status(400).json({ error: "Username/email and password required" });

  try {
    const result = await pool.query(
      "SELECT * FROM admins WHERE username=$1 OR email=$1",
      [usernameOrEmail]
    );

    if (!result.rows.length)
      return res.status(401).json({ error: "Invalid admin credentials" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword)
      return res.status(401).json({ error: "Invalid admin credentials" });

    res.json({ user: { id: user.id, username: user.username, email: user.email } });
  } catch (e) {
    console.error("Admin Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- PENDING REGISTRATIONS ----------------
app.get("/pending-registrations", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, email, role, created_at FROM registration WHERE approved=false ORDER BY created_at ASC"
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Pending Registrations Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- TEACHERS ----------------
app.get("/teachers", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM teachers ORDER BY name ASC");
    res.json(result.rows);
  } catch (e) {
    console.error("Teachers Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- LIVE CLASSES ----------------
app.get("/live-classes", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM live_classes ORDER BY class_time DESC");
    res.json(result.rows);
  } catch (e) {
    console.error("Live Classes Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- RESULTS ----------------
app.get("/results/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query("SELECT * FROM results WHERE student_email=$1", [studentEmail]);
    res.json(result.rows);
  } catch (e) {
    console.error("Results Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- FINANCE ----------------
app.get("/finance/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query("SELECT * FROM finance WHERE student_email=$1", [studentEmail]);
    res.json(result.rows);
  } catch (e) {
    console.error("Finance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- MATERIALS ----------------
app.get("/materials/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query("SELECT * FROM materials WHERE student_email=$1", [studentEmail]);
    res.json(result.rows);
  } catch (e) {
    console.error("Materials Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- MESSAGES ----------------
app.get("/messages/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM messages WHERE student_email=$1 ORDER BY created_at ASC",
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- SEND MESSAGE ----------------
app.post("/send-message", async (req, res) => {
  const { studentEmail, message, sender } = req.body;
  if (!studentEmail || !message)
    return res.status(400).json({ error: "studentEmail and message required" });

  try {
    const result = await pool.query(
      "INSERT INTO messages(student_email,message,sender,created_at) VALUES($1,$2,$3,NOW()) RETURNING *",
      [studentEmail, message, sender || "student"]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error("Send Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- EXAMS ----------------
app.get("/exams/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query("SELECT * FROM exams WHERE student_email=$1 ORDER BY exam_date DESC", [studentEmail]);
    res.json(result.rows);
  } catch (e) {
    console.error("Exams Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- DASHBOARD SUMMARY ----------------
app.get("/dashboard-summary/:role/:email", async (req, res) => {
  const { role, email } = req.params;
  try {
    if (role === "student") {
      const [resultsCount, financeCount, materialsCount] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM results WHERE student_email=$1", [email]),
        pool.query("SELECT COUNT(*) FROM finance WHERE student_email=$1", [email]),
        pool.query("SELECT COUNT(*) FROM materials WHERE student_email=$1", [email]),
      ]);
      res.json({
        results: resultsCount.rows[0].count,
        finance: financeCount.rows[0].count,
        materials: materialsCount.rows[0].count,
      });
    } else if (role === "admin") {
      const [studentsCount, teachersCount, examsCount] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM users"),
        pool.query("SELECT COUNT(*) FROM teachers"),
        pool.query("SELECT COUNT(*) FROM exams"),
      ]);
      res.json({
        students: studentsCount.rows[0].count,
        teachers: teachersCount.rows[0].count,
        exams: examsCount.rows[0].count,
      });
    } else {
      res.status(400).json({ error: "Invalid role" });
    }
  } catch (e) {
    console.error("Dashboard Summary Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
