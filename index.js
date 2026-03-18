// ---------------- IMPORTS ----------------
require('dotenv').config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

// ---------------- DATABASE CONNECTION ----------------
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
});

// ---------------- ROOT ----------------
app.get("/", (req, res) => res.send("✅ School Management Backend is running!"));

// ===================== AUTH =====================

// ---------------- REGISTER ----------------
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into registration table
    const result = await pool.query(
      `INSERT INTO registration (username, email, password, role) 
       VALUES ($1, $2, $3, 'student') 
       RETURNING id, username, email, role, approved`,
      [username, email, hashedPassword]
    );

    res.status(201).json({ 
      message: "Registration submitted! Pending admin approval.", 
      registration: result.rows[0] 
    });

  } catch (e) {
    console.error("Register Error FULL:", e);

    // Handle unique username/email
    if (e.code === '23505') {
      return res.status(400).json({ error: "Username or email already exists" });
    }

    res.status(500).json({ error: e.message });
  }
});

// ---------------- LOGIN (Users: students & teachers) ----------------
app.post("/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $1",
      [usernameOrEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.status(200).json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      }
    });

  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- ADMIN LOGIN ----------------
app.post("/admin-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM admins WHERE username = $1 OR email = $1",
      [usernameOrEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const admin = result.rows[0];
    const valid = await bcrypt.compare(password, admin.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.status(200).json({
      user: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: "admin"
      }
    });

  } catch (e) {
    console.error("Admin Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== PENDING & APPROVAL =====================
app.get("/pending-registrations", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM registration WHERE approved = false ORDER BY created_at ASC"
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Pending Registrations Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/approve-registration/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const regResult = await pool.query(
      "SELECT * FROM registration WHERE id = $1", 
      [id]
    );

    if (regResult.rows.length === 0) {
      return res.status(404).json({ error: "Registration not found" });
    }

    const user = regResult.rows[0];

    // Insert into users table
    await pool.query(
      "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)",
      [user.username, user.email, user.password, user.role || 'student']
    );

    // Mark registration as approved
    await pool.query(
      "UPDATE registration SET approved = true, approved_at = NOW(), approved_by = (SELECT id FROM admins LIMIT 1) WHERE id = $1",
      [id]
    );

    res.json({ message: "User approved successfully" });

  } catch (e) {
    console.error("Approval Error:", e);

    if (e.code === '23505') {
      return res.status(400).json({ error: "User already exists in users table" });
    }

    res.status(500).json({ error: e.message });
  }
});

// ===================== STUDENT PROFILE =====================
app.get("/student-profile/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const result = await pool.query(`
      SELECT s.full_name, s.class_name, s.admission_number, s.email, s.phone, 
             s.date_of_birth, s.address, s.profile_picture_url,
             (SELECT COUNT(*) FROM attendance WHERE student_id = s.id AND status = 'present') * 100.0 / 
             NULLIF((SELECT COUNT(*) FROM attendance WHERE student_id = s.id), 0) as attendance_percentage
      FROM students s 
      WHERE s.email = $1`, 
      [email]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Student Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== STUDENT FEATURES =====================
app.get("/exams/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT e.* FROM exams e
      JOIN results r ON r.exam_id = e.id
      JOIN students s ON s.id = r.student_id
      WHERE s.email = $1 
      ORDER BY e.exam_date DESC`, 
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Exams Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/results/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT r.* FROM results r
      JOIN students s ON s.id = r.student_id
      WHERE s.email = $1`, 
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Results Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/finance/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT f.* FROM finance f
      JOIN students s ON s.id = f.student_id
      WHERE s.email = $1`, 
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Finance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/materials/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT m.* FROM materials m
      JOIN students s ON s.class_name = m.class_name
      WHERE s.email = $1`, 
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Materials Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/live-classes", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM live_classes ORDER BY class_time DESC");
    res.json(result.rows);
  } catch (e) {
    console.error("Live Classes Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/attendance/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT a.* FROM attendance a
      JOIN students s ON s.id = a.student_id
      WHERE s.email = $1 
      ORDER BY a.date DESC`, 
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Attendance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/messages/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const studentResult = await pool.query("SELECT id FROM students WHERE email = $1", [studentEmail]);
    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }
    const studentId = studentResult.rows[0].id;

    const messagesResult = await pool.query(`
      SELECT m.id, m.message, m.sender_role, m.created_at, m.is_read
      FROM messages m
      WHERE m.receiver_id = $1 OR m.sender_id = $1
      ORDER BY m.created_at ASC`, 
      [studentId]
    );

    res.json(messagesResult.rows);
  } catch (e) {
    console.error("Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== PENDING REGISTRATIONS (Admin) =====================
app.get("/pending-registrations", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM registration WHERE approved = false ORDER BY created_at ASC"
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Pending Registrations Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/approve-registration/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const regResult = await pool.query("SELECT * FROM registration WHERE id = $1", [id]);
    if (regResult.rows.length === 0) {
      return res.status(404).json({ error: "Registration not found" });
    }

    const user = regResult.rows[0];

    // Create user in users table
    await pool.query(
      "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)",
      [user.username, user.email, user.password, user.role]
    );

    // Mark as approved
    await pool.query(
      "UPDATE registration SET approved = true, approved_at = NOW(), approved_by = (SELECT id FROM admins LIMIT 1) WHERE id = $1", 
      [id]
    );

    res.json({ message: "User approved successfully" });
  } catch (e) {
    console.error("Approval Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ School Management Backend running on port ${PORT}`);
});