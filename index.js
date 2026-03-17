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
app.get("/", (req, res) => res.send("School Management Backend is running!"));

// ===================== AUTH =====================
app.post("/register", async (req, res) => {
  const { username, email, password, role = "student" } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO registration (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role, approved",
      [username, email, hashedPassword, role]
    );
    res.json({ message: "Registration submitted! Pending admin approval.", registration: result.rows[0] });
  } catch (e) {
    console.error("Register Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/check-registration/:usernameOrEmail", async (req, res) => {
  const { usernameOrEmail } = req.params;
  try {
    const result = await pool.query(
      "SELECT approved FROM registration WHERE (username = $1 OR email = $1) AND approved = false",
      [usernameOrEmail]
    );
    res.json({ pending: result.rows.length > 0 });
  } catch (e) {
    console.error("Check Registration Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) return res.status(400).json({ error: "Username/email and password required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1 OR email = $1", [usernameOrEmail]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/admin-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) return res.status(400).json({ error: "Username/email and password required" });

  try {
    const result = await pool.query("SELECT * FROM admins WHERE username = $1 OR email = $1", [usernameOrEmail]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const admin = result.rows[0];
    const valid = await bcrypt.compare(password, admin.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ user: { id: admin.id, username: admin.username, email: admin.email, role: "admin" } });
  } catch (e) {
    console.error("Admin Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== PENDING & APPROVAL =====================
app.get("/pending-registrations", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM registration WHERE approved = false ORDER BY created_at ASC");
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
    if (regResult.rows.length === 0) return res.status(404).json({ error: "Registration not found" });

    const user = regResult.rows[0];
    await pool.query(
      "INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)",
      [user.username, user.email, user.password, user.role]
    );
    await pool.query("UPDATE registration SET approved = true WHERE id = $1", [id]);

    res.json({ message: "User approved successfully" });
  } catch (e) {
    console.error("Approval Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== DASHBOARD SUMMARY =====================
app.get("/dashboard-summary/:role/:email", async (req, res) => {
  const { role, email } = req.params;
  try {
    if (role === "student") {
      const [exams, results, finance, materials] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM exams WHERE student_email = $1", [email]),
        pool.query("SELECT COUNT(*) FROM results WHERE student_email = $1", [email]),
        pool.query("SELECT COUNT(*) FROM finance WHERE student_email = $1", [email]),
        pool.query("SELECT COUNT(*) FROM materials WHERE class_id IN (SELECT class_id FROM students WHERE email = $1)", [email]),
      ]);
      res.json({
        exams: parseInt(exams.rows[0].count),
        results: parseInt(results.rows[0].count),
        finance: parseInt(finance.rows[0].count),
        materials: parseInt(materials.rows[0].count),
      });
    } else if (role === "admin") {
      const [studentsCount, teachersCount, classesCount] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM users WHERE role = 'student'"),
        pool.query("SELECT COUNT(*) FROM users WHERE role = 'teacher'"),
        pool.query("SELECT COUNT(*) FROM classes"),
      ]);
      res.json({
        students: parseInt(studentsCount.rows[0].count),
        teachers: parseInt(teachersCount.rows[0].count),
        classes: parseInt(classesCount.rows[0].count),
      });
    } else {
      res.status(400).json({ error: "Invalid role" });
    }
  } catch (e) {
    console.error("Dashboard Summary Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== STUDENTS =====================
app.get("/students", async (req, res) => {
  const { page = 0, pageSize = 20, search = "" } = req.query;
  const offset = parseInt(page) * parseInt(pageSize);
  try {
    const query = `
      SELECT * FROM students 
      WHERE full_name ILIKE $1 OR email ILIKE $1 
      ORDER BY full_name ASC 
      LIMIT $2 OFFSET $3`;
    const studentsResult = await pool.query(query, [`%${search}%`, pageSize, offset]);

    const totalResult = await pool.query(
      "SELECT COUNT(*) FROM students WHERE full_name ILIKE $1 OR email ILIKE $1",
      [`%${search}%`]
    );

    res.json({ data: studentsResult.rows, total: parseInt(totalResult.rows[0].count) });
  } catch (e) {
    console.error("Students Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/update-student/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;
  try {
    await pool.query("UPDATE students SET full_name = $1, email = $2 WHERE id = $3", [name, email, id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Update Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/delete-student/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM students WHERE id = $1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== TEACHERS =====================
app.get("/teachers", async (req, res) => {
  const { page = 0, pageSize = 20, search = "" } = req.query;
  const offset = parseInt(page) * parseInt(pageSize);
  try {
    const query = `
      SELECT * FROM teachers 
      WHERE full_name ILIKE $1 OR email ILIKE $1 
      ORDER BY full_name ASC 
      LIMIT $2 OFFSET $3`;
    const teachersResult = await pool.query(query, [`%${search}%`, pageSize, offset]);

    const totalResult = await pool.query(
      "SELECT COUNT(*) FROM teachers WHERE full_name ILIKE $1 OR email ILIKE $1",
      [`%${search}%`]
    );

    res.json({ data: teachersResult.rows, total: parseInt(totalResult.rows[0].count) });
  } catch (e) {
    console.error("Teachers Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/update-teacher/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;
  try {
    await pool.query("UPDATE teachers SET full_name = $1, email = $2 WHERE id = $3", [name, email, id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Update Teacher Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/delete-teacher/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM teachers WHERE id = $1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Teacher Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== STUDENT FEATURES =====================
app.get("/exams/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(
      `SELECT e.* FROM exams e 
       JOIN results r ON r.exam_id = e.id 
       JOIN students s ON s.id = r.student_id 
       WHERE s.email = $1 ORDER BY e.exam_date DESC`,
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
    const result = await pool.query(
      `SELECT r.* FROM results r 
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
    const result = await pool.query(
      `SELECT f.* FROM finance f 
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
    const result = await pool.query(
      `SELECT m.* FROM materials m 
       JOIN students s ON s.class_id = m.class_id 
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
    const result = await pool.query(
      `SELECT a.* FROM attendance a 
       JOIN students s ON s.id = a.student_id 
       WHERE s.email = $1 ORDER BY a.date DESC`,
      [studentEmail]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Attendance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== STUDENT PROFILE =====================
app.get("/student-profile/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const result = await pool.query(
      `SELECT s.full_name, s.class_name, s.admission_number, s.email, s.phone, s.date_of_birth, s.address,
              (SELECT COUNT(*) FROM attendance WHERE student_id = s.id AND status = 'present') * 100.0 / 
              NULLIF((SELECT COUNT(*) FROM attendance WHERE student_id = s.id), 0) as attendance_percentage
       FROM students s WHERE s.email = $1`,
      [email]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Student Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== MESSAGES =====================
app.get("/messages/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const studentResult = await pool.query("SELECT id FROM students WHERE email = $1", [studentEmail]);
    if (studentResult.rows.length === 0) return res.status(404).json({ error: "Student not found" });

    const studentId = studentResult.rows[0].id;
    const messagesResult = await pool.query(
      `SELECT m.id, m.message, m.sender_role, m.created_at 
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

app.post("/send-message", async (req, res) => {
  const { studentEmail, message, sender = "admin" } = req.body;
  if (!studentEmail || !message) return res.status(400).json({ error: "studentEmail and message are required" });

  try {
    const studentResult = await pool.query("SELECT id FROM students WHERE email = $1", [studentEmail]);
    if (studentResult.rows.length === 0) return res.status(404).json({ error: "Student not found" });

    const studentId = studentResult.rows[0].id;
    const senderId = sender === "admin" ? null : studentId;

    const result = await pool.query(
      "INSERT INTO messages (id, sender_id, receiver_id, message, sender_role, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *",
      [uuidv4(), senderId, studentId, message, sender]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error("Send Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/delete-message/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM messages WHERE id = $1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== MODERATION =====================
app.post("/warn-student", async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query("UPDATE students SET warnings = warnings + 1 WHERE email = $1", [email]);
    res.json({ success: true });
  } catch (e) {
    console.error("Warn Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/block-student", async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query("UPDATE students SET blocked = true WHERE email = $1", [email]);
    res.json({ success: true });
  } catch (e) {
    console.error("Block Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ School Management Backend running on port ${PORT}`);
});