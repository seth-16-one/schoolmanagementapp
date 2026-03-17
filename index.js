// ---------------- IMPORTS ----------------
require('dotenv').config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

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

// ---------------- ROOT ----------------
app.get("/", (req, res) => res.send("School Management Backend is running!"));

// ---------------- REGISTER ----------------
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO registration (username, email, password) VALUES ($1,$2,$3) RETURNING id, username, email, role, approved",
      [username, email, hashedPassword]
    );
    res.json({ message: "Registration submitted! Pending admin approval.", registration: result.rows[0] });
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
    await pool.query(
      "INSERT INTO users (id, username, email, password, role) VALUES ($1,$2,$3,$4,$5)",
      [uuidv4(), user.username, user.email, user.password, user.role]
    );
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
  if (!usernameOrEmail || !password) return res.status(400).json({ error: "Username/email and password required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE username=$1 OR email=$1", [usernameOrEmail]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid credentials" });

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
  if (!usernameOrEmail || !password) return res.status(400).json({ error: "Username/email and password required" });

  try {
    const result = await pool.query("SELECT * FROM admins WHERE username=$1 OR email=$1", [usernameOrEmail]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid admin credentials" });

    const admin = result.rows[0];
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid admin credentials" });

    res.json({ user: { id: admin.id, username: admin.username, email: admin.email } });
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

// ---------------- STUDENTS ----------------
app.get("/students", async (req, res) => {
  const { page = 0, pageSize = 20, search = "" } = req.query;
  try {
    const offset = page * pageSize;
    const query = `
      SELECT * FROM students 
      WHERE full_name ILIKE $1 OR email ILIKE $1
      ORDER BY full_name ASC
      LIMIT $2 OFFSET $3`;
    const studentsResult = await pool.query(query, [`%${search}%`, pageSize, offset]);
    const totalResult = await pool.query(`SELECT COUNT(*) FROM students WHERE full_name ILIKE $1 OR email ILIKE $1`, [`%${search}%`]);

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
    await pool.query("UPDATE students SET full_name=$1, email=$2 WHERE id=$3", [name, email, id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Update Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/delete-student/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM students WHERE id=$1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- TEACHERS ----------------
app.get("/teachers", async (req, res) => {
  const { page = 0, pageSize = 20, search = "" } = req.query;
  try {
    const offset = page * pageSize;
    const query = `
      SELECT * FROM teachers 
      WHERE full_name ILIKE $1 OR email ILIKE $1
      ORDER BY full_name ASC
      LIMIT $2 OFFSET $3`;
    const teachersResult = await pool.query(query, [`%${search}%`, pageSize, offset]);
    const totalResult = await pool.query(`SELECT COUNT(*) FROM teachers WHERE full_name ILIKE $1 OR email ILIKE $1`, [`%${search}%`]);

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
    await pool.query("UPDATE teachers SET full_name=$1, email=$2 WHERE id=$3", [name, email, id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Update Teacher Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/delete-teacher/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM teachers WHERE id=$1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Teacher Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- STUDENT FEATURES ----------------
app.get("/exams/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(
      `SELECT e.* FROM exams e
       JOIN results r ON r.exam_id=e.id
       JOIN students s ON s.id=r.student_id
       WHERE s.email=$1 ORDER BY e.exam_date DESC`, [studentEmail]
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
       JOIN students s ON s.id=r.student_id
       WHERE s.email=$1`, [studentEmail]
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
       JOIN students s ON s.id=f.student_id
       WHERE s.email=$1`, [studentEmail]
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
       JOIN students s ON s.class_id = s.class_id
       WHERE s.email=$1`, [studentEmail]
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

// ---------------- MESSAGES ----------------
app.get("/messages/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const studentResult = await pool.query("SELECT id FROM students WHERE email=$1", [studentEmail]);
    if (!studentResult.rows.length) return res.status(404).json({ error: "Student not found" });

    const studentId = studentResult.rows[0].id;

    const messagesResult = await pool.query(
      `SELECT m.id, m.message, m.sender_role, m.created_at
       FROM messages m
       WHERE m.receiver_id = $1 OR m.sender_id = $1
       ORDER BY m.created_at ASC`, [studentId]
    );
    res.json(messagesResult.rows);
  } catch (e) {
    console.error("Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/send-message", async (req, res) => {
  const { studentEmail, message, sender_role } = req.body;
  if (!studentEmail || !message || !sender_role)
    return res.status(400).json({ error: "studentEmail, message, and sender_role are required" });

  try {
    const studentResult = await pool.query("SELECT id FROM students WHERE email=$1", [studentEmail]);
    if (!studentResult.rows.length) return res.status(404).json({ error: "Student not found" });

    const studentId = studentResult.rows[0].id;
    const senderId = sender_role === "admin" ? null : studentId;

    const result = await pool.query(
      "INSERT INTO messages (id, sender_id, receiver_id, message, sender_role, created_at) VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *",
      [uuidv4(), senderId, studentId, message, sender_role]
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
    await pool.query("DELETE FROM messages WHERE id=$1", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error("Delete Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- MODERATION ----------------
app.post("/warn-student", async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query("UPDATE students SET warnings = warnings + 1 WHERE email=$1", [email]);
    res.json({ success: true });
  } catch (e) {
    console.error("Warn Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/block-student", async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query("UPDATE students SET blocked=true WHERE email=$1", [email]);
    res.json({ success: true });
  } catch (e) {
    console.error("Block Student Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ---------------- DASHBOARD SUMMARY ----------------
app.get("/dashboard-summary/:role/:email", async (req, res) => {
  const { role, email } = req.params;
  try {
    if (role === "student") {
      const [resultsCount, financeCount, materialsCount] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM results r JOIN students s ON s.id=r.student_id WHERE s.email=$1", [email]),
        pool.query("SELECT COUNT(*) FROM finance f JOIN students s ON s.id=f.student_id WHERE s.email=$1", [email]),
        pool.query("SELECT COUNT(*) FROM materials m JOIN students s ON s.class_id = s.class_id WHERE s.email=$1", [email]),
      ]);
      res.json({
        results: parseInt(resultsCount.rows[0].count),
        finance: parseInt(financeCount.rows[0].count),
        materials: parseInt(materialsCount.rows[0].count),
      });
    } else if (role === "admin") {
      const [studentsCount, teachersCount, examsCount] = await Promise.all([
        pool.query("SELECT COUNT(*) FROM users"),
        pool.query("SELECT COUNT(*) FROM teachers"),
        pool.query("SELECT COUNT(*) FROM exams"),
      ]);
      res.json({
        students: parseInt(studentsCount.rows[0].count),
        teachers: parseInt(teachersCount.rows[0].count),
        exams: parseInt(examsCount.rows[0].count),
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
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));