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

// Register - Only students (parents register separately)
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO registration (username, email, password, role)
       VALUES ($1, $2, $3, 'student')
       RETURNING id, username, email, role, approved`,
      [username, email, hashedPassword]
    );

    console.log(`New student registration: ${email}`);
    res.status(201).json({
      message: "Registration submitted! Pending admin approval.",
      registration: result.rows[0]
    });
  } catch (e) {
    console.error("Register Error:", e);
    if (e.code === '23505') {
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: e.message });
  }
});

// Login - All roles (student, teacher, parent)
app.post("/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    console.log(`Login attempt: ${usernameOrEmail}`);

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $1",
      [usernameOrEmail]
    );

    if (result.rows.length === 0) {
      console.log("No user found");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      console.log("Password incorrect");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Force lowercase role
    const role = (user.role || 'unknown').toLowerCase().trim();

    console.log(`Login success → Email: ${user.email}, Role: ${role}`);

    res.status(200).json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: role  // always lowercase
      }
    });
  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Admin Login
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

// ===================== PARENT REGISTRATION =====================
app.post("/parent/register", async (req, res) => {
  const { username, email, password, full_name, phone } = req.body;
  if (!username || !email || !password || !full_name) {
    return res.status(400).json({ error: "Required fields missing" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, 'parent') RETURNING id",
      [username, email, hashedPassword]
    );
    const userId = userResult.rows[0].id;

    await pool.query(
      "INSERT INTO parents (user_id, full_name, phone) VALUES ($1, $2, $3)",
      [userId, full_name, phone || null]
    );

    console.log(`New parent registered: ${email}`);
    res.status(201).json({ message: "Parent account created successfully" });
  } catch (e) {
    console.error("Parent Register Error:", e);
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
    const regResult = await pool.query("SELECT * FROM registration WHERE id = $1", [id]);
    if (regResult.rows.length === 0) {
      return res.status(404).json({ error: "Registration not found" });
    }

    const reg = regResult.rows[0];
    const role = (reg.role || 'student').toLowerCase().trim();

    const userResult = await pool.query(
      "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id",
      [reg.username, reg.email, reg.password, role]
    );
    const userId = userResult.rows[0].id;

    if (role === 'parent') {
      await pool.query(
        "INSERT INTO parents (user_id, full_name) VALUES ($1, $2)",
        [userId, reg.username || 'New Parent']
      );
    }

    await pool.query(
      "UPDATE registration SET approved = true, approved_at = NOW(), approved_by = (SELECT id FROM admins LIMIT 1) WHERE id = $1",
      [id]
    );

    console.log(`Approved registration ${id} → Role: ${role}`);
    res.json({ message: "User approved successfully" });
  } catch (e) {
    console.error("Approval Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== PARENT FEATURES =====================
app.get("/parent/children/:parentEmail", async (req, res) => {
  const { parentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT s.full_name, s.class_name, s.admission_number, s.email
      FROM parent_child pc
      JOIN parents p ON pc.parent_id = p.id
      JOIN students s ON pc.student_id = s.id
      JOIN users u ON p.user_id = u.id
      WHERE u.email = $1
    `, [parentEmail]);

    res.json(result.rows);
  } catch (e) {
    console.error("Get Parent Children Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/parent/messages/:parentEmail", async (req, res) => {
  const { parentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT m.id, m.message, m.sender_role, m.created_at, m.is_read
      FROM messages m
      JOIN users u ON m.receiver_id = u.id OR m.sender_id = u.id
      WHERE u.email = $1
      ORDER BY m.created_at DESC
    `, [parentEmail]);

    res.json(result.rows);
  } catch (e) {
    console.error("Parent Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== REUSED STUDENT FEATURES =====================
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

app.get("/messages/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const userResult = await pool.query("SELECT id, role FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const userId = userResult.rows[0].id;
    const role = userResult.rows[0].role.toLowerCase();

    let query = `
      SELECT m.id, m.message, m.sender_role, m.created_at, m.is_read
      FROM messages m
      WHERE m.receiver_id = $1 OR m.sender_id = $1
      ORDER BY m.created_at DESC
    `;
    const result = await pool.query(query, [userId]);

    res.json(result.rows);
  } catch (e) {
    console.error("Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Teacher marks attendance for a class on a specific date
app.post("/attendance/mark", async (req, res) => {
  const { teacherEmail, studentIds, date, statusArray } = req.body; // statusArray = array of 'present'/'absent'/'late'

  if (!teacherEmail || !studentIds || !date || !Array.isArray(statusArray)) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Verify teacher exists (optional)
    const teacher = await pool.query("SELECT id FROM users WHERE email = $1 AND role = 'teacher'", [teacherEmail]);
    if (teacher.rows.length === 0) return res.status(403).json({ error: "Unauthorized" });

    const results = [];
    for (let i = 0; i < studentIds.length; i++) {
      const studentId = studentIds[i];
      const status = statusArray[i];

      // Upsert (insert or update if already exists for that date)
      const result = await pool.query(`
        INSERT INTO attendance (student_id, date, status)
        VALUES ($1, $2, $3)
        ON CONFLICT (student_id, date)
        DO UPDATE SET status = $3
        RETURNING id, student_id, date, status
      `, [studentId, date, status]);

      results.push(result.rows[0]);
    }

    res.status(200).json({ message: "Attendance marked", records: results });
  } catch (e) {
    console.error("Mark Attendance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Get attendance for teacher's class on a date (or all recent)
app.get("/attendance/class/:teacherEmail", async (req, res) => {
  const { teacherEmail } = req.params;
  const { date } = req.query; // optional YYYY-MM-DD

  try {
    let query = `
      SELECT a.*, s.full_name, s.class_name
      FROM attendance a
      JOIN students s ON a.student_id = s.id
      JOIN teachers t ON s.class_name = t.class_name OR 1=1 -- adjust based on your relation
      JOIN users u ON t.user_id = u.id
      WHERE u.email = $1
    `;
    const params = [teacherEmail];

    if (date) {
      query += " AND a.date = $2";
      params.push(date);
    }

    query += " ORDER BY a.date DESC, s.full_name";

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (e) {
    console.error("Get Class Attendance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/live-classes/create", async (req, res) => {
  const { teacherEmail, title, subjectId, className, meetingLink, classTime } = req.body;

  if (!teacherEmail || !title || !meetingLink || !classTime) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const teacher = await pool.query("SELECT id FROM users WHERE email = $1 AND role = 'teacher'", [teacherEmail]);
    if (teacher.rows.length === 0) return res.status(403).json({ error: "Unauthorized" });

    const result = await pool.query(
      `INSERT INTO live_classes (teacher_id, title, subject_id, meeting_link, class_time, class_name)
       VALUES ((SELECT id FROM teachers WHERE user_id = (SELECT id FROM users WHERE email = $1)), $2, $3, $4, $5, $6)
       RETURNING *`,
      [teacherEmail, title, subjectId || null, meetingLink, classTime, className || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Create Live Class Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/teacher/performance/:teacherEmail", async (req, res) => {
  const { teacherEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT s.full_name, s.class_name,
             AVG(r.marks * 100.0 / NULLIF(e.total_marks, 0)) as average_score
      FROM students s
      LEFT JOIN results r ON r.student_id = s.id
      LEFT JOIN exams e ON r.exam_id = e.id
      WHERE s.class_name IN (
        SELECT class_name FROM teachers WHERE user_id = (SELECT id FROM users WHERE email = $1)
      )
      GROUP BY s.id, s.full_name, s.class_name
      ORDER BY average_score DESC
    `, [teacherEmail]);

    res.json(result.rows);
  } catch (e) {
    console.error("Teacher Performance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/teacher-profile/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const result = await pool.query(`
      SELECT t.full_name, t.subject, t.phone, t.profile_picture_url,
             COUNT(DISTINCT c.id) as total_classes,
             (SELECT COUNT(DISTINCT s.id) 
              FROM students s 
              WHERE s.class_name = t.class_name) as total_students
      FROM teachers t
      JOIN users u ON t.user_id = u.id
      LEFT JOIN classes c ON c.teacher_id = t.id
      WHERE u.email = $1
      GROUP BY t.id
    `, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Teacher not found" });
    }

    res.json(result.rows[0]);
  } catch (e) {
    console.error("Teacher Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/parent/link-child", async (req, res) => {
  const { parentId, childIdentifier } = req.body;
  try {
    // Find child by email or admission_number
    const childQuery = await pool.query(
      "SELECT id FROM students WHERE email = $1 OR admission_number = $1",
      [childIdentifier]
    );
    if (childQuery.rows.length === 0) return res.status(404).json({ error: "Child not found" });

    const childId = childQuery.rows[0].id;

    // Link (assuming parent_child table exists)
    await pool.query(
      "INSERT INTO parent_child (parent_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [parentId, childId]
    );

    res.json({ message: "Child linked successfully" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ School Management Backend running on port ${PORT}`);
});
