// ---------------- IMPORTS ----------------
require('dotenv').config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

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
app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "school_backend",
    timestamp: new Date().toISOString(),
  });
});

// ===================== AUTH =====================

const otpChallenges = new Map();
const OTP_EXPIRY_MS = Number(process.env.OTP_EXPIRY_MS || 10 * 60 * 1000);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_DEV_PREVIEW = process.env.OTP_DEV_PREVIEW !== "false";
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return EMAIL_REGEX.test(normalizeEmail(email));
}

function normalizeOtpChannel(channel) {
  return String(channel || "email").toLowerCase().trim();
}

function cleanupExpiredOtpChallenges() {
  const now = Date.now();
  for (const [challengeId, challenge] of otpChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      otpChallenges.delete(challengeId);
    }
  }
}

function generateOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function maskValue(value, type = "email") {
  if (!value) return null;

  if (type === "phone") {
    const digits = String(value).replace(/\D/g, "");
    if (digits.length <= 4) return `••${digits}`;
    return `••••${digits.slice(-4)}`;
  }

  const [localPart, domain = ""] = String(value).split("@");
  if (!domain) return "••••";

  const visibleLocal = localPart.length <= 2
    ? `${localPart[0] || ""}•`
    : `${localPart.slice(0, 2)}•••`;
  return `${visibleLocal}@${domain}`;
}

async function authenticateAdminLogin(usernameOrEmail, password) {
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.password_hash, u.role
     FROM users u
     LEFT JOIN admins a ON a.user_id = u.id
     WHERE (u.username = $1 OR u.email = $1) AND u.role = 'admin'
     LIMIT 1`,
    [usernameOrEmail]
  );

  if (result.rows.length === 0) {
    return { status: 401, body: { error: "Invalid credentials" } };
  }

  const adminUser = result.rows[0];
  const valid = await bcrypt.compare(password, adminUser.password_hash);

  if (!valid) {
    return { status: 401, body: { error: "Invalid credentials" } };
  }

  return {
    status: 200,
    body: {
      user: {
        id: adminUser.id,
        username: adminUser.username,
        email: adminUser.email,
        role: "admin"
      }
    }
  };
}

async function authenticateLoginAttempt(usernameOrEmail, password, expectedRole = null) {
  const normalizedExpectedRole = expectedRole
    ? String(expectedRole).toLowerCase().trim()
    : null;

  if (normalizedExpectedRole === "admin") {
    return authenticateAdminLogin(usernameOrEmail, password);
  }

  return loginUserFromUsersTable(usernameOrEmail, password, normalizedExpectedRole);
}

async function resolveOtpDestinations(user) {
  const destinations = {};
  if (user.email) {
    destinations.email = user.email;
  }

  try {
    if (user.role === "student") {
      const result = await pool.query(
        `SELECT s.phone
         FROM students s
         JOIN users u ON s.user_id = u.id
         WHERE u.email = $1
         LIMIT 1`,
        [user.email]
      );
      const phone = result.rows[0]?.phone;
      if (phone) destinations.sms = phone;
    }

    if (user.role === "teacher") {
      const result = await pool.query(
        `SELECT t.phone
         FROM teachers t
         JOIN users u ON t.user_id = u.id
         WHERE u.email = $1
         LIMIT 1`,
        [user.email]
      );
      const phone = result.rows[0]?.phone;
      if (phone) destinations.sms = phone;
    }

    if (user.role === "parent") {
      const result = await pool.query(
        `SELECT p.phone
         FROM parents p
         JOIN users u ON p.user_id = u.id
         WHERE u.email = $1
         LIMIT 1`,
        [user.email]
      );
      const phone = result.rows[0]?.phone;
      if (phone) destinations.sms = phone;
    }

    if (user.role === "admin") {
      const result = await pool.query(
        `SELECT a.phone
         FROM admins a
         JOIN users u ON a.user_id = u.id
         WHERE u.email = $1
         LIMIT 1`,
        [user.email]
      );
      const phone = result.rows[0]?.phone;
      if (phone) destinations.sms = phone;
    }
  } catch (e) {
    console.error("Resolve OTP destinations error:", e);
  }

  return destinations;
}

function getOtpWebhookUrl(channel) {
  if (channel === "sms") {
    return process.env.OTP_SMS_WEBHOOK_URL || process.env.OTP_WEBHOOK_URL || null;
  }
  return process.env.OTP_EMAIL_WEBHOOK_URL || process.env.OTP_WEBHOOK_URL || null;
}

async function deliverOtp({ user, channel, destination, code }) {
  const webhookUrl = getOtpWebhookUrl(channel);
  const message = `Your eSchool verification code is ${code}. It expires in 10 minutes.`;

  if (webhookUrl) {
    try {
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channel,
          destination,
          code,
          message,
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            username: user.username
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Webhook responded with ${response.status}`);
      }

      return {
        deliveryMode: "webhook",
        previewCode: null
      };
    } catch (e) {
      console.error(`OTP ${channel} webhook failed:`, e);
    }
  }

  console.log(`[OTP ${channel.toUpperCase()}] ${destination} => ${code}`);
  return {
    deliveryMode: "preview",
    previewCode: OTP_DEV_PREVIEW ? code : null
  };
}

async function loginUserFromUsersTable(usernameOrEmail, password, enforcedRole = null) {
  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1 OR email = $1",
    [usernameOrEmail]
  );

  if (result.rows.length === 0) {
    return { status: 401, body: { error: "Invalid credentials" } };
  }

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);

  if (!valid) {
    return { status: 401, body: { error: "Invalid credentials" } };
  }

  const role = (user.role || "unknown").toLowerCase().trim();
  const normalizedExpectedRole = enforcedRole
    ? String(enforcedRole).toLowerCase().trim()
    : null;

  if (normalizedExpectedRole && role !== normalizedExpectedRole) {
    return {
      status: 403,
      body: {
        error: `This app accepts ${normalizedExpectedRole} accounts only`,
        actualRole: role
      }
    };
  }

  return {
    status: 200,
    body: {
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: role
      }
    }
  };
}

// Register - Student / Teacher / Parent approval requests
app.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const normalizedRole = String(role || "student").toLowerCase().trim();
  const allowedRoles = new Set(["student", "teacher", "parent"]);

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: "A valid email address is required" });
  }

  if (!allowedRoles.has(normalizedRole)) {
    return res.status(400).json({ error: "Unsupported registration role" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO registration (username, email, password, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, role, approved`,
      [username, normalizedEmail, hashedPassword, normalizedRole]
    );

    console.log(`New ${normalizedRole} registration: ${normalizedEmail}`);
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

// Login - All roles with optional role enforcement
app.post("/login", async (req, res) => {
  const { usernameOrEmail, password, expectedRole } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    console.log(`Login attempt: ${usernameOrEmail}`);
    const result = await loginUserFromUsersTable(usernameOrEmail, password, expectedRole);
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/student-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await loginUserFromUsersTable(usernameOrEmail, password, "student");
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Student Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/teacher-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await loginUserFromUsersTable(usernameOrEmail, password, "teacher");
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Teacher Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/parent-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await loginUserFromUsersTable(usernameOrEmail, password, "parent");
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Parent Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/finance-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await loginUserFromUsersTable(usernameOrEmail, password, "finance");
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Finance Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/login-otp/request", async (req, res) => {
  const {
    usernameOrEmail,
    password,
    expectedRole,
    channel,
  } = req.body;

  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  cleanupExpiredOtpChallenges();

  try {
    const authResult = await authenticateLoginAttempt(usernameOrEmail, password, expectedRole);
    if (authResult.status !== 200) {
      return res.status(authResult.status).json(authResult.body);
    }

    const user = authResult.body.user;
    const requestedChannel = normalizeOtpChannel(channel);
    const destinations = await resolveOtpDestinations(user);
    const availableChannels = Object.keys(destinations);

    if (!availableChannels.length) {
      return res.status(400).json({
        error: "No OTP delivery destination is configured for this account",
      });
    }

    if (!destinations[requestedChannel]) {
      return res.status(400).json({
        error: `${requestedChannel.toUpperCase()} OTP is not available for this account`,
        availableChannels,
        maskedDestinations: {
          email: maskValue(destinations.email, "email"),
          sms: maskValue(destinations.sms, "phone"),
        }
      });
    }

    const challengeId = uuidv4();
    const code = generateOtpCode();
    const expiresAt = Date.now() + OTP_EXPIRY_MS;
    const destination = destinations[requestedChannel];
    const delivery = await deliverOtp({
      user,
      channel: requestedChannel,
      destination,
      code,
    });

    otpChallenges.set(challengeId, {
      attempts: 0,
      code,
      user,
      channel: requestedChannel,
      expiresAt,
    });

    return res.status(200).json({
      challengeId,
      channel: requestedChannel,
      destinationMasked: maskValue(
        destination,
        requestedChannel === "sms" ? "phone" : "email"
      ),
      availableChannels,
      maskedDestinations: {
        email: maskValue(destinations.email, "email"),
        sms: maskValue(destinations.sms, "phone"),
      },
      expiresAt: new Date(expiresAt).toISOString(),
      deliveryMode: delivery.deliveryMode,
      previewCode: delivery.previewCode,
    });
  } catch (e) {
    console.error("Login OTP Request Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/login-otp/verify", async (req, res) => {
  const { challengeId, code } = req.body;

  if (!challengeId || !code) {
    return res.status(400).json({ error: "Challenge ID and verification code required" });
  }

  cleanupExpiredOtpChallenges();
  const challenge = otpChallenges.get(challengeId);

  if (!challenge) {
    return res.status(404).json({ error: "OTP challenge expired or was not found" });
  }

  if (challenge.expiresAt <= Date.now()) {
    otpChallenges.delete(challengeId);
    return res.status(410).json({ error: "OTP challenge has expired" });
  }

  challenge.attempts += 1;
  if (String(code).trim() !== challenge.code) {
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
      otpChallenges.delete(challengeId);
      return res.status(429).json({ error: "Too many incorrect verification attempts" });
    }

    return res.status(401).json({
      error: "Invalid verification code",
      remainingAttempts: OTP_MAX_ATTEMPTS - challenge.attempts,
    });
  }

  otpChallenges.delete(challengeId);
  return res.status(200).json({ user: challenge.user });
});

// Admin Login
app.post("/admin-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await authenticateAdminLogin(usernameOrEmail, password);
    res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Admin Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ===================== PARENT REGISTRATION =====================
app.post("/parent/register", async (req, res) => {
  const { username, email, password, full_name, phone } = req.body;
  const normalizedEmail = normalizeEmail(email);
  if (!username || !email || !password || !full_name) {
    return res.status(400).json({ error: "Required fields missing" });
  }

  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: "A valid email address is required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, 'parent') RETURNING id",
      [username, normalizedEmail, hashedPassword]
    );
    const userId = userResult.rows[0].id;

    await pool.query(
      "INSERT INTO parents (user_id, full_name, phone) VALUES ($1, $2, $3)",
      [userId, full_name, phone || null]
    );

    console.log(`New parent registered: ${normalizedEmail}`);
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
      SELECT s.full_name, s.class_name, s.admission_number, child_user.email
      FROM parent_child pc
      JOIN parents p ON pc.parent_id = p.id
      JOIN students s ON pc.student_id = s.id
      JOIN users u ON p.user_id = u.id
      LEFT JOIN users child_user ON child_user.id = s.user_id
      WHERE u.email = $1
    `, [normalizeEmail(parentEmail)]);

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
  const email = normalizeEmail(req.params.email);
  try {
    const result = await pool.query(`
      SELECT s.full_name, s.class_name, s.admission_number, u.email, s.phone,
             s.date_of_birth, s.address, s.profile_picture_url,
             (SELECT COUNT(*) FROM attendance WHERE student_id = s.id AND status = 'present') * 100.0 /
             NULLIF((SELECT COUNT(*) FROM attendance WHERE student_id = s.id), 0) as attendance_percentage
      FROM students s
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1`,
      [normalizeEmail(email)]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Student Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/student-profile/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const {
    full_name,
    gender,
    date_of_birth,
    class_name,
    phone,
    address,
    admission_number,
    profile_picture_url,
  } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "A valid email address is required" });
  }

  if (!full_name || !class_name || !admission_number) {
    return res.status(400).json({
      error: "Full name, class name, and admission number are required",
    });
  }

  try {
    const userResult = await pool.query(
      "SELECT id, role FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    if (user.role !== 'student') {
      return res.status(403).json({ error: "Only student accounts can update this profile" });
    }

    const upsertResult = await pool.query(
      `INSERT INTO students (
         user_id,
         admission_number,
         full_name,
         gender,
         date_of_birth,
         class_name,
         phone,
         address,
         profile_picture_url,
         updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET
         admission_number = EXCLUDED.admission_number,
         full_name = EXCLUDED.full_name,
         gender = EXCLUDED.gender,
         date_of_birth = EXCLUDED.date_of_birth,
         class_name = EXCLUDED.class_name,
         phone = EXCLUDED.phone,
         address = EXCLUDED.address,
         profile_picture_url = EXCLUDED.profile_picture_url,
         updated_at = NOW()
       RETURNING id`,
      [
        user.id,
        String(admission_number).trim(),
        String(full_name).trim(),
        gender ? String(gender).trim() : null,
        date_of_birth || null,
        String(class_name).trim(),
        phone ? String(phone).trim() : null,
        address ? String(address).trim() : null,
        profile_picture_url ? String(profile_picture_url).trim() : null,
      ]
    );

    const profileResult = await pool.query(`
      SELECT s.full_name, s.class_name, s.admission_number, u.email, s.phone,
             s.gender, s.date_of_birth, s.address, s.profile_picture_url,
             (SELECT COUNT(*) FROM attendance WHERE student_id = s.id AND status = 'present') * 100.0 /
             NULLIF((SELECT COUNT(*) FROM attendance WHERE student_id = s.id), 0) as attendance_percentage
      FROM students s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = $1
      LIMIT 1`,
      [upsertResult.rows[0].id]
    );

    res.status(200).json(profileResult.rows[0]);
  } catch (e) {
    console.error("Update Student Profile Error:", e);
    if (e.code === '23505') {
      return res.status(400).json({ error: "Admission number is already in use" });
    }
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
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1
      ORDER BY e.exam_date DESC`,
      [normalizeEmail(studentEmail)]
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
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1`,
      [normalizeEmail(studentEmail)]
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
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1`,
      [normalizeEmail(studentEmail)]
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
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1`,
      [normalizeEmail(studentEmail)]
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
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1
      ORDER BY a.date DESC`,
      [normalizeEmail(studentEmail)]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Attendance Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/messages/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
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
  const email = normalizeEmail(req.params.email);
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
      `SELECT s.id
       FROM students s
       LEFT JOIN users u ON s.user_id = u.id
       WHERE u.email = $1 OR s.admission_number = $2`,
      [normalizeEmail(childIdentifier), childIdentifier]
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
  console.log(`School Management Backend running on port ${PORT}`);
});




