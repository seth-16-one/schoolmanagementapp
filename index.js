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

async function markUserPresenceById(userId, isActive = true) {
  if (!userId) return;
  await pool.query(
    `UPDATE users
     SET last_login = NOW(),
         is_active = $2
     WHERE id = $1`,
    [userId, isActive]
  );
}

async function getUserByEmail(email) {
  const normalizedEmail = normalizeEmail(email);
  const result = await pool.query(
    `SELECT id, username, email, role, last_login, is_active
     FROM users
     WHERE email = $1
     LIMIT 1`,
    [normalizedEmail]
  );
  return result.rows[0] || null;
}

async function getStudentRecordByEmail(email) {
  const normalizedEmail = normalizeEmail(email);
  const result = await pool.query(
    `SELECT s.id,
            s.user_id,
            s.full_name,
            s.class_name,
            s.admission_number,
            u.email
     FROM students s
     JOIN users u ON u.id = s.user_id
     WHERE u.email = $1
     LIMIT 1`,
    [normalizedEmail]
  );
  return result.rows[0] || null;
}

async function ensureAdminUser(email) {
  const user = await getUserByEmail(email);
  if (!user || user.role !== 'admin') {
    return null;
  }
  return user;
}

function looksLikeViolation(messageText) {
  const text = String(messageText || '').toLowerCase();
  if (!text) return false;
  const riskyTerms = [
    'nude',
    'nudes',
    'explicit',
    'sex',
    'porn',
    'private photo',
    'private video',
    'leak',
    'send pic'
  ];
  return riskyTerms.some((term) => text.includes(term));
}

async function ensureAcceptedFriendship(userId, otherUserId) {
  const result = await pool.query(
    `SELECT id
     FROM friend_requests
     WHERE status = 'accepted'
       AND (
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       )
     LIMIT 1`,
    [userId, otherUserId]
  );
  return result.rows.length > 0;
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

  await markUserPresenceById(adminUser.id, true);

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

  await markUserPresenceById(user.id, true);

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
  const { username, email, password, role, full_name, phone } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const normalizedRole = String(role || "student").toLowerCase().trim();
  const normalizedUsername = String(username || "").trim();
  const normalizedFullName = String(full_name || "").trim();
  const normalizedPhone = String(phone || "").trim();
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
      `INSERT INTO registration (username, email, password_hash, role, full_name, phone)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, role, approved, full_name, phone`,
      [
        normalizedUsername,
        normalizedEmail,
        hashedPassword,
        normalizedRole,
        normalizedFullName || null,
        normalizedPhone || null,
      ]
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
             s.gender, s.date_of_birth, s.address, s.profile_picture_url,
             s.profile_locked, s.updated_at,
             (SELECT COUNT(*) FROM attendance WHERE student_id = s.id AND status = 'present') * 100.0 /
             NULLIF((SELECT COUNT(*) FROM attendance WHERE student_id = s.id), 0) as attendance_percentage
      FROM students s
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1
      LIMIT 1`,
      [email]
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
    const normalizedPicture =
      typeof profile_picture_url === "string" && profile_picture_url.trim().length > 0
        ? profile_picture_url.trim()
        : null;
    const adminOverrideKey = process.env.ADMIN_PROFILE_OVERRIDE_KEY;
    const hasAdminOverride =
      adminOverrideKey &&
      req.get("x-admin-profile-override") === adminOverrideKey;

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

    const existingProfile = await pool.query(
      "SELECT id, profile_locked FROM students WHERE user_id = $1 LIMIT 1",
      [user.id]
    );

    if (
      existingProfile.rows.length > 0 &&
      existingProfile.rows[0].profile_locked === true &&
      !hasAdminOverride
    ) {
      return res.status(403).json({
        error: "This student profile is locked. Ask an admin to edit it.",
      });
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
         profile_locked,
         updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, NOW())
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
         profile_locked = true,
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
        normalizedPicture,
      ]
    );

    const profileResult = await pool.query(`
      SELECT s.full_name, s.class_name, s.admission_number, u.email, s.phone,
             s.gender, s.date_of_birth, s.address, s.profile_picture_url,
             s.profile_locked, s.updated_at,
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
      SELECT e.*, COALESCE(sub.subject_name, 'General') AS subject_name
      FROM exams e
      JOIN results r ON r.exam_id = e.id
      JOIN students s ON s.id = r.student_id
      JOIN users u ON s.user_id = u.id
      LEFT JOIN subjects sub ON sub.id = e.subject_id
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
      SELECT r.*,
             e.exam_name,
             e.exam_date,
             e.total_marks,
             COALESCE(sub.subject_name, 'General') AS subject_name
      FROM results r
      JOIN students s ON s.id = r.student_id
      JOIN users u ON s.user_id = u.id
      LEFT JOIN exams e ON e.id = r.exam_id
      LEFT JOIN subjects sub ON sub.id = e.subject_id
      WHERE u.email = $1
      ORDER BY e.exam_date DESC NULLS LAST, r.created_at DESC`,
      [normalizeEmail(studentEmail)]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Results Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/finance/dashboard-summary", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) AS total_paid,
        COALESCE(SUM(CASE WHEN status <> 'paid' OR status IS NULL THEN amount ELSE 0 END), 0) AS pending_fees,
        COALESCE(SUM(CASE WHEN status <> 'paid' OR status IS NULL THEN amount ELSE 0 END), 0) AS balance,
        COALESCE(SUM(
          CASE
            WHEN status = 'paid'
             AND DATE_TRUNC('month', COALESCE(payment_date, created_at)) = DATE_TRUNC('month', NOW())
            THEN amount
            ELSE 0
          END
        ), 0) AS monthly_payment
      FROM finance
    `);

    res.json(result.rows[0] || {});
  } catch (e) {
    console.error("Finance Dashboard Summary Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/finance/recent-transactions", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        f.id,
        f.fee_type AS description,
        f.amount,
        f.status,
        COALESCE(f.payment_date, f.created_at) AS transaction_date,
        s.full_name AS student_name
      FROM finance f
      LEFT JOIN students s ON s.id = f.student_id
      ORDER BY COALESCE(f.payment_date, f.created_at) DESC
      LIMIT 12
    `);

    res.json(result.rows);
  } catch (e) {
    console.error("Finance Recent Transactions Error:", e);
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
      WHERE u.email = $1
      ORDER BY COALESCE(f.payment_date, f.created_at) DESC`,
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
      SELECT m.*,
             COALESCE(t.full_name, 'Teacher') AS teacher_name,
             COALESCE(sub.subject_name, 'General') AS subject_name
      FROM materials m
      JOIN students s ON s.class_name = m.class_name
      JOIN users u ON s.user_id = u.id
      LEFT JOIN teachers t ON t.id = m.teacher_id
      LEFT JOIN subjects sub ON sub.id = m.subject_id
      WHERE u.email = $1
      ORDER BY m.created_at DESC`,
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

app.get("/assignments/:studentEmail", async (req, res) => {
  const studentEmail = normalizeEmail(req.params.studentEmail);
  const submittedOnly = String(req.query.submitted || "").toLowerCase() === "true";

  try {
    const student = await getStudentRecordByEmail(studentEmail);
    if (!student) {
      return res.status(404).json({ error: "Student not found" });
    }

    const result = await pool.query(
      `SELECT a.id,
              a.title,
              a.description,
              a.class_name,
              a.attachment_url,
              a.youtube_url,
              a.assigned_at,
              a.due_date,
              a.status,
              a.subject_id,
              a.teacher_id,
              COALESCE(sub.subject_name, 'General') AS subject_name,
              COALESCE(t.full_name, 'Teacher') AS teacher_name,
              submission.id AS submission_id,
              submission.submission_text,
              submission.submission_file_url,
              submission.submitted_at,
              submission.status AS submission_status,
              submission.score,
              submission.feedback,
              COALESCE(submission.is_late, false) AS is_late,
              (submission.id IS NOT NULL) AS is_submitted
       FROM assignments a
       LEFT JOIN subjects sub ON sub.id = a.subject_id
       LEFT JOIN teachers t ON t.id = a.teacher_id
       LEFT JOIN assignment_submissions submission
         ON submission.assignment_id = a.id
        AND submission.student_id = $1
       WHERE (a.class_name IS NULL OR a.class_name = '' OR a.class_name = $2)
         AND ($3::boolean = false OR submission.id IS NOT NULL)
       ORDER BY COALESCE(a.due_date, a.assigned_at, NOW()) ASC`,
      [student.id, student.class_name || "", submittedOnly]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Assignments Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/assignments/:studentEmail/submitted", async (req, res) => {
  const studentEmail = normalizeEmail(req.params.studentEmail);

  try {
    const student = await getStudentRecordByEmail(studentEmail);
    if (!student) {
      return res.status(404).json({ error: "Student not found" });
    }

    const result = await pool.query(
      `SELECT a.id,
              a.title,
              a.description,
              a.class_name,
              a.attachment_url,
              a.youtube_url,
              a.assigned_at,
              a.due_date,
              a.status,
              a.subject_id,
              a.teacher_id,
              COALESCE(sub.subject_name, 'General') AS subject_name,
              COALESCE(t.full_name, 'Teacher') AS teacher_name,
              submission.id AS submission_id,
              submission.submission_text,
              submission.submission_file_url,
              submission.submitted_at,
              submission.status AS submission_status,
              submission.score,
              submission.feedback,
              COALESCE(submission.is_late, false) AS is_late,
              true AS is_submitted
       FROM assignments a
       JOIN assignment_submissions submission
         ON submission.assignment_id = a.id
        AND submission.student_id = $1
       LEFT JOIN subjects sub ON sub.id = a.subject_id
       LEFT JOIN teachers t ON t.id = a.teacher_id
       WHERE a.class_name IS NULL OR a.class_name = '' OR a.class_name = $2
       ORDER BY COALESCE(submission.submitted_at, a.due_date, a.assigned_at, NOW()) DESC`,
      [student.id, student.class_name || ""]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Submitted Assignments Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/assignments/:assignmentId/submit", async (req, res) => {
  const assignmentId = req.params.assignmentId;
  const studentEmail = normalizeEmail(req.body.studentEmail);
  const submissionText = String(req.body.submissionText || "").trim();
  const submissionFileUrl = req.body.submissionFileUrl || null;

  if (!studentEmail) {
    return res.status(400).json({ error: "Student email is required" });
  }

  if (!submissionText && !submissionFileUrl) {
    return res.status(400).json({ error: "Submission text or attachment is required" });
  }

  const client = await pool.connect();
  try {
    const student = await getStudentRecordByEmail(studentEmail);
    if (!student) {
      return res.status(404).json({ error: "Student not found" });
    }

    const assignmentResult = await client.query(
      `SELECT id, title, due_date
       FROM assignments
       WHERE id = $1
       LIMIT 1`,
      [assignmentId]
    );

    if (assignmentResult.rows.length === 0) {
      return res.status(404).json({ error: "Assignment not found" });
    }

    const assignment = assignmentResult.rows[0];
    const dueDate = assignment.due_date ? new Date(assignment.due_date) : null;
    const isLate = dueDate ? dueDate.getTime() < Date.now() : false;

    const result = await client.query(
      `INSERT INTO assignment_submissions (
         assignment_id,
         student_id,
         submission_text,
         submission_file_url,
         submitted_at,
         status,
         is_late
       )
       VALUES ($1, $2, $3, $4, NOW(), 'submitted', $5)
       ON CONFLICT (assignment_id, student_id)
       DO UPDATE SET
         submission_text = EXCLUDED.submission_text,
         submission_file_url = EXCLUDED.submission_file_url,
         submitted_at = NOW(),
         status = 'submitted',
         is_late = EXCLUDED.is_late
       RETURNING *`,
      [
        assignmentId,
        student.id,
        submissionText || null,
        submissionFileUrl,
        isLate,
      ]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES (
         $1,
         $2,
         $3,
         'assignment_submission',
         false
       )`,
      [
        student.user_id,
        'Assignment submitted',
        `Your submission for "${assignment.title}" was saved successfully.`,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Submit Assignment Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/live-classes/:studentEmail", async (req, res) => {
  const { studentEmail } = req.params;
  try {
    const result = await pool.query(`
      SELECT lc.*,
             COALESCE(t.full_name, 'Teacher') AS teacher_name,
             COALESCE(sub.subject_name, 'General') AS subject_name
      FROM live_classes lc
      LEFT JOIN teachers t ON t.id = lc.teacher_id
      LEFT JOIN subjects sub ON sub.id = lc.subject_id
      JOIN students s
        ON lc.class_name IS NULL
        OR lc.class_name = ''
        OR s.class_name = lc.class_name
      JOIN users u ON s.user_id = u.id
      WHERE u.email = $1
      ORDER BY lc.class_time DESC`,
      [normalizeEmail(studentEmail)]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Student Live Classes Error:", e);
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

      const query = `
        SELECT m.id,
               m.message,
               m.sender_role,
               m.created_at,
               m.is_read,
               COALESCE(
                 CASE WHEN m.sender_id = $1 THEN 'You' ELSE NULL END,
                 t.full_name,
                 p.full_name,
                 a.full_name,
                 sender_user.username,
                 sender_user.email,
                 INITCAP(COALESCE(m.sender_role, 'school'))
               ) AS sender_name,
               t.subject AS sender_subject
        FROM messages m
        LEFT JOIN users sender_user ON sender_user.id = m.sender_id
        LEFT JOIN teachers t ON t.user_id = sender_user.id
        LEFT JOIN parents p ON p.user_id = sender_user.id
        LEFT JOIN admins a ON a.user_id = sender_user.id
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

app.get("/notifications/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `SELECT id,
              title,
              message,
              type,
              sender_user_id,
              sender_role,
              audience,
              is_read,
              created_at
       FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Notifications Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/notifications/:id/read", async (req, res) => {
  const notificationId = req.params.id;
  try {
    const result = await pool.query(
      `UPDATE notifications
       SET is_read = true
       WHERE id = $1
       RETURNING id, is_read`,
      [notificationId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    res.json(result.rows[0]);
  } catch (e) {
    console.error("Mark Notification Read Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/admin/notifications/broadcast", async (req, res) => {
  const adminEmail = normalizeEmail(req.body.adminEmail);
  const title = String(req.body.title || "").trim();
  const message = String(req.body.message || "").trim();
  const type = String(req.body.type || "announcement").trim().toLowerCase();
  const audience = String(req.body.audience || "all").trim().toLowerCase();

  if (!title || !message) {
    return res.status(400).json({ error: "Title and message are required" });
  }

  const client = await pool.connect();
  try {
    const admin = await ensureAdminUser(adminEmail);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can broadcast notifications" });
    }

    await client.query("BEGIN");

    const usersResult = await client.query(
      audience === 'all'
        ? `SELECT id, role FROM users WHERE id <> $1`
        : `SELECT id, role FROM users WHERE id <> $1 AND role = $2`,
      audience === 'all' ? [admin.id] : [admin.id, audience]
    );

    for (const user of usersResult.rows) {
      await client.query(
        `INSERT INTO notifications (
           user_id,
           title,
           message,
           type,
           sender_user_id,
           sender_role,
           audience,
           is_read
         )
         VALUES ($1, $2, $3, $4, $5, 'admin', $6, false)`,
        [user.id, title, message, type, admin.id, audience]
      );
    }

    await client.query(
      `INSERT INTO notifications (
         user_id,
         title,
         message,
         type,
         sender_user_id,
         sender_role,
         audience,
         is_read
       )
       VALUES ($1, $2, $3, 'system', $1, 'admin', $4, false)`,
      [admin.id, 'Broadcast sent', `Your message "${title}" was sent to ${usersResult.rows.length} user(s).`, audience]
    );

    await client.query("COMMIT");
    res.status(201).json({ ok: true, recipients: usersResult.rows.length });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Admin Broadcast Notification Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/admin/database-summary/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const admin = await ensureAdminUser(email);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can access this resource" });
    }

    const summaryResult = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM students) AS students_count,
        (SELECT COUNT(*) FROM teachers) AS teachers_count,
        (SELECT COUNT(*) FROM parents) AS parents_count,
        (SELECT COUNT(*) FROM users) AS users_count,
        (SELECT COUNT(*) FROM pending_registrations_view) AS pending_users_count
    `).catch(async () => {
      return pool.query(`
        SELECT
          (SELECT COUNT(*) FROM students) AS students_count,
          (SELECT COUNT(*) FROM teachers) AS teachers_count,
          (SELECT COUNT(*) FROM parents) AS parents_count,
          (SELECT COUNT(*) FROM users) AS users_count,
          (SELECT COUNT(*) FROM registration WHERE approved = false) AS pending_users_count
      `);
    });

    const financeResult = await pool.query(`
      SELECT COALESCE(SUM(CASE WHEN status <> 'paid' THEN amount ELSE 0 END), 0) AS pending_fees
      FROM finance
    `);

    const moderationResult = await pool.query(`
      SELECT COUNT(*) AS flagged_messages
      FROM messages
      WHERE moderation_status IS NOT NULL
        AND moderation_status <> 'clear'
    `);

    res.json({
      ...summaryResult.rows[0],
      pending_fees: financeResult.rows[0]?.pending_fees ?? 0,
      flagged_messages: moderationResult.rows[0]?.flagged_messages ?? 0,
    });
  } catch (e) {
    console.error("Admin Database Summary Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/admin/chat/moderation/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const admin = await ensureAdminUser(email);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can access this resource" });
    }

    const result = await pool.query(`
      SELECT m.id,
             m.message,
             m.created_at,
             m.message_type,
             m.media_url,
             m.group_id,
             m.moderation_status,
             m.moderation_reason,
             m.flagged_at,
             sender.email AS sender_email,
             receiver.email AS receiver_email,
             COALESCE(ss.full_name, st.full_name, sp.full_name, sa.full_name, sender.username, sender.email) AS sender_name,
             COALESCE(rs.full_name, rt.full_name, rp.full_name, ra.full_name, receiver.username, receiver.email) AS receiver_name,
             g.name AS group_name,
             sender.role AS sender_role,
             receiver.role AS receiver_role
      FROM messages m
      LEFT JOIN users sender ON sender.id = m.sender_id
      LEFT JOIN users receiver ON receiver.id = m.receiver_id
      LEFT JOIN students ss ON ss.user_id = sender.id
      LEFT JOIN teachers st ON st.user_id = sender.id
      LEFT JOIN parents sp ON sp.user_id = sender.id
      LEFT JOIN admins sa ON sa.user_id = sender.id
      LEFT JOIN students rs ON rs.user_id = receiver.id
      LEFT JOIN teachers rt ON rt.user_id = receiver.id
      LEFT JOIN parents rp ON rp.user_id = receiver.id
      LEFT JOIN admins ra ON ra.user_id = receiver.id
      LEFT JOIN chat_groups g ON g.id = m.group_id
      ORDER BY m.created_at DESC
      LIMIT 300
    `);

    const messages = result.rows.map((row) => {
      const autoFlagged = looksLikeViolation(row.message);
      const moderationStatus = row.moderation_status || (autoFlagged ? 'flagged' : 'clear');
      const moderationReason = row.moderation_reason || (autoFlagged ? 'Potential privacy or explicit-content violation' : null);
      return {
        ...row,
        moderation_status: moderationStatus,
        moderation_reason: moderationReason,
        flagged: moderationStatus !== 'clear',
        target_user_email: row.sender_email,
        target_user_name: row.sender_name,
      };
    });

    const flaggedCount = messages.filter((item) => item.flagged).length;
    res.json({
      summary: {
        total_messages: messages.length,
        flagged_messages: flaggedCount,
        groups_involved: new Set(messages.filter((m) => m.group_name).map((m) => m.group_name)).size,
      },
      messages,
    });
  } catch (e) {
    console.error("Admin Chat Moderation Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/admin/chat/warn", async (req, res) => {
  const adminEmail = normalizeEmail(req.body.adminEmail);
  const targetEmail = normalizeEmail(req.body.targetEmail);
  const reason = String(req.body.reason || "").trim();
  const messageId = req.body.messageId || null;

  if (!targetEmail || !reason) {
    return res.status(400).json({ error: "Target email and reason are required" });
  }

  const client = await pool.connect();
  try {
    const admin = await ensureAdminUser(adminEmail);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can send warnings" });
    }

    const target = await getUserByEmail(targetEmail);
    if (!target) {
      return res.status(404).json({ error: "Target user not found" });
    }

    await client.query("BEGIN");

    await client.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES ($1, $2, $3, 'warning', false)`,
      [
        target.id,
        'Account Warning',
        `Admin warning: ${reason}. Continued violations may lead to account suspension.`,
      ]
    );

    await client.query(
      `INSERT INTO admin_warnings (admin_user_id, target_user_id, message_id, reason, status)
       VALUES ($1, $2, $3, $4, 'active')`,
      [admin.id, target.id, messageId, reason]
    );

    if (messageId) {
      await client.query(
        `UPDATE messages
         SET moderation_status = 'flagged',
             moderation_reason = $2,
             flagged_at = NOW()
         WHERE id = $1`,
        [messageId, reason]
      );
    }

    await client.query("COMMIT");
    res.status(201).json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Admin Chat Warning Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/announcements", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, title, message, priority, created_at
      FROM announcements
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (e) {
    console.error("Announcements Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/presence/ping", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    await markUserPresenceById(user.id, true);
    res.json({ ok: true });
  } catch (e) {
    console.error("Chat Presence Ping Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/presence/offline", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    await pool.query(
      `UPDATE users
       SET is_active = false,
           last_login = NOW()
       WHERE id = $1`,
      [user.id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("Chat Presence Offline Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/discover/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const search = String(req.query.q || "").trim();

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const likeSearch = `%${search}%`;
    const result = await pool.query(
      `SELECT u.id,
              u.email,
              u.role,
              u.last_login,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS display_name,
              COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url) AS profile_picture_url,
              EXISTS (
                SELECT 1
                FROM friend_requests fr
                WHERE fr.status = 'accepted'
                  AND (
                    (fr.sender_id = $1 AND fr.receiver_id = u.id)
                    OR
                    (fr.sender_id = u.id AND fr.receiver_id = $1)
                  )
              ) AS is_friend,
              (
                SELECT fr.status
                FROM friend_requests fr
                WHERE (
                  (fr.sender_id = $1 AND fr.receiver_id = u.id)
                  OR
                  (fr.sender_id = u.id AND fr.receiver_id = $1)
                )
                ORDER BY fr.created_at DESC
                LIMIT 1
              ) AS request_status,
              (
                SELECT CASE WHEN fr.sender_id = $1 THEN 'outgoing' ELSE 'incoming' END
                FROM friend_requests fr
                WHERE (
                  (fr.sender_id = $1 AND fr.receiver_id = u.id)
                  OR
                  (fr.sender_id = u.id AND fr.receiver_id = $1)
                )
                ORDER BY fr.created_at DESC
                LIMIT 1
              ) AS request_direction,
              (u.last_login IS NOT NULL AND u.last_login >= NOW() - INTERVAL '5 minutes') AS is_online
       FROM users u
       LEFT JOIN students s ON s.user_id = u.id
       LEFT JOIN teachers t ON t.user_id = u.id
       LEFT JOIN parents p ON p.user_id = u.id
       LEFT JOIN admins a ON a.user_id = u.id
       WHERE u.id <> $1
         AND (
           $2 = ''
           OR u.email ILIKE $3
           OR u.username ILIKE $3
           OR COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, '') ILIKE $3
         )
       ORDER BY is_online DESC, COALESCE(u.last_login, u.created_at) DESC
       LIMIT 25`,
      [user.id, search, likeSearch]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Discover Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/friend-requests/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `SELECT fr.id,
              fr.status,
              fr.created_at,
              CASE WHEN fr.receiver_id = $1 THEN 'incoming' ELSE 'outgoing' END AS direction,
              peer.id AS peer_id,
              peer.email AS peer_email,
              peer.role AS peer_role,
              peer.last_login AS peer_last_login,
              (peer.last_login IS NOT NULL AND peer.last_login >= NOW() - INTERVAL '5 minutes') AS peer_is_online,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, peer.username, peer.email) AS peer_name,
              COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url) AS peer_profile_picture_url
       FROM friend_requests fr
       JOIN users peer
         ON peer.id = CASE WHEN fr.sender_id = $1 THEN fr.receiver_id ELSE fr.sender_id END
       LEFT JOIN students s ON s.user_id = peer.id
       LEFT JOIN teachers t ON t.user_id = peer.id
       LEFT JOIN parents p ON p.user_id = peer.id
       LEFT JOIN admins a ON a.user_id = peer.id
       WHERE fr.sender_id = $1 OR fr.receiver_id = $1
       ORDER BY fr.created_at DESC`,
      [user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Friend Requests Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/friend-requests", async (req, res) => {
  const senderEmail = normalizeEmail(req.body.senderEmail);
  const receiverEmail = normalizeEmail(req.body.receiverEmail);

  try {
    const sender = await getUserByEmail(senderEmail);
    const receiver = await getUserByEmail(receiverEmail);

    if (!sender || !receiver) {
      return res.status(404).json({ error: "Sender or receiver was not found" });
    }

    if (sender.id === receiver.id) {
      return res.status(400).json({ error: "You cannot send a friend request to yourself" });
    }

    const existing = await pool.query(
      `SELECT id, status
       FROM friend_requests
       WHERE (
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       )
       ORDER BY created_at DESC
       LIMIT 1`,
      [sender.id, receiver.id]
    );

    if (existing.rows.length > 0) {
      const current = existing.rows[0];
      if (current.status === 'pending') {
        return res.status(400).json({ error: "A friend request is already pending" });
      }
      if (current.status === 'accepted') {
        return res.status(400).json({ error: "You are already friends" });
      }

      const refreshed = await pool.query(
        `UPDATE friend_requests
         SET sender_id = $1,
             receiver_id = $2,
             status = 'pending',
             created_at = NOW()
         WHERE id = $3
         RETURNING *`,
        [sender.id, receiver.id, current.id]
      );
      return res.status(200).json(refreshed.rows[0]);
    }

    const result = await pool.query(
      `INSERT INTO friend_requests (sender_id, receiver_id, status)
       VALUES ($1, $2, 'pending')
       RETURNING *`,
      [sender.id, receiver.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Send Friend Request Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/friend-requests/:id/respond", async (req, res) => {
  const requestId = req.params.id;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const action = String(req.body.action || "").toLowerCase().trim();

  if (!['accepted', 'rejected'].includes(action)) {
    return res.status(400).json({ error: "Action must be accepted or rejected" });
  }

  try {
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "User not found" });
    }

    const requestResult = await pool.query(
      `SELECT *
       FROM friend_requests
       WHERE id = $1
       LIMIT 1`,
      [requestId]
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: "Friend request not found" });
    }

    const requestRow = requestResult.rows[0];
    if (requestRow.receiver_id !== actor.id) {
      return res.status(403).json({ error: "Only the receiver can respond to this request" });
    }

    const updated = await pool.query(
      `UPDATE friend_requests
       SET status = $2
       WHERE id = $1
       RETURNING *`,
      [requestId, action]
    );

    res.json(updated.rows[0]);
  } catch (e) {
    console.error("Respond Friend Request Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/contacts/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `WITH contacts AS (
         SELECT CASE
                  WHEN fr.sender_id = $1 THEN fr.receiver_id
                  ELSE fr.sender_id
                END AS contact_id
         FROM friend_requests fr
         WHERE fr.status = 'accepted'
           AND (fr.sender_id = $1 OR fr.receiver_id = $1)
       ),
       latest_message AS (
         SELECT DISTINCT ON (
           CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END
         )
           CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END AS contact_id,
           m.message,
           m.created_at,
           m.sender_id,
           m.is_read,
           m.read_at,
           m.delivered_at,
           m.message_type
         FROM messages m
         WHERE m.group_id IS NULL
           AND (m.sender_id = $1 OR m.receiver_id = $1)
         ORDER BY CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END, m.created_at DESC
       ),
       unread AS (
         SELECT m.sender_id AS contact_id, COUNT(*) AS unread_count
         FROM messages m
         WHERE m.group_id IS NULL
           AND m.receiver_id = $1
           AND COALESCE(m.is_read, false) = false
         GROUP BY m.sender_id
       )
       SELECT u.id,
              u.email,
              u.role,
              u.last_login,
              (u.last_login IS NOT NULL AND u.last_login >= NOW() - INTERVAL '5 minutes') AS is_online,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS display_name,
              COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url) AS profile_picture_url,
              COALESCE(unread.unread_count, 0) AS unread_count,
              latest_message.message AS last_message,
              latest_message.created_at AS last_message_at,
              latest_message.sender_id AS last_message_sender_id,
              latest_message.is_read AS last_message_is_read,
              latest_message.read_at AS last_message_read_at,
              latest_message.delivered_at AS last_message_delivered_at,
              latest_message.message_type AS last_message_type
       FROM contacts c
       JOIN users u ON u.id = c.contact_id
       LEFT JOIN students s ON s.user_id = u.id
       LEFT JOIN teachers t ON t.user_id = u.id
       LEFT JOIN parents p ON p.user_id = u.id
       LEFT JOIN admins a ON a.user_id = u.id
       LEFT JOIN latest_message ON latest_message.contact_id = u.id
       LEFT JOIN unread ON unread.contact_id = u.id
       ORDER BY COALESCE(latest_message.created_at, u.last_login, u.created_at) DESC`,
      [user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Contacts Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/thread/:email/:peerEmail", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const peerEmail = normalizeEmail(req.params.peerEmail);
  try {
    const user = await getUserByEmail(email);
    const peer = await getUserByEmail(peerEmail);
    if (!user || !peer) {
      return res.status(404).json({ error: "User was not found" });
    }

    const canChat = await ensureAcceptedFriendship(user.id, peer.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be friends before chatting" });
    }

    await pool.query(
      `UPDATE messages
       SET delivered_at = COALESCE(delivered_at, NOW())
       WHERE group_id IS NULL
         AND sender_id = $2
         AND receiver_id = $1`,
      [user.id, peer.id]
    );

    const result = await pool.query(
      `SELECT m.id,
              m.sender_id,
              m.receiver_id,
              sender_user.email AS sender_email,
              m.message,
              m.sender_role,
              m.created_at,
              m.is_read,
              m.delivered_at,
              m.read_at,
              m.message_type,
              m.media_url,
              m.thumbnail_url,
               m.duration_seconds,
               m.client_message_id
       FROM messages m
       JOIN users sender_user ON sender_user.id = m.sender_id
       WHERE m.group_id IS NULL
         AND (
           (m.sender_id = $1 AND m.receiver_id = $2)
           OR
           (m.sender_id = $2 AND m.receiver_id = $1)
         )
       ORDER BY m.created_at ASC`,
      [user.id, peer.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Thread Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/thread/send", async (req, res) => {
  const senderEmail = normalizeEmail(req.body.senderEmail);
  const receiverEmail = normalizeEmail(req.body.receiverEmail);
  const message = String(req.body.message || "");
  const messageType = String(req.body.messageType || "text").trim().toLowerCase();
  const mediaUrl = req.body.mediaUrl || null;
  const thumbnailUrl = req.body.thumbnailUrl || null;
  const durationSeconds = req.body.durationSeconds || null;
  const clientMessageId = req.body.clientMessageId || null;

  try {
    const sender = await getUserByEmail(senderEmail);
    const receiver = await getUserByEmail(receiverEmail);
    if (!sender || !receiver) {
      return res.status(404).json({ error: "Sender or receiver was not found" });
    }

    const canChat = await ensureAcceptedFriendship(sender.id, receiver.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be friends before chatting" });
    }

    if (!message.trim() && !mediaUrl) {
      return res.status(400).json({ error: "Message text or media is required" });
    }

    const result = await pool.query(
      `INSERT INTO messages (
         sender_id,
         receiver_id,
         message,
         is_read,
         sender_role,
         message_type,
         media_url,
         thumbnail_url,
         duration_seconds,
         client_message_id
       )
       VALUES ($1, $2, $3, false, $4, $5, $6, $7, $8, $9)
       RETURNING id, sender_id, receiver_id, message, sender_role, created_at, is_read,
                 delivered_at, read_at, message_type, media_url, thumbnail_url,
                 duration_seconds, client_message_id`,
      [
        sender.id,
        receiver.id,
        message.trim(),
        sender.role,
        messageType,
        mediaUrl,
        thumbnailUrl,
        durationSeconds,
        clientMessageId,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Send Chat Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/thread/read", async (req, res) => {
  const readerEmail = normalizeEmail(req.body.readerEmail);
  const peerEmail = normalizeEmail(req.body.peerEmail);
  try {
    const reader = await getUserByEmail(readerEmail);
    const peer = await getUserByEmail(peerEmail);
    if (!reader || !peer) {
      return res.status(404).json({ error: "Reader or peer was not found" });
    }

    const canChat = await ensureAcceptedFriendship(reader.id, peer.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be friends before chatting" });
    }

    await pool.query(
      `UPDATE messages
       SET delivered_at = COALESCE(delivered_at, NOW()),
           is_read = true,
           read_at = NOW()
       WHERE group_id IS NULL
         AND sender_id = $2
         AND receiver_id = $1`,
      [reader.id, peer.id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("Read Chat Thread Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/groups/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `SELECT g.id,
              g.name,
              g.avatar_url,
              g.created_at,
              COUNT(DISTINCT members.user_id) AS member_count,
              MAX(m.created_at) AS last_message_at
       FROM chat_groups g
       JOIN chat_group_members gm ON gm.group_id = g.id
       LEFT JOIN chat_group_members members ON members.group_id = g.id
       LEFT JOIN messages m ON m.group_id = g.id
       WHERE gm.user_id = $1
       GROUP BY g.id
       ORDER BY COALESCE(MAX(m.created_at), g.created_at) DESC`,
      [user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Groups Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/groups", async (req, res) => {
  const creatorEmail = normalizeEmail(req.body.creatorEmail);
  const name = String(req.body.name || "").trim();
  const avatarUrl = req.body.avatarUrl || null;
  const memberEmails = Array.isArray(req.body.memberEmails) ? req.body.memberEmails : [];

  if (!name) {
    return res.status(400).json({ error: "Group name is required" });
  }

  const client = await pool.connect();
  try {
    const creator = await getUserByEmail(creatorEmail);
    if (!creator) {
      return res.status(404).json({ error: "Creator not found" });
    }

    const normalizedEmails = [...new Set([creatorEmail, ...memberEmails.map(normalizeEmail)])];
    const memberResult = await client.query(
      `SELECT id, email
       FROM users
       WHERE email = ANY($1)`,
      [normalizedEmails]
    );

    await client.query("BEGIN");
    const groupResult = await client.query(
      `INSERT INTO chat_groups (name, created_by, avatar_url)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [name, creator.id, avatarUrl]
    );
    const group = groupResult.rows[0];

    for (const member of memberResult.rows) {
      await client.query(
        `INSERT INTO chat_group_members (group_id, user_id, is_admin)
         VALUES ($1, $2, $3)
         ON CONFLICT (group_id, user_id) DO NOTHING`,
        [group.id, member.id, member.id === creator.id]
      );
    }
    await client.query("COMMIT");

    res.status(201).json(group);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Create Chat Group Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/chat/groups/:groupId/add-members", async (req, res) => {
  const groupId = req.params.groupId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const memberEmails = Array.isArray(req.body.memberEmails) ? req.body.memberEmails : [];

  const client = await pool.connect();
  try {
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "Actor not found" });
    }

    const membership = await client.query(
      `SELECT id
       FROM chat_group_members
       WHERE group_id = $1
         AND user_id = $2
         AND is_admin = true
       LIMIT 1`,
      [groupId, actor.id]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: "Only a group admin can add members" });
    }

    const normalizedEmails = [...new Set(memberEmails.map(normalizeEmail))];
    const members = await client.query(
      `SELECT id
       FROM users
       WHERE email = ANY($1)`,
      [normalizedEmails]
    );

    for (const member of members.rows) {
      await client.query(
        `INSERT INTO chat_group_members (group_id, user_id, is_admin)
         VALUES ($1, $2, false)
         ON CONFLICT (group_id, user_id) DO NOTHING`,
        [groupId, member.id]
      );
    }

    res.json({ ok: true, added: members.rows.length });
  } catch (e) {
    console.error("Add Group Members Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/chat/groups/:groupId/messages/:email", async (req, res) => {
  const groupId = req.params.groupId;
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const membership = await pool.query(
      `SELECT id
       FROM chat_group_members
       WHERE group_id = $1 AND user_id = $2
       LIMIT 1`,
      [groupId, user.id]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: "You are not a member of this group" });
    }

    const result = await pool.query(
      `SELECT m.id,
              m.group_id,
              m.sender_id,
              u.email AS sender_email,
              m.message,
              m.sender_role,
              m.created_at,
              m.message_type,
              m.media_url,
              m.thumbnail_url,
              m.duration_seconds,
              m.client_message_id,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS sender_name
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       LEFT JOIN students s ON s.user_id = u.id
       LEFT JOIN teachers t ON t.user_id = u.id
       LEFT JOIN parents p ON p.user_id = u.id
       LEFT JOIN admins a ON a.user_id = u.id
       WHERE m.group_id = $1
       ORDER BY m.created_at ASC`,
      [groupId]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Get Group Messages Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/groups/:groupId/messages", async (req, res) => {
  const groupId = req.params.groupId;
  const senderEmail = normalizeEmail(req.body.senderEmail);
  const message = String(req.body.message || "");
  const messageType = String(req.body.messageType || "text").trim().toLowerCase();
  const mediaUrl = req.body.mediaUrl || null;
  const thumbnailUrl = req.body.thumbnailUrl || null;
  const durationSeconds = req.body.durationSeconds || null;
  const clientMessageId = req.body.clientMessageId || null;

  try {
    const sender = await getUserByEmail(senderEmail);
    if (!sender) {
      return res.status(404).json({ error: "Sender not found" });
    }

    const membership = await pool.query(
      `SELECT id
       FROM chat_group_members
       WHERE group_id = $1 AND user_id = $2
       LIMIT 1`,
      [groupId, sender.id]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: "You are not a member of this group" });
    }

    if (!message.trim() && !mediaUrl) {
      return res.status(400).json({ error: "Message text or media is required" });
    }

    const result = await pool.query(
      `INSERT INTO messages (
         sender_id,
         receiver_id,
         group_id,
         message,
         is_read,
         sender_role,
         message_type,
         media_url,
         thumbnail_url,
         duration_seconds,
         client_message_id
       )
       VALUES ($1, NULL, $2, $3, false, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        sender.id,
        groupId,
        message.trim(),
        sender.role,
        messageType,
        mediaUrl,
        thumbnailUrl,
        durationSeconds,
        clientMessageId,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Send Group Message Error:", e);
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




