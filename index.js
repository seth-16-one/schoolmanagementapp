// ---------------- IMPORTS ----------------
require('dotenv').config();
const express = require("express");
const path = require("path");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const speakeasy = require("speakeasy");
const { v4: uuidv4 } = require("uuid");
const { createRealtimeChatModule } = require("./realtime_chat_module");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use("/downloads", express.static(path.join(__dirname, "public")));

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
app.get("/version", (req, res) => {
  const configuredBaseUrl = String(
    process.env.PUBLIC_BASE_URL || process.env.APP_BASE_URL || ""
  ).trim().replace(/\/+$/, "");
  const inferredBaseUrl = `${req.protocol}://${req.get("host")}`;
  const baseUrl = configuredBaseUrl || inferredBaseUrl;

  res.status(200).json({
    app_name: "eSchool Student",
    version: "1.1.3",
    apk_url: `${baseUrl}/downloads/eschool_student.apk`,
    notes: "Bug fixes and improvements",
  });
});

app.post("/otp/request", requireOtpApiKey, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const requestIp = getRequestIp(req);
  const userAgent = String(req.headers["user-agent"] || "").trim() || null;

  try {
    const purpose = normalizeOtpPurpose(req.body.purpose);
    assertValidEmailOrThrow(email);
    await assertSecureOtpRequestAllowed({ email, purpose, requestIp });
    await ensureSecureOtpSchema();

    await pool.query(
      `UPDATE email_otp_challenges
       SET consumed_at = CURRENT_TIMESTAMP
       WHERE email = $1
         AND purpose = $2
         AND consumed_at IS NULL
         AND verified_at IS NULL`,
      [email, purpose]
    );

    const challengeId = uuidv4();
    const code = generateOtpCode();
    const otpHash = buildSecureOtpHash({
      challengeId,
      email,
      purpose,
      code,
    });
    const expiresAt = new Date(Date.now() + SECURE_OTP_EXPIRY_MS);

    await pool.query(
      `INSERT INTO email_otp_challenges (
         id,
         email,
         purpose,
         otp_hash,
         request_ip,
         user_agent,
         attempt_count,
         max_attempts,
         expires_at
       ) VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8)`,
      [
        challengeId,
        email,
        purpose,
        otpHash,
        requestIp,
        userAgent,
        SECURE_OTP_MAX_ATTEMPTS,
        expiresAt,
      ]
    );

    await sendSecureOtpEmail({ email, code, purpose });

    return res.status(200).json({
      success: true,
      challengeId,
      purpose,
      destinationMasked: maskValue(email, "email"),
      expiresAt: expiresAt.toISOString(),
      requestLimit: SECURE_OTP_REQUEST_LIMIT,
      requestWindowMinutes: Math.round(SECURE_OTP_REQUEST_WINDOW_MS / 60000),
    });
  } catch (e) {
    console.error("Secure OTP Request Error:", e);
    return res.status(e.statusCode || 500).json({
      error: e.message || "Failed to request OTP",
    });
  }
});

app.post("/otp/verify", requireOtpApiKey, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const challengeId = String(req.body.challengeId || "").trim();
  const code = String(req.body.code || "").trim();

  if (!challengeId || !code) {
    return res.status(400).json({ error: "challengeId and code are required" });
  }

  try {
    const purpose = normalizeOtpPurpose(req.body.purpose);
    assertValidEmailOrThrow(email);
    await ensureSecureOtpSchema();

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `SELECT *
         FROM email_otp_challenges
         WHERE id = $1
           AND email = $2
           AND purpose = $3
         LIMIT 1
         FOR UPDATE`,
        [challengeId, email, purpose]
      );

      if (!result.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "OTP challenge not found" });
      }

      const challenge = result.rows[0];
      const now = new Date();
      if (challenge.consumed_at || challenge.verified_at) {
        await client.query("ROLLBACK");
        return res.status(410).json({ error: "OTP has already been used or invalidated" });
      }

      if (new Date(challenge.expires_at).getTime() <= now.getTime()) {
        await client.query(
          `UPDATE email_otp_challenges
           SET consumed_at = CURRENT_TIMESTAMP
           WHERE id = $1`,
          [challengeId]
        );
        await client.query("COMMIT");
        return res.status(410).json({ error: "OTP has expired" });
      }

      const expectedHash = buildSecureOtpHash({
        challengeId,
        email,
        purpose,
        code,
      });
      const nextAttemptCount = Number(challenge.attempt_count || 0) + 1;

      if (expectedHash !== challenge.otp_hash) {
        const shouldLock = nextAttemptCount >= Number(challenge.max_attempts || SECURE_OTP_MAX_ATTEMPTS);
        await client.query(
          `UPDATE email_otp_challenges
           SET attempt_count = $2,
               last_attempt_at = CURRENT_TIMESTAMP,
               consumed_at = CASE WHEN $3 THEN CURRENT_TIMESTAMP ELSE consumed_at END
           WHERE id = $1`,
          [challengeId, nextAttemptCount, shouldLock]
        );
        await client.query("COMMIT");
        return res.status(shouldLock ? 429 : 401).json({
          error: shouldLock
            ? "Too many incorrect verification attempts"
            : "Invalid verification code",
          remainingAttempts: shouldLock
            ? 0
            : Math.max(0, Number(challenge.max_attempts || SECURE_OTP_MAX_ATTEMPTS) - nextAttemptCount),
        });
      }

      await client.query(
        `UPDATE email_otp_challenges
         SET attempt_count = $2,
             last_attempt_at = CURRENT_TIMESTAMP,
             verified_at = CURRENT_TIMESTAMP,
             consumed_at = CURRENT_TIMESTAMP
         WHERE id = $1`,
        [challengeId, nextAttemptCount]
      );
      await client.query("COMMIT");

      return res.status(200).json({
        success: true,
        email,
        purpose,
        verifiedAt: new Date().toISOString(),
      });
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error("Secure OTP Verify Error:", e);
    return res.status(e.statusCode || 500).json({
      error: e.message || "Failed to verify OTP",
    });
  }
});

// ===================== AUTH =====================

const otpChallenges = new Map();
const passwordResetChallenges = new Map();
const appLockResetChallenges = new Map();
const pendingAuthenticatorSetups = new Map();
const otpRequestWindows = new Map();
const passwordResetRequestWindows = new Map();
const OTP_EXPIRY_MS = Number(process.env.OTP_EXPIRY_MS || 5 * 60 * 1000);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_REQUEST_LIMIT = Number(process.env.OTP_REQUEST_LIMIT || 5);
const OTP_REQUEST_WINDOW_MS = Number(process.env.OTP_REQUEST_WINDOW_MS || 60 * 60 * 1000);
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
let otpMailer = null;

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
    `SELECT id, username, email, role, last_login, is_active,
            COALESCE(authenticator_enabled, false) AS authenticator_enabled,
            authenticator_secret
     FROM users
     WHERE email = $1
     LIMIT 1`,
    [normalizedEmail]
  );
  return result.rows[0] || null;
}

function getRequestIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return (
    req.headers["x-real-ip"] ||
    req.ip ||
    req.socket?.remoteAddress ||
    null
  );
}

app.use(
  "/api/realtime-chat",
  createRealtimeChatModule({
    pool,
    getRequestIp,
  })
);

let pushDeviceSchemaEnsured = false;
let authenticatorSchemaEnsured = false;
let secureOtpSchemaEnsured = false;
let firebaseAccessTokenCache = {
  token: null,
  expiresAt: 0,
};
const SECURE_OTP_EXPIRY_MS = Number(process.env.SECURE_OTP_EXPIRY_MS || 5 * 60 * 1000);
const SECURE_OTP_MAX_ATTEMPTS = Number(process.env.SECURE_OTP_MAX_ATTEMPTS || OTP_MAX_ATTEMPTS || 5);
const SECURE_OTP_REQUEST_LIMIT = Number(process.env.SECURE_OTP_REQUEST_LIMIT || 5);
const SECURE_OTP_REQUEST_WINDOW_MS = Number(process.env.SECURE_OTP_REQUEST_WINDOW_MS || 15 * 60 * 1000);

async function ensurePushDeviceSchema() {
  if (pushDeviceSchemaEnsured) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_devices (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_token text NOT NULL UNIQUE,
      platform text,
      app_role text,
      device_name text,
      app_version text,
      is_active boolean NOT NULL DEFAULT true,
      last_seen_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_push_devices_user_active
    ON push_devices(user_id, is_active, last_seen_at DESC)
  `);
  pushDeviceSchemaEnsured = true;
}

async function ensureAuthenticatorSchema() {
  if (authenticatorSchemaEnsured) return;
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS authenticator_secret text,
    ADD COLUMN IF NOT EXISTS authenticator_enabled boolean NOT NULL DEFAULT false
  `);
  authenticatorSchemaEnsured = true;
}

async function ensureSecureOtpSchema() {
  if (secureOtpSchemaEnsured) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_otp_challenges (
      id uuid PRIMARY KEY,
      email text NOT NULL,
      purpose text NOT NULL DEFAULT 'general',
      otp_hash text NOT NULL,
      request_ip text,
      user_agent text,
      attempt_count integer NOT NULL DEFAULT 0,
      max_attempts integer NOT NULL DEFAULT 5,
      expires_at timestamp without time zone NOT NULL,
      verified_at timestamp without time zone,
      consumed_at timestamp without time zone,
      last_attempt_at timestamp without time zone,
      created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_email_purpose_created
    ON email_otp_challenges(email, purpose, created_at DESC)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_expires
    ON email_otp_challenges(expires_at)
  `);
  secureOtpSchemaEnsured = true;
}

function getSecureOtpApiKey() {
  return String(process.env.OTP_API_KEY || process.env.INTERNAL_API_KEY || "").trim();
}

function requireOtpApiKey(req, res, next) {
  const configuredApiKey = getSecureOtpApiKey();
  if (!configuredApiKey) {
    return res.status(500).json({
      error: "OTP API key is not configured on the server",
    });
  }

  const headerApiKey = String(req.headers["x-api-key"] || "").trim();
  const bearerToken = String(req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "")
    .trim();
  const providedApiKey = headerApiKey || bearerToken;

  if (!providedApiKey || providedApiKey !== configuredApiKey) {
    return res.status(401).json({ error: "Invalid API key" });
  }

  next();
}

function assertValidEmailOrThrow(email) {
  if (!isValidEmail(email)) {
    const error = new Error("A valid email address is required");
    error.statusCode = 400;
    throw error;
  }
}

function normalizeOtpPurpose(purpose) {
  const normalized = String(purpose || "general").trim().toLowerCase();
  if (!/^[a-z0-9:_-]{1,50}$/.test(normalized)) {
    const error = new Error("Purpose must contain only letters, numbers, colon, underscore, or hyphen");
    error.statusCode = 400;
    throw error;
  }
  return normalized;
}

function buildSecureOtpHash({ challengeId, email, purpose, code }) {
  const secret = String(process.env.OTP_HASH_SECRET || "").trim();
  if (!secret) {
    const error = new Error("OTP_HASH_SECRET is not configured on the server");
    error.statusCode = 500;
    throw error;
  }
  return crypto
    .createHmac("sha256", secret)
    .update([challengeId, normalizeEmail(email), normalizeOtpPurpose(purpose), String(code || "").trim()].join(":"))
    .digest("hex");
}

async function assertSecureOtpRequestAllowed({ email, purpose, requestIp }) {
  await ensureSecureOtpSchema();
  const windowStart = new Date(Date.now() - SECURE_OTP_REQUEST_WINDOW_MS);
  const normalizedEmail = normalizeEmail(email);
  const normalizedPurpose = normalizeOtpPurpose(purpose);

  const emailCountResult = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM email_otp_challenges
     WHERE email = $1
       AND purpose = $2
       AND created_at >= $3`,
    [normalizedEmail, normalizedPurpose, windowStart]
  );
  const emailCount = Number(emailCountResult.rows[0]?.count || 0);
  if (emailCount >= SECURE_OTP_REQUEST_LIMIT) {
    const error = new Error("Too many OTP requests for this email. Try again later.");
    error.statusCode = 429;
    throw error;
  }

  if (requestIp) {
    const ipCountResult = await pool.query(
      `SELECT COUNT(*)::int AS count
       FROM email_otp_challenges
       WHERE request_ip = $1
         AND created_at >= $2`,
      [requestIp, windowStart]
    );
    const ipCount = Number(ipCountResult.rows[0]?.count || 0);
    if (ipCount >= SECURE_OTP_REQUEST_LIMIT) {
      const error = new Error("Too many OTP requests from this network. Try again later.");
      error.statusCode = 429;
      throw error;
    }
  }
}

async function sendSecureOtpEmail({ email, code, purpose }) {
  const transporter = getOtpMailer();
  const from = String(process.env.OTP_FROM_EMAIL || process.env.EMAIL_USER || "").trim();
  const subject = `Your eSchool ${purpose} verification code`;
  const expiryMinutes = Math.max(1, Math.round(SECURE_OTP_EXPIRY_MS / 60000));
  await transporter.sendMail({
    from,
    to: email,
    subject,
    text: `Your eSchool verification code is ${code}. It expires in ${expiryMinutes} minutes. If you did not request this code, please ignore this email.`,
    html: `
      <div style="font-family:Arial,sans-serif;color:#0f172a;">
        <h2 style="margin-bottom:8px;">eSchool Verification</h2>
        <p>Your one-time verification code for <strong>${purpose}</strong> is:</p>
        <div style="font-size:30px;font-weight:800;letter-spacing:6px;margin:16px 0;color:#1d4ed8;">
          ${code}
        </div>
        <p>This code expires in <strong>${expiryMinutes} minutes</strong>.</p>
        <p>If you did not request this code, you can ignore this email.</p>
      </div>
    `,
  });
}

function buildAuthenticatorLabel(user) {
  const identity = user.email || user.username || "user";
  return `eSchool (${identity})`;
}

function generateAuthenticatorSecret(user) {
  return speakeasy.generateSecret({
    name: buildAuthenticatorLabel(user),
    issuer: "eSchool",
    length: 20,
  });
}

function verifyAuthenticatorToken(secret, token) {
  const normalizedToken = String(token || "").replace(/\s+/g, "").trim();
  if (!secret || normalizedToken.length !== 6) return false;
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: normalizedToken,
    window: 1,
  });
}

async function getActivePushTokensForUserIds(userIds = []) {
  await ensurePushDeviceSchema();
  const normalizedIds = userIds.filter(Boolean);
  if (!normalizedIds.length) return [];
  const result = await pool.query(
    `SELECT user_id, device_token
     FROM push_devices
     WHERE user_id = ANY($1::uuid[])
       AND is_active = true`,
    [normalizedIds]
  );
  return result.rows;
}

function getFirebaseServiceAccount() {
  const projectId = String(process.env.FIREBASE_PROJECT_ID || "").trim();
  const clientEmail = String(process.env.FIREBASE_CLIENT_EMAIL || "").trim();
  const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n").trim();
  if (!projectId || !clientEmail || !privateKey) {
    return null;
  }
  return {
    projectId,
    clientEmail,
    privateKey,
  };
}

function toBase64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function getFirebaseAccessToken() {
  const serviceAccount = getFirebaseServiceAccount();
  if (!serviceAccount) return null;

  const now = Math.floor(Date.now() / 1000);
  if (
    firebaseAccessTokenCache.token &&
    firebaseAccessTokenCache.expiresAt - 60 > now
  ) {
    return firebaseAccessTokenCache.token;
  }

  const header = {
    alg: "RS256",
    typ: "JWT",
  };
  const payload = {
    iss: serviceAccount.clientEmail,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);
  signer.end();
  const signature = signer
    .sign(serviceAccount.privateKey, "base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${unsignedToken}.${signature}`,
    }),
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`Failed to get Firebase access token: ${response.status} ${raw}`);
  }

  const data = await response.json();
  firebaseAccessTokenCache = {
    token: data.access_token,
    expiresAt: now + Number(data.expires_in || 3600),
  };
  return firebaseAccessTokenCache.token;
}

async function sendPushToUserIds(userIds = [], { title, body, data = {} }) {
  const serviceAccount = getFirebaseServiceAccount();
  if (!serviceAccount || typeof fetch !== "function") return;
  const devices = await getActivePushTokensForUserIds(userIds);
  if (!devices.length) return;
  const accessToken = await getFirebaseAccessToken();
  if (!accessToken) return;

  const normalizedData = Object.entries(data || {}).reduce((acc, [key, value]) => {
    acc[key] = value == null ? "" : String(value);
    return acc;
  }, {});

  await Promise.allSettled(
    devices.map(async ({ device_token }) => {
      try {
        const response = await fetch(
          `https://fcm.googleapis.com/v1/projects/${serviceAccount.projectId}/messages:send`,
          {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            message: {
              token: device_token,
              notification: {
                title: String(title || "eSchool"),
                body: String(body || ""),
              },
              android: {
                priority: "high",
                notification: {
                  channel_id: "chat_alerts_channel",
                },
              },
              data: normalizedData,
            },
          }),
        });

        if (!response.ok) {
          const raw = await response.text();
          console.error("FCM Push Error:", response.status, raw);
          if (
            raw.includes("UNREGISTERED") ||
            raw.includes("registration-token-not-registered") ||
            response.status === 404 ||
            response.status === 410
          ) {
            await pool.query(
              `UPDATE push_devices
               SET is_active = false,
                   last_seen_at = NOW()
               WHERE device_token = $1`,
              [device_token]
            );
          }
          return;
        }
      } catch (error) {
        console.error("FCM Push Dispatch Error:", error);
      }
    })
  );
}

async function recordLoginSession(req, user) {
  try {
    if (!user?.id) return null;
    const ipAddress = getRequestIp(req);
    const deviceInfo = String(req.headers["user-agent"] || "").trim() || null;
    await pool.query(
      `UPDATE login_sessions
       SET is_current = false
       WHERE user_id = $1
         AND logged_out_at IS NULL`,
      [user.id]
    );
    const existing = await pool.query(
      `SELECT id, ip_address, device_info
       FROM login_sessions
       WHERE user_id = $1
       ORDER BY logged_in_at DESC
       LIMIT 1`,
      [user.id]
    );
    const previous = existing.rows[0];
    const suspicious =
      !!previous &&
      ((previous.ip_address || "") !== (ipAddress || "") ||
        (previous.device_info || "") !== (deviceInfo || ""));

    const result = await pool.query(
      `INSERT INTO login_sessions (user_id, role, ip_address, device_info, suspicious, is_current)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, logged_in_at, ip_address, device_info, suspicious, is_current`,
      [user.id, user.role, ipAddress, deviceInfo, suspicious]
    );

    if (suspicious) {
      const title = "New login from another device";
      const message = `A new ${user.role || "account"} login was detected from ${ipAddress || "an unknown IP"}. If this was not you, review your active devices now.`;
      try {
        await pool.query(
          `INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
           VALUES ($1, $2, $3, 'security_alert', false, NOW())`,
          [user.id, title, message]
        );
      } catch (_) {}
      await sendPushToUserIds([user.id], {
        title,
        body: message,
        data: {
          type: "security_alert",
          email: user.email,
        },
      });
    }

    return result.rows[0] || null;
  } catch (e) {
    console.error("Record Login Session Error:", e);
    return null;
  }
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

const CHAT_APPEAL_WINDOW_HOURS = Number(process.env.CHAT_APPEAL_WINDOW_HOURS || 48);
const CHAT_TYPING_TTL_MS = Number(process.env.CHAT_TYPING_TTL_MS || 8000);
const chatTypingState = new Map();

function buildTypingKey(senderId, receiverId) {
  return `${senderId}:${receiverId}`;
}

function setTypingState(senderId, receiverId, isTyping) {
  const key = buildTypingKey(senderId, receiverId);
  if (!isTyping) {
    chatTypingState.delete(key);
    return;
  }

  chatTypingState.set(key, {
    updatedAt: Date.now(),
  });
}

function readTypingState(senderId, receiverId) {
  const key = buildTypingKey(senderId, receiverId);
  const entry = chatTypingState.get(key);
  if (!entry) {
    return null;
  }

  if (Date.now() - entry.updatedAt > CHAT_TYPING_TTL_MS) {
    chatTypingState.delete(key);
    return null;
  }

  return entry;
}

async function insertGroupSystemMessage({
  client = pool,
  groupId,
  actorId,
  actorRole = "system",
  message,
}) {
  if (!groupId || !actorId || !String(message || "").trim()) {
    return;
  }

  await client.query(
    `INSERT INTO messages (
       sender_id,
       receiver_id,
       group_id,
       message,
       is_read,
       sender_role,
       message_type
     )
     VALUES ($1, NULL, $2, $3, true, $4, 'system')`,
    [actorId, groupId, String(message).trim(), actorRole]
  );
}

function buildChatFreezeMessage(reason) {
  return reason || "Chat access has been frozen. Please contact the school admin.";
}

async function syncChatFreezeForUser(userId) {
  if (!userId) {
    return {
      isFrozen: false,
      reason: null,
      appealDeadlineAt: null,
    };
  }

  const activeWarningResult = await pool.query(
    `SELECT aw.id,
            aw.reason,
            aw.status,
            aw.appeal_status,
            aw.appeal_message,
            aw.appeal_deadline_at,
            aw.freeze_until,
            aw.resolution_note,
            aw.created_at
     FROM admin_warnings aw
     WHERE aw.target_user_id = $1
       AND aw.status = 'active'
     ORDER BY aw.created_at DESC
     LIMIT 1`,
    [userId]
  );

  const warning = activeWarningResult.rows[0];
  const now = new Date();
  const deadline = warning?.appeal_deadline_at ? new Date(warning.appeal_deadline_at) : null;
  const freezeUntil = warning?.freeze_until ? new Date(warning.freeze_until) : null;
  const missedAppealWindow =
    warning &&
    warning.appeal_status !== 'submitted' &&
    warning.appeal_status !== 'accepted' &&
    warning.appeal_status !== 'rejected' &&
    deadline &&
    deadline.getTime() <= now.getTime();

  if (missedAppealWindow) {
    await pool.query(
      `UPDATE users
       SET is_chat_frozen = true,
           chat_frozen_at = COALESCE(chat_frozen_at, NOW()),
           chat_freeze_reason = $2
       WHERE id = $1`,
      [userId, `Chat frozen after missed appeal deadline: ${warning.reason}`]
    );
    return {
      isFrozen: true,
      reason: `Chat frozen after missed appeal deadline: ${warning.reason}`,
      warning,
      appealDeadlineAt: warning.appeal_deadline_at,
    };
  }

  const userResult = await pool.query(
    `SELECT is_chat_frozen, chat_frozen_at, chat_freeze_reason, chat_freeze_expires_at
     FROM users
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );
  const user = userResult.rows[0] || {};

  if (freezeUntil && freezeUntil.getTime() <= now.getTime()) {
    await pool.query(
      `UPDATE users
       SET is_chat_frozen = false,
           chat_frozen_at = NULL,
           chat_freeze_reason = NULL,
           chat_freeze_expires_at = NULL
       WHERE id = $1`,
      [userId]
    );
    return {
      isFrozen: false,
      reason: null,
      warning,
      appealDeadlineAt: warning?.appeal_deadline_at || null,
    };
  }

  if (warning && warning.appeal_status === 'submitted') {
    return {
      isFrozen: false,
      reason: null,
      warning,
      appealDeadlineAt: warning.appeal_deadline_at,
    };
  }

  if (warning && warning.appeal_status === 'rejected' && freezeUntil && freezeUntil.getTime() > now.getTime()) {
    return {
      isFrozen: true,
      reason: `Chat access is frozen until ${warning.freeze_until}.`,
      warning,
      appealDeadlineAt: warning.appeal_deadline_at,
    };
  }

  return {
    isFrozen: user.is_chat_frozen === true,
    reason: user.chat_freeze_reason || null,
    warning,
    appealDeadlineAt: warning?.appeal_deadline_at || null,
  };
}

async function ensureChatAccessAllowed(user) {
  if (!user) {
    return { ok: false, status: 404, error: "User not found" };
  }

  const chatState = await syncChatFreezeForUser(user.id);
  if (chatState.isFrozen) {
    return {
      ok: false,
      status: 423,
      error: buildChatFreezeMessage(chatState.reason),
      chatState,
    };
  }

  return {
    ok: true,
    status: 200,
    chatState,
  };
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

async function ensureAcceptedFriendshipOrFamily(userId, otherUserId) {
  const acceptedFriendship = await ensureAcceptedFriendship(userId, otherUserId);
  if (acceptedFriendship) return true;

  const familyLink = await pool.query(
    `SELECT 1
     FROM parent_child pc
     JOIN parents p ON p.id = pc.parent_id
     JOIN students s ON s.id = pc.student_id
     WHERE (p.user_id = $1 AND s.user_id = $2)
        OR (p.user_id = $2 AND s.user_id = $1)
     LIMIT 1`,
    [userId, otherUserId]
  );

  return familyLink.rows.length > 0;
}

async function getGroupMembership(groupId, userId, client = pool) {
  const result = await client.query(
    `SELECT id, group_id, user_id, is_admin, COALESCE(role, CASE WHEN is_admin THEN 'admin' ELSE 'member' END) AS role
     FROM chat_group_members
     WHERE group_id = $1 AND user_id = $2
     LIMIT 1`,
    [groupId, userId]
  );
  return result.rows[0] || null;
}

function slugMeetingPart(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24) || "room";
}

function buildJitsiRoomName(prefix, parts = []) {
  const stamp = Date.now().toString(36);
  return ["eschool", prefix, ...parts.map(slugMeetingPart).filter(Boolean), stamp]
    .join("-")
    .slice(0, 120);
}

function buildJitsiRoomUrl(roomName, callType = "video") {
  const hash =
    callType === "voice"
      ? "#config.startWithVideoMuted=true&config.prejoinConfig.enabled=true"
      : "#config.prejoinConfig.enabled=true";
  return `https://meet.jit.si/${roomName}${hash}`;
}

function canManageGroupMembers(membership) {
  if (!membership) return false;
  return membership.is_admin === true || membership.role === 'admin' || membership.role === 'moderator';
}

async function ensureChatGroupRoleSchema(client = pool) {
  await client.query(
    `ALTER TABLE public.chat_group_members
     ADD COLUMN IF NOT EXISTS role text DEFAULT 'member'`
  );
  await client.query(
    `UPDATE public.chat_group_members
     SET role = CASE WHEN is_admin = true THEN 'admin' ELSE 'member' END
     WHERE role IS NULL OR role = ''`
  );
}

async function ensureChatMessageFeatureSchema(client = pool) {
  await client.query(
    `ALTER TABLE public.messages
     ADD COLUMN IF NOT EXISTS reply_to_message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
     ADD COLUMN IF NOT EXISTS forwarded_from_message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
     ADD COLUMN IF NOT EXISTS is_pinned boolean DEFAULT false,
     ADD COLUMN IF NOT EXISTS pinned_at timestamp without time zone,
     ADD COLUMN IF NOT EXISTS reactions jsonb DEFAULT '{}'::jsonb`
  );
}

function parseMessageReactions(rawValue) {
  if (!rawValue) return {};
  if (typeof rawValue === "object") {
    return rawValue;
  }

  try {
    return JSON.parse(String(rawValue));
  } catch (_) {
    return {};
  }
}

function normalizeReactionState(rawValue) {
  const parsed = parseMessageReactions(rawValue);
  const normalized = {};
  for (const [emoji, users] of Object.entries(parsed)) {
    if (!emoji) continue;
    const list = Array.isArray(users)
      ? [...new Set(users.map((value) => normalizeEmail(value)).filter(Boolean))]
      : [];
    normalized[emoji] = list;
  }
  return normalized;
}

async function getChatContactProfile(email) {
  const normalizedEmail = normalizeEmail(email);
  const result = await pool.query(
    `SELECT u.id,
            u.email,
            u.role,
            u.username,
            u.last_login,
            COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS full_name,
            COALESCE(s.phone, t.phone, p.phone, a.phone) AS phone,
            COALESCE(s.address, p.address) AS address,
            s.gender,
            s.date_of_birth,
            s.class_name AS student_class_name,
            s.admission_number,
            t.class_name AS teacher_class_name,
            t.teacher_number,
            t.subject,
            COALESCE(s.bio, t.bio, p.bio, a.bio) AS bio,
            COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url) AS profile_picture_url
     FROM users u
     LEFT JOIN students s ON s.user_id = u.id
     LEFT JOIN teachers t ON t.user_id = u.id
     LEFT JOIN parents p ON p.user_id = u.id
     LEFT JOIN admins a ON a.user_id = u.id
     WHERE u.email = $1
     LIMIT 1`,
    [normalizedEmail]
  );
  return result.rows[0] || null;
}

async function areUsersBlocked(actorId, peerId) {
  if (!actorId || !peerId) return false;
  const result = await pool.query(
    `SELECT 1
     FROM blocked_users
     WHERE blocker_user_id = $1
       AND blocked_user_id = $2
     LIMIT 1`,
    [actorId, peerId]
  );
  return result.rows.length > 0;
}

async function getNextStudentAdmissionNumber(client = pool) {
  await client.query(`SELECT pg_advisory_xact_lock(11000)`);
  await client.query(
    `CREATE SEQUENCE IF NOT EXISTS public.student_admission_number_seq
     START WITH 11000
     INCREMENT BY 1
     MINVALUE 11000`
  );
  await client.query(
    `SELECT setval(
       'public.student_admission_number_seq',
       GREATEST(
         COALESCE(
           (SELECT MAX(admission_number::bigint)
            FROM students
            WHERE admission_number ~ '^[0-9]+$'),
           10999
         ),
         10999
       ),
       true
     )`
  );

  const nextResult = await client.query(
    `SELECT nextval('public.student_admission_number_seq') AS next_value`
  );
  return String(nextResult.rows[0].next_value);
}

function normalizeOtpChannel(channel) {
  const normalized = String(channel || "email").toLowerCase().trim();
  if (normalized === "authenticator") return "authenticator";
  return "email";
}

function cleanupExpiredOtpChallenges() {
  const now = Date.now();
  for (const [challengeId, challenge] of otpChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      otpChallenges.delete(challengeId);
    }
  }
}

function cleanupExpiredPasswordResetChallenges() {
  const now = Date.now();
  for (const [challengeId, challenge] of passwordResetChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      passwordResetChallenges.delete(challengeId);
    }
  }
}

function cleanupExpiredAppLockResetChallenges() {
  const now = Date.now();
  for (const [challengeId, challenge] of appLockResetChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      appLockResetChallenges.delete(challengeId);
    }
  }
}

function cleanupRequestWindow(store) {
  const now = Date.now();
  for (const [key, entry] of store.entries()) {
    const timestamps = (entry?.timestamps || []).filter(
      (timestamp) => now - timestamp < OTP_REQUEST_WINDOW_MS
    );
    if (!timestamps.length) {
      store.delete(key);
      continue;
    }
    entry.timestamps = timestamps;
  }
}

function assertOtpRequestAllowed(store, key) {
  cleanupRequestWindow(store);
  const now = Date.now();
  const current = store.get(key) || { timestamps: [] };
  current.timestamps = current.timestamps.filter(
    (timestamp) => now - timestamp < OTP_REQUEST_WINDOW_MS
  );
  if (current.timestamps.length >= OTP_REQUEST_LIMIT) {
    const retryAt = current.timestamps[0] + OTP_REQUEST_WINDOW_MS;
    const waitMinutes = Math.max(1, Math.ceil((retryAt - now) / 60000));
    const error = new Error(
      `Too many OTP requests. Try again in about ${waitMinutes} minute(s).`
    );
    error.statusCode = 429;
    error.retryAt = retryAt;
    throw error;
  }
  current.timestamps.push(now);
  store.set(key, current);
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
  await ensureAuthenticatorSchema();
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.password_hash, u.role,
            COALESCE(u.authenticator_enabled, false) AS authenticator_enabled,
            u.authenticator_secret
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
    if (user.authenticator_enabled) {
      destinations.authenticator = user.email;
    }
  }

  return destinations;
}

function getOtpMailer() {
  if (otpMailer) return otpMailer;
  const user = String(process.env.EMAIL_USER || "").trim();
  const pass = String(
    process.env.EMAIL_PASSWORD ||
    process.env.EMAIL_APP_PASSWORD ||
    process.env.GMAIL_APP_PASSWORD ||
    ""
  ).trim();
  if (!user || !pass) {
    throw new Error("EMAIL_USER and EMAIL_PASSWORD must be configured for OTP delivery");
  }
  otpMailer = nodemailer.createTransport({
    service: "gmail",
    auth: { user, pass },
  });
  return otpMailer;
}

function buildClientSafeAuthError(defaultMessage, error, extras = {}) {
  const statusCode = Number(error?.statusCode) || 500;
  const safeMessage =
    statusCode >= 500
      ? defaultMessage
      : String(error?.message || defaultMessage).trim() || defaultMessage;
  return {
    statusCode,
    body: {
      error: safeMessage,
      ...extras,
    },
  };
}

async function deliverOtp({ user, channel, destination, code }) {
  const normalizedChannel = channel === "authenticator" ? "email" : "email";
  const expiresMinutes = Math.round(OTP_EXPIRY_MS / 60000);
  const transporter = getOtpMailer();
  const subject =
    normalizedChannel === "email"
      ? "Your eSchool verification code"
      : "Your eSchool authenticator verification code";
  const message = `Your eSchool verification code is ${code}. It expires in ${expiresMinutes} minutes.`;

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: destination,
    subject,
    text: `${message}\n\nIf you did not request this code, you can ignore this email.`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #0f172a;">
        <h2 style="margin-bottom: 8px;">eSchool Verification</h2>
        <p>Hello ${user.username || user.email},</p>
        <p>Your verification code is:</p>
        <div style="font-size: 28px; font-weight: 800; letter-spacing: 6px; margin: 16px 0; color: #1d4ed8;">
          ${code}
        </div>
        <p>This code expires in <strong>${expiresMinutes} minutes</strong>.</p>
        <p>If you did not request this code, you can ignore this email.</p>
      </div>
    `,
  });

  return {
    deliveryMode: "email",
    previewCode: null
  };
}

async function loginUserFromUsersTable(usernameOrEmail, password, enforcedRole = null) {
  await ensureAuthenticatorSchema();
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
    if (result.status === 200 && result.body?.user) {
      result.body.session = await recordLoginSession(req, result.body.user);
    }
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
    if (result.status === 200 && result.body?.user) {
      result.body.session = await recordLoginSession(req, result.body.user);
    }
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
    if (result.status === 200 && result.body?.user) {
      result.body.session = await recordLoginSession(req, result.body.user);
    }
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
    if (result.status === 200 && result.body?.user) {
      result.body.session = await recordLoginSession(req, result.body.user);
    }
    return res.status(result.status).json(result.body);
  } catch (e) {
    console.error("Finance Login Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/login-otp/request", (req, res) => {
  return res.status(405).json({
    error: "Use POST for /login-otp/request",
    requiredBody: ["username", "password"],
    acceptedAliases: ["usernameOrEmail", "password", "expectedRole", "channel"],
  });
});

app.post("/login-otp/request", async (req, res) => {
  const usernameOrEmail = String(
    req.body.usernameOrEmail ?? req.body.username ?? req.body.email ?? ""
  ).trim();
  const password = String(req.body.password ?? "").trim();
  const expectedRole = req.body.expectedRole;
  const channel = req.body.channel;

  if (!usernameOrEmail || !password) {
    return res.status(400).json({
      error: "Username/email and password required",
      expectedMethod: "POST",
      expectedContentType: "application/json",
      requiredBody: ["username", "password"],
    });
  }

  cleanupExpiredOtpChallenges();

  try {
    await ensureAuthenticatorSchema();
    const authResult = await authenticateLoginAttempt(usernameOrEmail, password, expectedRole);
    if (authResult.status !== 200) {
      return res.status(authResult.status).json(authResult.body);
    }

    const user = authResult.body.user;
    assertOtpRequestAllowed(
      otpRequestWindows,
      `login:${normalizeEmail(user.email || usernameOrEmail)}`
    );
    const requestedChannel = normalizeOtpChannel(channel);
    const destinations = await resolveOtpDestinations(user);
    const availableChannels = destinations.authenticator
      ? ["email", "authenticator"]
      : ["email"];

    if (!availableChannels.length) {
      return res.status(400).json({
        error: "No OTP delivery destination is configured for this account",
      });
    }

    if (requestedChannel === "authenticator" && !destinations.authenticator) {
      return res.status(400).json({
        error: "Authenticator is not enabled for this account yet",
        availableChannels,
        maskedDestinations: {
          email: maskValue(destinations.email, "email"),
        }
      });
    }

    if (!destinations.email && requestedChannel !== "authenticator") {
      return res.status(400).json({
        error: `Email OTP is not available for this account`,
        availableChannels,
        maskedDestinations: {
          email: maskValue(destinations.email, "email"),
        }
      });
    }

    const challengeId = uuidv4();
    const expiresAt = Date.now() + OTP_EXPIRY_MS;
    let delivery;
    let code = null;
    let destination = null;

    if (requestedChannel === "authenticator") {
      delivery = {
        deliveryMode: "authenticator",
        previewCode: null,
      };
    } else {
      code = generateOtpCode();
      destination = destinations.email;
      delivery = await deliverOtp({
        user,
        channel: "email",
        destination,
        code,
      });
    }

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
      destinationMasked:
        requestedChannel === "authenticator"
          ? "your authenticator app"
          : maskValue(destination, "email"),
      availableChannels,
      maskedDestinations: {
        email: maskValue(destinations.email, "email"),
        authenticator: destinations.authenticator ? "your authenticator app" : null,
      },
      expiresAt: new Date(expiresAt).toISOString(),
      deliveryMode: delivery.deliveryMode,
      previewCode: delivery.previewCode,
    });
  } catch (e) {
    console.error("Login OTP Request Error:", e);
    const safeError = buildClientSafeAuthError(
      "Failed to fetch verification code. Please try again.",
      e,
      {
        retryAt: e.retryAt ? new Date(e.retryAt).toISOString() : undefined,
      }
    );
    return res.status(safeError.statusCode).json(safeError.body);
  }
});

app.post("/login-otp/verify", async (req, res) => {
  try {
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
    const isAuthenticatorFlow = challenge.channel === "authenticator";
    const isValidCode = isAuthenticatorFlow
      ? verifyAuthenticatorToken(challenge.user?.authenticator_secret, code)
      : String(code).trim() === challenge.code;

    if (!isValidCode) {
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
    const session = await recordLoginSession(req, challenge.user);
    return res.status(200).json({ user: challenge.user, session });
  } catch (e) {
    console.error("Login OTP Verify Error:", e);
    const safeError = buildClientSafeAuthError(
      "Failed to verify the login code. Please try again.",
      e
    );
    return res.status(safeError.statusCode).json(safeError.body);
  }
});

app.post("/password-reset/request", async (req, res) => {
  const {
    usernameOrEmail,
    expectedRole,
    channel,
  } = req.body;

  if (!usernameOrEmail) {
    return res.status(400).json({ error: "Username or email is required" });
  }

  cleanupExpiredPasswordResetChallenges();

  try {
    const lookup = String(usernameOrEmail).trim();
    const result = await pool.query(
      `SELECT id, username, email, role
       FROM users
       WHERE username = $1 OR email = $1
       LIMIT 1`,
      [lookup]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Account not found" });
    }

    const user = result.rows[0];
    assertOtpRequestAllowed(
      passwordResetRequestWindows,
      `password:${normalizeEmail(user.email || usernameOrEmail)}`
    );
    const normalizedExpectedRole = expectedRole
      ? String(expectedRole).toLowerCase().trim()
      : null;
    if (normalizedExpectedRole && user.role !== normalizedExpectedRole) {
      return res.status(403).json({
        error: `This app accepts ${normalizedExpectedRole} accounts only`,
      });
    }

    const requestedChannel = normalizeOtpChannel(channel);
    const destinations = await resolveOtpDestinations(user);
    const availableChannels = ["email"];

    if (!availableChannels.length) {
      return res.status(400).json({
        error: "No password reset delivery destination is configured for this account",
      });
    }

    if (!destinations.email) {
      return res.status(400).json({
        error: `Email password reset code is not available for this account`,
        availableChannels,
        maskedDestinations: {
          email: maskValue(destinations.email, "email"),
        }
      });
    }

    const challengeId = uuidv4();
    const code = generateOtpCode();
    const expiresAt = Date.now() + OTP_EXPIRY_MS;
    const destination = destinations.email;
    const delivery = await deliverOtp({
      user,
      channel: "email",
      destination,
      code,
    });

    passwordResetChallenges.set(challengeId, {
      attempts: 0,
      code,
      user,
      channel: "email",
      expiresAt,
    });

    return res.status(200).json({
      challengeId,
      channel: "email",
      destinationMasked: maskValue(destination, "email"),
      availableChannels,
      maskedDestinations: {
        email: maskValue(destinations.email, "email"),
      },
      expiresAt: new Date(expiresAt).toISOString(),
      deliveryMode: delivery.deliveryMode,
      previewCode: delivery.previewCode,
    });
  } catch (e) {
    console.error("Password Reset Request Error:", e);
    return res.status(e.statusCode || 500).json({
      error: e.message,
      retryAt: e.retryAt ? new Date(e.retryAt).toISOString() : undefined,
    });
  }
});

app.post("/password-reset/confirm", async (req, res) => {
  const { challengeId, code, newPassword } = req.body;

  if (!challengeId || !code || !newPassword) {
    return res.status(400).json({ error: "Challenge ID, code, and new password are required" });
  }

  if (String(newPassword).trim().length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters long" });
  }

  cleanupExpiredPasswordResetChallenges();
  const challenge = passwordResetChallenges.get(challengeId);

  if (!challenge) {
    return res.status(404).json({ error: "Password reset challenge expired or was not found" });
  }

  if (challenge.expiresAt <= Date.now()) {
    passwordResetChallenges.delete(challengeId);
    return res.status(410).json({ error: "Password reset code has expired" });
  }

  challenge.attempts += 1;
  if (String(code).trim() !== challenge.code) {
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
      passwordResetChallenges.delete(challengeId);
      return res.status(429).json({ error: "Too many incorrect verification attempts" });
    }

    return res.status(401).json({
      error: "Invalid verification code",
      remainingAttempts: OTP_MAX_ATTEMPTS - challenge.attempts,
    });
  }

  try {
    const passwordHash = await bcrypt.hash(String(newPassword).trim(), 10);
    await pool.query(
      `UPDATE users
       SET password_hash = $2
       WHERE id = $1`,
      [challenge.user.id, passwordHash]
    );
    passwordResetChallenges.delete(challengeId);
    return res.status(200).json({ success: true });
  } catch (e) {
    console.error("Password Reset Confirm Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/app-lock/reset/request", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  cleanupExpiredAppLockResetChallenges();

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "Account not found" });
    }

    assertOtpRequestAllowed(passwordResetRequestWindows, `applock:${email}`);
    const code = generateOtpCode();
    const challengeId = uuidv4();
    const expiresAt = Date.now() + OTP_EXPIRY_MS;
    await deliverOtp({
      user,
      channel: "email",
      destination: user.email,
      code,
    });

    appLockResetChallenges.set(challengeId, {
      user,
      code,
      attempts: 0,
      expiresAt,
    });

    return res.status(200).json({
      challengeId,
      destinationMasked: maskValue(user.email, "email"),
      expiresAt: new Date(expiresAt).toISOString(),
    });
  } catch (e) {
    console.error("App Lock Reset Request Error:", e);
    return res.status(e.statusCode || 500).json({
      error: e.message,
      retryAt: e.retryAt ? new Date(e.retryAt).toISOString() : undefined,
    });
  }
});

app.post("/app-lock/reset/confirm", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const challengeId = String(req.body.challengeId || "").trim();
  const code = String(req.body.code || "").trim();

  if (!email || !challengeId || !code) {
    return res.status(400).json({ error: "Email, challengeId, and code are required" });
  }

  cleanupExpiredAppLockResetChallenges();
  const challenge = appLockResetChallenges.get(challengeId);
  if (!challenge || normalizeEmail(challenge.user?.email) !== email) {
    return res.status(404).json({ error: "Reset challenge expired or was not found" });
  }
  if (challenge.expiresAt <= Date.now()) {
    appLockResetChallenges.delete(challengeId);
    return res.status(410).json({ error: "Reset code has expired" });
  }

  challenge.attempts += 1;
  if (code !== challenge.code) {
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
      appLockResetChallenges.delete(challengeId);
      return res.status(429).json({ error: "Too many incorrect verification attempts" });
    }
    return res.status(401).json({
      error: "Invalid verification code",
      remainingAttempts: OTP_MAX_ATTEMPTS - challenge.attempts,
    });
  }

  appLockResetChallenges.delete(challengeId);
  return res.status(200).json({ success: true });
});

app.get("/authenticator/status/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    await ensureAuthenticatorSchema();
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({
      enabled: user.authenticator_enabled === true,
      email: user.email,
    });
  } catch (e) {
    console.error("Authenticator Status Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/authenticator/setup/request", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  try {
    await ensureAuthenticatorSchema();
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const secret = generateAuthenticatorSecret(user);
    pendingAuthenticatorSetups.set(email, {
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
      createdAt: Date.now(),
    });

    return res.json({
      email: user.email,
      manualEntryKey: secret.base32,
      otpauthUrl: secret.otpauth_url,
      issuer: "eSchool",
      accountLabel: buildAuthenticatorLabel(user),
    });
  } catch (e) {
    console.error("Authenticator Setup Request Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/authenticator/setup/confirm", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();
  try {
    await ensureAuthenticatorSchema();
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const pending = pendingAuthenticatorSetups.get(email);
    if (!pending) {
      return res.status(404).json({ error: "No pending authenticator setup found" });
    }
    if (!verifyAuthenticatorToken(pending.secret, code)) {
      return res.status(401).json({ error: "Invalid authenticator code" });
    }

    await pool.query(
      `UPDATE users
       SET authenticator_secret = $2,
           authenticator_enabled = true
       WHERE id = $1`,
      [user.id, pending.secret]
    );
    pendingAuthenticatorSetups.delete(email);
    return res.json({ success: true, enabled: true });
  } catch (e) {
    console.error("Authenticator Setup Confirm Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/authenticator/disable", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();
  try {
    await ensureAuthenticatorSchema();
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (!user.authenticator_enabled || !user.authenticator_secret) {
      return res.status(400).json({ error: "Authenticator is not enabled" });
    }
    if (!verifyAuthenticatorToken(user.authenticator_secret, code)) {
      return res.status(401).json({ error: "Invalid authenticator code" });
    }

    await pool.query(
      `UPDATE users
       SET authenticator_secret = NULL,
           authenticator_enabled = false
       WHERE id = $1`,
      [user.id]
    );
    return res.json({ success: true, enabled: false });
  } catch (e) {
    console.error("Authenticator Disable Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Admin Login
app.post("/admin-login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) {
    return res.status(400).json({ error: "Username/email and password required" });
  }

  try {
    const result = await authenticateAdminLogin(usernameOrEmail, password);
    if (result.status === 200 && result.body?.user) {
      result.body.session = await recordLoginSession(req, result.body.user);
    }
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const regResult = await client.query(
      "SELECT * FROM registration WHERE id = $1 FOR UPDATE",
      [id]
    );
    if (regResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Registration not found" });
    }

    const reg = regResult.rows[0];
    const role = (reg.role || 'student').toLowerCase().trim();
    const fullName = String(reg.full_name || reg.username || 'New User').trim();
    const phone = reg.phone || null;

    if (reg.approved === true) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This registration is already approved" });
    }

    const existingUser = await client.query(
      "SELECT id FROM users WHERE email = $1 OR username = $2 LIMIT 1",
      [reg.email, reg.username]
    );
    let userId;

    if (existingUser.rows.length > 0) {
      userId = existingUser.rows[0].id;
      await client.query(
        `UPDATE users
         SET username = $2,
             email = $3,
             password_hash = $4,
             role = $5
         WHERE id = $1`,
        [userId, reg.username, reg.email, reg.password_hash, role]
      );
    } else {
      const userResult = await client.query(
        `INSERT INTO users (username, email, password_hash, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [reg.username, reg.email, reg.password_hash, role]
      );
      userId = userResult.rows[0].id;
    }

    if (role === 'student') {
      const existingStudent = await client.query(
        `SELECT admission_number, class_name
         FROM students
         WHERE user_id = $1
         LIMIT 1`,
        [userId]
      );
      const admissionNumber =
        existingStudent.rows[0]?.admission_number ||
        await getNextStudentAdmissionNumber(client);

      await client.query(
        `INSERT INTO students (user_id, admission_number, full_name, phone, profile_locked)
         VALUES ($1, $2, $3, $4, false)
         ON CONFLICT (user_id)
         DO UPDATE SET
           admission_number = EXCLUDED.admission_number,
           full_name = EXCLUDED.full_name,
           phone = EXCLUDED.phone,
           profile_locked = CASE
             WHEN COALESCE(students.class_name, '') = '' THEN false
             ELSE students.profile_locked
           END,
           updated_at = NOW()`,
        [userId, admissionNumber, fullName, phone]
      );
    }

    if (role === 'teacher') {
      await client.query(
        `INSERT INTO teachers (user_id, full_name, phone)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id)
         DO UPDATE SET
           full_name = EXCLUDED.full_name,
           phone = EXCLUDED.phone,
           updated_at = NOW()`,
        [userId, fullName, phone]
      );
    }

    if (role === 'parent') {
      await client.query(
        `INSERT INTO parents (user_id, full_name, phone)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id)
         DO UPDATE SET
           full_name = EXCLUDED.full_name,
           phone = EXCLUDED.phone,
           updated_at = NOW()`,
        [userId, fullName, phone]
      );
    }

    await client.query(
      "UPDATE registration SET approved = true, approved_at = NOW(), approved_by = (SELECT user_id FROM admins WHERE user_id IS NOT NULL LIMIT 1) WHERE id = $1",
      [id]
    );

    console.log(`Approved registration ${id} → Role: ${role}`);
    await client.query("COMMIT");
    res.json({ message: "User approved successfully" });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Approval Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ===================== PARENT FEATURES =====================
app.get("/students", async (req, res) => {
  const page = Math.max(parseInt(req.query.page || "0", 10), 0);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || "20", 10), 1), 100);
  const search = String(req.query.search || "").trim();
  const offset = page * pageSize;

  try {
    const searchParam = `%${search}%`;
    const result = await pool.query(
      `SELECT s.id,
              s.user_id,
              s.full_name,
              s.class_name,
              s.admission_number,
              s.phone,
              s.gender,
              s.address,
              s.profile_picture_url,
              COALESCE(s.profile_locked, false) AS profile_locked,
              s.updated_at,
              u.email,
              COUNT(*) OVER() AS total_count
       FROM students s
       JOIN users u ON u.id = s.user_id
       WHERE (
         $1 = ''
         OR s.full_name ILIKE $2
         OR u.email ILIKE $2
         OR COALESCE(s.admission_number, '') ILIKE $2
         OR COALESCE(s.class_name, '') ILIKE $2
       )
       ORDER BY s.updated_at DESC NULLS LAST, s.created_at DESC
       LIMIT $3 OFFSET $4`,
      [search, searchParam, pageSize, offset]
    );

    const total = result.rows.length > 0 ? Number(result.rows[0].total_count || result.rows.length) : 0;
    res.json({
      data: result.rows.map((row) => ({
        ...row,
        total_count: undefined,
      })),
      total,
      page,
      pageSize,
    });
  } catch (e) {
    console.error("Get Students Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/students/:id/unlock-profile", async (req, res) => {
  const studentId = req.params.id;
  try {
    const result = await pool.query(
      `UPDATE students
       SET profile_locked = false,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, full_name, class_name, admission_number, profile_locked`,
      [studentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    res.json({
      message: "Student profile unlocked for one edit.",
      student: result.rows[0],
    });
  } catch (e) {
    console.error("Unlock Student Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/students/unlock-all-profiles", async (_req, res) => {
  try {
    const result = await pool.query(
      `UPDATE students
       SET profile_locked = false,
           updated_at = NOW()
       WHERE COALESCE(profile_locked, false) = true`
    );

    res.json({
      message: "All student profiles unlocked for one edit.",
      updated_count: result.rowCount || 0,
    });
  } catch (e) {
    console.error("Unlock All Student Profiles Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/students/lock-all-profiles", async (_req, res) => {
  try {
    const result = await pool.query(
      `UPDATE students
       SET profile_locked = true,
           updated_at = NOW()
       WHERE COALESCE(profile_locked, false) = false`
    );

    res.json({
      message: "All student profiles locked.",
      updated_count: result.rowCount || 0,
    });
  } catch (e) {
    console.error("Lock All Student Profiles Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/update-student/:id", async (req, res) => {
  const studentId = req.params.id;
  const name = String(req.body.name || "").trim();
  const email = normalizeEmail(req.body.email);

  if (!name || !email) {
    return res.status(400).json({ error: "Student name and email are required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const studentResult = await client.query(
      `SELECT s.id, s.user_id
       FROM students s
       WHERE s.id = $1
       LIMIT 1`,
      [studentId]
    );

    if (studentResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Student not found" });
    }

    const student = studentResult.rows[0];

    await client.query(
      `UPDATE students
       SET full_name = $2,
           updated_at = NOW()
       WHERE id = $1`,
      [studentId, name]
    );

    await client.query(
      `UPDATE users
       SET email = $2
       WHERE id = $1`,
      [student.user_id, email]
    );

    await client.query("COMMIT");
    res.json({ message: "Student updated successfully" });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Update Student Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.delete("/delete-student/:id", async (req, res) => {
  const studentId = req.params.id;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const studentResult = await client.query(
      `SELECT user_id
       FROM students
       WHERE id = $1
       LIMIT 1`,
      [studentId]
    );

    if (studentResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Student not found" });
    }

    const userId = studentResult.rows[0].user_id;
    await client.query("DELETE FROM students WHERE id = $1", [studentId]);
    await client.query("DELETE FROM users WHERE id = $1", [userId]);
    await client.query("COMMIT");
    res.json({ message: "Student deleted successfully" });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Delete Student Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/teachers", async (req, res) => {
  const page = Math.max(parseInt(req.query.page || "0", 10), 0);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || "20", 10), 1), 100);
  const search = String(req.query.search || "").trim();
  const offset = page * pageSize;

  try {
    const searchParam = `%${search}%`;
    const result = await pool.query(
      `SELECT t.id,
              t.user_id,
              t.full_name,
              t.teacher_number,
              t.subject,
              t.class_name,
              t.phone,
              t.profile_picture_url,
              COALESCE(t.profile_locked, true) AS profile_locked,
              t.updated_at,
              u.email,
              COUNT(*) OVER() AS total_count
       FROM teachers t
       JOIN users u ON u.id = t.user_id
       WHERE (
         $1 = ''
         OR t.full_name ILIKE $2
         OR u.email ILIKE $2
         OR COALESCE(t.teacher_number, '') ILIKE $2
         OR COALESCE(t.subject, '') ILIKE $2
         OR COALESCE(t.class_name, '') ILIKE $2
       )
       ORDER BY t.updated_at DESC NULLS LAST, t.created_at DESC
       LIMIT $3 OFFSET $4`,
      [search, searchParam, pageSize, offset]
    );

    const total =
      result.rows.length > 0 ? Number(result.rows[0].total_count || result.rows.length) : 0;
    res.json({
      data: result.rows.map((row) => ({
        ...row,
        total_count: undefined,
      })),
      total,
      page,
      pageSize,
    });
  } catch (e) {
    console.error("Get Teachers Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/teachers/:id/unlock-profile", async (req, res) => {
  const teacherId = req.params.id;
  try {
    const result = await pool.query(
      `UPDATE teachers
       SET profile_locked = false,
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, full_name, subject, class_name, teacher_number, profile_locked`,
      [teacherId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Teacher not found" });
    }

    res.json({
      message: "Teacher profile unlocked for one edit.",
      teacher: result.rows[0],
    });
  } catch (e) {
    console.error("Unlock Teacher Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/teachers/unlock-all-profiles", async (_req, res) => {
  try {
    const result = await pool.query(
      `UPDATE teachers
       SET profile_locked = false,
           updated_at = NOW()
       WHERE COALESCE(profile_locked, true) = true`
    );

    res.json({
      message: "All teacher profiles unlocked for one edit.",
      updated_count: result.rowCount || 0,
    });
  } catch (e) {
    console.error("Unlock All Teacher Profiles Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/teachers/lock-all-profiles", async (_req, res) => {
  try {
    const result = await pool.query(
      `UPDATE teachers
       SET profile_locked = true,
           updated_at = NOW()
       WHERE COALESCE(profile_locked, true) = false`
    );

    res.json({
      message: "All teacher profiles locked.",
      updated_count: result.rowCount || 0,
    });
  } catch (e) {
    console.error("Lock All Teacher Profiles Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.put("/update-teacher/:id", async (req, res) => {
  const teacherId = req.params.id;
  const name = String(req.body.name || "").trim();
  const email = normalizeEmail(req.body.email);

  if (!name || !email) {
    return res.status(400).json({ error: "Teacher name and email are required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const teacherResult = await client.query(
      `SELECT t.id, t.user_id
       FROM teachers t
       WHERE t.id = $1
       LIMIT 1`,
      [teacherId]
    );

    if (teacherResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Teacher not found" });
    }

    const teacher = teacherResult.rows[0];

    await client.query(
      `UPDATE teachers
       SET full_name = $2,
           updated_at = NOW()
       WHERE id = $1`,
      [teacherId, name]
    );

    await client.query(
      `UPDATE users
       SET email = $2
       WHERE id = $1`,
      [teacher.user_id, email]
    );

    await client.query("COMMIT");
    res.json({ message: "Teacher updated successfully" });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Update Teacher Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

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
      `SELECT id,
              profile_locked,
              full_name,
              admission_number,
              class_name,
              profile_picture_url
       FROM students
       WHERE user_id = $1
       LIMIT 1`,
      [user.id]
    );

    const isInitialProfileCompletion =
      existingProfile.rows.length === 0 ||
      !String(existingProfile.rows[0].class_name || "").trim();

    if (
      existingProfile.rows.length > 0 &&
      existingProfile.rows[0].profile_locked === true &&
      !isInitialProfileCompletion &&
      !hasAdminOverride
    ) {
      return res.status(403).json({
        error: "This student profile is locked. Ask an admin to edit it.",
      });
    }

    const preservedFullName =
      existingProfile.rows.length > 0
        ? existingProfile.rows[0].full_name
        : String(full_name).trim();
    const preservedAdmissionNumber =
      existingProfile.rows.length > 0
        ? existingProfile.rows[0].admission_number
        : String(admission_number).trim();
    const preservedPicture =
      typeof profile_picture_url === "string" && profile_picture_url.trim().length > 0
        ? profile_picture_url.trim()
        : (existingProfile.rows.length > 0
            ? existingProfile.rows[0].profile_picture_url || null
            : null);

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
        preservedAdmissionNumber,
        preservedFullName,
        gender ? String(gender).trim() : null,
        date_of_birth || null,
        String(class_name).trim(),
        phone ? String(phone).trim() : null,
        address ? String(address).trim() : null,
        preservedPicture,
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

app.post("/student-profile/:email/photo", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const profilePictureUrl = String(req.body.profile_picture_url || "").trim();

  if (!profilePictureUrl) {
    return res.status(400).json({ error: "A profile picture is required" });
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
    if (user.role !== "student") {
      return res.status(403).json({ error: "Only student accounts can update this profile" });
    }

    const result = await pool.query(
      `UPDATE students
       SET profile_picture_url = $2,
           updated_at = NOW()
       WHERE user_id = $1
       RETURNING id`,
      [user.id, profilePictureUrl]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Student profile not found" });
    }

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
      [result.rows[0].id]
    );

    return res.json(profileResult.rows[0]);
  } catch (e) {
    console.error("Update Student Profile Photo Error:", e);
    return res.status(500).json({ error: e.message });
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
      LEFT JOIN (
        SELECT LOWER(TRIM(COALESCE(s.class_name, ''))) AS student_class_name
        FROM students s
        JOIN users u ON s.user_id = u.id
        WHERE u.email = $1
        LIMIT 1
      ) student_profile ON true
      WHERE COALESCE(student_profile.student_class_name, '') = ''
         OR lc.class_name IS NULL
         OR TRIM(COALESCE(lc.class_name, '')) = ''
         OR LOWER(
              REGEXP_REPLACE(TRIM(COALESCE(lc.class_name, '')), '\\s+', '', 'g')
            ) = LOWER(
              REGEXP_REPLACE(COALESCE(student_profile.student_class_name, ''), '\\s+', '', 'g')
            )
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

app.put("/notifications/:email/read-all", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `UPDATE notifications
       SET is_read = true
       WHERE user_id = $1
         AND COALESCE(is_read, false) = false
       RETURNING id`,
      [user.id]
    );

    res.json({ success: true, count: result.rows.length });
  } catch (e) {
    console.error("Mark All Notifications Read Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/login-sessions/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `SELECT id,
              role,
              ip_address,
              NULL::text AS location,
              device_info,
              suspicious,
              logged_in_at,
              logged_out_at,
              is_current
       FROM login_sessions
       WHERE user_id = $1
       ORDER BY logged_in_at DESC
       LIMIT 20`,
      [user.id]
    );

    return res.json({ sessions: result.rows });
  } catch (e) {
    console.error("Get Login Sessions Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/push/devices/register", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const deviceToken = String(req.body.deviceToken || "").trim();
  const platform = String(req.body.platform || "android").trim().toLowerCase();
  const appRole = String(req.body.appRole || "").trim().toLowerCase() || null;
  const deviceName = String(req.body.deviceName || "").trim() || null;
  const appVersion = String(req.body.appVersion || "").trim() || null;

  try {
    if (!email || !deviceToken) {
      return res.status(400).json({ error: "email and deviceToken are required" });
    }
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    await ensurePushDeviceSchema();
    await pool.query(
      `INSERT INTO push_devices (
         user_id,
         device_token,
         platform,
         app_role,
         device_name,
         app_version,
         is_active,
         last_seen_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, true, NOW())
       ON CONFLICT (device_token)
       DO UPDATE SET
         user_id = EXCLUDED.user_id,
         platform = EXCLUDED.platform,
         app_role = EXCLUDED.app_role,
         device_name = EXCLUDED.device_name,
         app_version = EXCLUDED.app_version,
         is_active = true,
         last_seen_at = NOW()`,
      [user.id, deviceToken, platform, appRole, deviceName, appVersion]
    );
    return res.json({ success: true });
  } catch (e) {
    console.error("Register Push Device Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/push/devices/unregister", async (req, res) => {
  const deviceToken = String(req.body.deviceToken || "").trim();
  try {
    if (!deviceToken) {
      return res.status(400).json({ error: "deviceToken is required" });
    }
    await ensurePushDeviceSchema();
    await pool.query(
      `UPDATE push_devices
       SET is_active = false,
           last_seen_at = NOW()
       WHERE device_token = $1`,
      [deviceToken]
    );
    return res.json({ success: true });
  } catch (e) {
    console.error("Unregister Push Device Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/login-sessions/logout-others", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const currentSessionId = String(req.body.currentSessionId || "").trim();
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `UPDATE login_sessions
       SET logged_out_at = NOW(),
           is_current = false
       WHERE user_id = $1
         AND ($2 = '' OR id::text <> $2)
         AND logged_out_at IS NULL
       RETURNING id`,
      [user.id, currentSessionId]
    );

    return res.json({ success: true, count: result.rows.length });
  } catch (e) {
    console.error("Logout Other Devices Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/login-sessions/logout-one", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const sessionId = String(req.body.sessionId || "").trim();
  try {
    if (!sessionId) {
      return res.status(400).json({ error: "sessionId is required" });
    }
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `UPDATE login_sessions
       SET logged_out_at = NOW(),
           is_current = false
       WHERE id::text = $1
         AND user_id = $2
         AND logged_out_at IS NULL
         AND is_current = false
       RETURNING id`,
      [sessionId, user.id]
    );

    return res.json({ success: true, count: result.rows.length });
  } catch (e) {
    console.error("Logout Single Device Error:", e);
    return res.status(500).json({ error: e.message });
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
    const recipientIds = usersResult.rows.map((user) => user.id);

    for (const user of usersResult.rows) {
      try {
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
      } catch (_) {
        await client.query(
          `INSERT INTO notifications (
             user_id,
             title,
             message,
             type,
             is_read
           )
           VALUES ($1, $2, $3, $4, false)`,
          [user.id, title, message, type]
        );
      }
    }

    try {
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
    } catch (_) {
      await client.query(
        `INSERT INTO notifications (
           user_id,
           title,
           message,
           type,
           is_read
         )
         VALUES ($1, $2, $3, 'system', false)`,
        [admin.id, 'Broadcast sent', `Your message "${title}" was sent to ${usersResult.rows.length} user(s).`]
      );
    }

    await client.query("COMMIT");
    await sendPushToUserIds(recipientIds, {
      title,
      body: message,
      data: {
        type,
        audience,
      },
    });
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
             m.thumbnail_url,
             m.group_id,
             m.moderation_status,
             m.moderation_reason,
             m.flagged_at,
             aw.id AS warning_id,
             aw.status AS warning_status,
             aw.appeal_status,
             aw.appeal_message,
             aw.appeal_submitted_at,
             aw.appeal_deadline_at,
             aw.resolved_at,
             aw.resolution_note,
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
      LEFT JOIN LATERAL (
        SELECT aw.*
        FROM admin_warnings aw
        WHERE aw.message_id = m.id
        ORDER BY aw.created_at DESC
        LIMIT 1
      ) aw ON true
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
        can_unflag: moderationStatus !== 'clear',
        can_reject_appeal: moderationStatus !== 'clear' && row.appeal_status === 'submitted',
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
      `INSERT INTO admin_warnings (
         admin_user_id,
         target_user_id,
         message_id,
         reason,
         status,
         appeal_status,
         appeal_deadline_at
       )
       VALUES ($1, $2, $3, $4, 'active', 'pending', NOW() + ($5 * INTERVAL '1 hour'))`,
      [admin.id, target.id, messageId, reason, CHAT_APPEAL_WINDOW_HOURS]
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

app.post("/admin/chat/unflag", async (req, res) => {
  const adminEmail = normalizeEmail(req.body.adminEmail);
  const warningId = req.body.warningId || null;
  const messageId = req.body.messageId || null;
  const resolutionNote = String(req.body.resolutionNote || "Appeal accepted by admin").trim();

  if (!warningId && !messageId) {
    return res.status(400).json({ error: "Warning ID or message ID is required" });
  }

  const client = await pool.connect();
  try {
    const admin = await ensureAdminUser(adminEmail);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can unflag messages" });
    }

    await client.query("BEGIN");

    const warningResult = warningId
      ? await client.query(
          `SELECT id, target_user_id, message_id
           FROM admin_warnings
           WHERE id = $1
           LIMIT 1`,
          [warningId]
        )
      : await client.query(
          `SELECT id, target_user_id, message_id
           FROM admin_warnings
           WHERE message_id = $1
           ORDER BY created_at DESC
           LIMIT 1`,
          [messageId]
        );

    const warning = warningResult.rows[0];
    if (!warning) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Warning record not found" });
    }

    await client.query(
      `UPDATE admin_warnings
       SET status = 'resolved',
           appeal_status = CASE
             WHEN appeal_status = 'submitted' THEN 'accepted'
             ELSE appeal_status
           END,
           resolved_at = NOW(),
           resolution_note = $2
       WHERE id = $1`,
      [warning.id, resolutionNote]
    );

    if (warning.message_id) {
      await client.query(
        `UPDATE messages
         SET moderation_status = 'clear',
             moderation_reason = NULL,
             flagged_at = NULL,
             reviewed_at = NOW(),
             reviewed_by = $2
         WHERE id = $1`,
        [warning.message_id, admin.id]
      );
    }

    await client.query(
      `UPDATE users
       SET is_chat_frozen = false,
           chat_frozen_at = NULL,
           chat_freeze_reason = NULL,
           chat_freeze_expires_at = NULL
       WHERE id = $1`,
      [warning.target_user_id]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES ($1, 'Message unflagged', $2, 'appeal_update', false)`,
      [warning.target_user_id, 'An admin has cleared your flagged message. Chat access is active again.']
    );

    await client.query("COMMIT");
    res.status(200).json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Admin Chat Unflag Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/admin/chat/reject-appeal", async (req, res) => {
  const adminEmail = normalizeEmail(req.body.adminEmail);
  const warningId = req.body.warningId || null;
  const messageId = req.body.messageId || null;
  const resolutionNote = String(req.body.resolutionNote || "Appeal rejected by admin").trim();
  const freezeHours = Number(req.body.freezeHours || 24);

  if ((!warningId && !messageId) || freezeHours <= 0) {
    return res.status(400).json({ error: "Warning/message reference and a valid freeze duration are required" });
  }

  const client = await pool.connect();
  try {
    const admin = await ensureAdminUser(adminEmail);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can reject appeals" });
    }

    await client.query("BEGIN");
    const warningResult = warningId
      ? await client.query(
          `SELECT id, target_user_id, message_id
           FROM admin_warnings
           WHERE id = $1
           LIMIT 1`,
          [warningId]
        )
      : await client.query(
          `SELECT id, target_user_id, message_id
           FROM admin_warnings
           WHERE message_id = $1
           ORDER BY created_at DESC
           LIMIT 1`,
          [messageId]
        );

    const warning = warningResult.rows[0];
    if (!warning) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Warning record not found" });
    }

    await client.query(
      `UPDATE admin_warnings
       SET appeal_status = 'rejected',
           freeze_duration_hours = $2,
           freeze_until = NOW() + ($2 * INTERVAL '1 hour'),
           resolved_at = NOW(),
           resolution_note = $3
       WHERE id = $1`,
      [warning.id, freezeHours, resolutionNote]
    );

    await client.query(
      `UPDATE users
       SET is_chat_frozen = true,
           chat_frozen_at = NOW(),
           chat_freeze_reason = $2,
           chat_freeze_expires_at = NOW() + ($3 * INTERVAL '1 hour')
       WHERE id = $1`,
      [
        warning.target_user_id,
        `Appeal rejected by admin. Chat access frozen for ${freezeHours} hour(s).`,
        freezeHours,
      ]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES ($1, 'Appeal rejected', $2, 'appeal_update', false)`,
      [
        warning.target_user_id,
        `Your appeal was rejected. Chat access has been frozen for ${freezeHours} hour(s).`,
      ]
    );

    await client.query("COMMIT");
    res.status(200).json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Reject Chat Appeal Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/chat/access/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const access = await ensureChatAccessAllowed(user);
    const warning = access.chatState?.warning || null;
    return res.status(200).json({
      can_chat: access.ok,
      is_chat_frozen: access.chatState?.isFrozen === true,
      reason: access.chatState?.reason || null,
      appeal_deadline_at: access.chatState?.appealDeadlineAt || null,
      active_warning: warning
        ? {
            id: warning.id,
            reason: warning.reason,
            status: warning.status,
            appeal_status: warning.appeal_status,
            appeal_deadline_at: warning.appeal_deadline_at,
            created_at: warning.created_at,
            freeze_until: warning.freeze_until || null,
            resolution_note: warning.resolution_note || null,
            appeal_message: warning.appeal_message || null,
          }
        : null,
    });
  } catch (e) {
    console.error("Chat Access Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/appeals/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `SELECT aw.id,
              aw.reason,
              aw.status,
              aw.appeal_status,
              aw.appeal_message,
              aw.appeal_submitted_at,
              aw.appeal_deadline_at,
              aw.freeze_duration_hours,
              aw.freeze_until,
              aw.created_at,
              aw.resolved_at,
              aw.resolution_note,
              aw.message_id,
              m.message AS flagged_message
       FROM admin_warnings aw
       LEFT JOIN messages m ON m.id = aw.message_id
       WHERE aw.target_user_id = $1
       ORDER BY aw.created_at DESC`,
      [user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Chat Appeals Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/appeals", async (req, res) => {
  const studentEmail = normalizeEmail(req.body.studentEmail);
  const warningId = req.body.warningId || null;
  const appealMessage = String(req.body.appealMessage || "").trim();

  if (!studentEmail || !warningId || !appealMessage) {
    return res.status(400).json({ error: "Student email, warning ID, and appeal message are required" });
  }

  const client = await pool.connect();
  try {
    const user = await getUserByEmail(studentEmail);
    if (!user) {
      return res.status(404).json({ error: "Student account was not found" });
    }

    await client.query("BEGIN");
    const warningResult = await client.query(
      `SELECT id, admin_user_id, status, appeal_status
       FROM admin_warnings
       WHERE id = $1
         AND target_user_id = $2
       LIMIT 1`,
      [warningId, user.id]
    );

    const warning = warningResult.rows[0];
    if (!warning) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Warning not found" });
    }

    if (warning.status !== 'active') {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This warning is already closed" });
    }

    await client.query(
      `UPDATE admin_warnings
       SET appeal_message = $2,
           appeal_status = 'submitted',
           appeal_submitted_at = NOW()
       WHERE id = $1`,
      [warningId, appealMessage]
    );

    await client.query(
      `UPDATE users
       SET is_chat_frozen = false,
           chat_frozen_at = NULL,
           chat_freeze_reason = NULL,
           chat_freeze_expires_at = NULL
       WHERE id = $1`,
      [user.id]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES ($1, 'New chat appeal', $2, 'appeal', false)`,
      [
        warning.admin_user_id,
        `A user has submitted an appeal for a flagged chat warning.`,
      ]
    );

    await client.query("COMMIT");
    res.status(201).json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Submit Chat Appeal Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post("/calls/initiate", async (req, res) => {
  const callerEmail = normalizeEmail(req.body.callerId);
  const recipientEmail = normalizeEmail(req.body.recipientId);
  const groupId = req.body.groupId || null;
  const callType = String(req.body.callType || "voice").trim().toLowerCase();

  if (!callerEmail || (!recipientEmail && !groupId)) {
    return res.status(400).json({ error: "Caller and recipient or group are required" });
  }

  try {
    const caller = await getUserByEmail(callerEmail);
    if (!caller) {
      return res.status(404).json({ error: "Caller was not found" });
    }

    if (groupId) {
      const membersResult = await pool.query(
        `SELECT DISTINCT cgm.user_id
         FROM chat_group_members cgm
         WHERE cgm.group_id = $1
           AND cgm.user_id <> $2`,
        [groupId, caller.id]
      );
      const groupInfo = await pool.query(
        `SELECT name FROM chat_groups WHERE id = $1 LIMIT 1`,
        [groupId]
      );
      const groupName = groupInfo.rows[0]?.name || "group";
      const roomName = buildJitsiRoomName(
        callType === "video" ? "group-video" : "group-voice",
        [groupName, groupId]
      );
      const roomUrl = buildJitsiRoomUrl(roomName, callType);

      for (const member of membersResult.rows) {
        await pool.query(
          `INSERT INTO notifications (user_id, title, message, type, is_read)
           VALUES ($1, $2, $3, 'call_request', false)`,
          [
            member.user_id,
            callType === 'video' ? 'Incoming group video call' : 'Incoming group voice call',
            `${caller.username || caller.email} started a ${callType} call in your group. Join here: ${roomUrl}`,
          ]
        );
      }

      return res.status(201).json({
        ok: true,
        call_type: callType,
        group_id: groupId,
        room_name: roomName,
        room_url: roomUrl,
      });
    }

    const recipient = await getUserByEmail(recipientEmail);
    if (!recipient) {
      return res.status(404).json({ error: "Recipient was not found" });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(caller.id, recipient.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be allowed to chat before calling" });
    }
    const roomName = buildJitsiRoomName(
      callType === "video" ? "video" : "voice",
      [
        caller.email ? caller.email.split("@")[0] : "caller",
        recipient.email ? recipient.email.split("@")[0] : "recipient",
      ]
    );
    const roomUrl = buildJitsiRoomUrl(roomName, callType);

    await pool.query(
      `INSERT INTO notifications (user_id, title, message, type, is_read)
       VALUES ($1, $2, $3, 'call_request', false)`,
      [
        recipient.id,
        callType === 'video' ? 'Incoming video call' : 'Incoming voice call',
        `${caller.username || caller.email} is calling you. Join here: ${roomUrl}`,
      ]
    );

    return res.status(201).json({
      ok: true,
      call_type: callType,
      recipient_id: recipient.id,
      room_name: roomName,
      room_url: roomUrl,
    });
  } catch (e) {
    console.error("Call Initiation Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/announcements", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id,
             title,
             message,
             priority,
             announcement_type,
             expires_after_view,
             expiry_days,
             expires_at,
             audience_role,
             created_at
      FROM announcements
      WHERE expires_at IS NULL OR expires_at > NOW()
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (e) {
    console.error("Announcements Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/announcements/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const result = await pool.query(
      `
      SELECT a.id,
             a.title,
             a.message,
             a.priority,
             a.announcement_type,
             a.expires_after_view,
             a.expiry_days,
             a.expires_at,
             a.audience_role,
             a.created_at,
             av.viewed_at,
             av.expires_at AS view_expires_at
      FROM announcements a
      LEFT JOIN announcement_views av
        ON av.announcement_id = a.id
       AND av.user_id = $1
      WHERE (a.audience_role = 'all' OR a.audience_role = $2)
        AND (a.expires_at IS NULL OR a.expires_at > NOW())
        AND (
          a.expires_after_view = false
          OR av.id IS NULL
          OR av.expires_at IS NULL
          OR av.expires_at > NOW()
        )
      ORDER BY a.created_at DESC
      `,
      [user.id, user.role]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("Announcements By User Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/announcements/:id/view", async (req, res) => {
  const announcementId = req.params.id;
  const email = normalizeEmail(req.body.email);

  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const announcementResult = await pool.query(
      `SELECT id, expires_after_view, expiry_days
       FROM announcements
       WHERE id = $1
       LIMIT 1`,
      [announcementId]
    );

    if (announcementResult.rows.length == 0) {
      return res.status(404).json({ error: "Announcement not found" });
    }

    const announcement = announcementResult.rows[0];
    let viewExpiresAt = null;
    if (announcement.expires_after_view === true && announcement.expiry_days != null) {
      viewExpiresAt = new Date(Date.now() + Number(announcement.expiry_days) * 24 * 60 * 60 * 1000);
    }

    const result = await pool.query(
      `INSERT INTO announcement_views (announcement_id, user_id, viewed_at, expires_at)
       VALUES ($1, $2, NOW(), $3)
       ON CONFLICT (announcement_id, user_id)
       DO UPDATE SET
         viewed_at = NOW(),
         expires_at = EXCLUDED.expires_at
       RETURNING *`,
      [announcementId, user.id, viewExpiresAt]
    );

    res.json(result.rows[0]);
  } catch (e) {
    console.error("Announcement View Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/admin/announcements", async (req, res) => {
  const adminEmail = normalizeEmail(req.body.adminEmail);
  const title = String(req.body.title || '').trim();
  const message = String(req.body.message || '').trim();
  const priority = String(req.body.priority || 'normal').trim().toLowerCase();
  const announcementType = String(req.body.announcementType || 'activity').trim().toLowerCase();
  const audienceRole = String(req.body.audienceRole || 'all').trim().toLowerCase();
  const expiresAfterView = req.body.expiresAfterView === true;
  const expiryDays = req.body.expiryDays == null || req.body.expiryDays == ''
    ? null
    : Number(req.body.expiryDays);

  if (!title || !message) {
    return res.status(400).json({ error: "Title and message are required" });
  }

  try {
    const admin = await ensureAdminUser(adminEmail);
    if (!admin) {
      return res.status(403).json({ error: "Only admin accounts can create announcements" });
    }

    const expiresAt = !expiresAfterView && expiryDays != null
      ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000)
      : null;

    const result = await pool.query(
      `INSERT INTO announcements (
         title,
         message,
         priority,
         announcement_type,
         expires_after_view,
         expiry_days,
         expires_at,
         audience_role,
         created_by
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        title,
        message,
        priority,
        announcementType,
        expiresAfterView,
        expiryDays,
        expiresAt,
        audienceRole,
        admin.id,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Admin Announcement Create Error:", e);
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

app.post("/chat/thread/typing", async (req, res) => {
  const senderEmail = normalizeEmail(req.body.senderEmail);
  const receiverEmail = normalizeEmail(req.body.receiverEmail);
  const isTyping = req.body.isTyping === true;

  try {
    const sender = await getUserByEmail(senderEmail);
    const receiver = await getUserByEmail(receiverEmail);
    if (!sender || !receiver) {
      return res.status(404).json({ error: "Sender or receiver was not found" });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(sender.id, receiver.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be allowed to chat first" });
    }

    setTypingState(sender.id, receiver.id, isTyping);
    res.json({ ok: true, is_typing: isTyping, updated_at: new Date().toISOString() });
  } catch (e) {
    console.error("Chat Typing Update Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/thread/typing/:email/:peerEmail", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const peerEmail = normalizeEmail(req.params.peerEmail);

  try {
    const user = await getUserByEmail(email);
    const peer = await getUserByEmail(peerEmail);
    if (!user || !peer) {
      return res.status(404).json({ error: "User was not found" });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(user.id, peer.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be allowed to chat first" });
    }

    const entry = readTypingState(peer.id, user.id);
    res.json({
      is_typing: !!entry,
      updated_at: entry ? new Date(entry.updatedAt).toISOString() : null,
    });
  } catch (e) {
    console.error("Chat Typing Status Error:", e);
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
                SELECT fr.id
                FROM friend_requests fr
                WHERE (
                  (fr.sender_id = $1 AND fr.receiver_id = u.id)
                  OR
                  (fr.sender_id = u.id AND fr.receiver_id = $1)
                )
                ORDER BY fr.created_at DESC
                LIMIT 1
              ) AS request_id,
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

app.post("/chat/friend-requests/:id/cancel", async (req, res) => {
  const requestId = req.params.id;
  const actorEmail = normalizeEmail(req.body.actorEmail);

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

    const request = requestResult.rows[0];
    if (request.sender_id !== actor.id) {
      return res.status(403).json({ error: "Only the sender can cancel this request" });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: "Only pending friend requests can be canceled" });
    }

    await pool.query(`DELETE FROM friend_requests WHERE id = $1`, [requestId]);
    return res.json({ success: true, id: requestId, status: 'canceled' });
  } catch (e) {
    console.error("Cancel Friend Request Error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.get("/chat/contacts/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const access = await ensureChatAccessAllowed(user);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
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
         UNION
         SELECT p.user_id AS contact_id
         FROM parent_child pc
         JOIN students s ON s.id = pc.student_id
         JOIN parents p ON p.id = pc.parent_id
         WHERE s.user_id = $1
         UNION
         SELECT s.user_id AS contact_id
         FROM parent_child pc
         JOIN students s ON s.id = pc.student_id
         JOIN parents p ON p.id = pc.parent_id
         WHERE p.user_id = $1
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

app.get("/student/parents/:studentEmail", async (req, res) => {
  const studentEmail = normalizeEmail(req.params.studentEmail);
  try {
    const result = await pool.query(
      `SELECT p.id,
              u.email,
              p.full_name,
              p.phone,
              p.address,
              p.profile_picture_url,
              pc.relationship
       FROM parent_child pc
       JOIN students s ON s.id = pc.student_id
       JOIN parents p ON p.id = pc.parent_id
       JOIN users u ON u.id = p.user_id
       JOIN users su ON su.id = s.user_id
       WHERE su.email = $1
       ORDER BY p.full_name ASC`,
      [studentEmail]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Student Parents Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/thread/:email/:peerEmail", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const peerEmail = normalizeEmail(req.params.peerEmail);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 40, 1), 80);
  const before = req.query.before ? new Date(req.query.before) : null;
  try {
    const user = await getUserByEmail(email);
    const peer = await getUserByEmail(peerEmail);
    if (!user || !peer) {
      return res.status(404).json({ error: "User was not found" });
    }

    const access = await ensureChatAccessAllowed(user);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(user.id, peer.id);
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
      `SELECT *
       FROM (
         SELECT m.id,
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
              m.client_message_id,
              m.reply_to_message_id,
              m.forwarded_from_message_id,
              COALESCE(m.is_pinned, false) AS is_pinned,
              m.pinned_at,
              COALESCE(m.reactions, '{}'::jsonb) AS reactions,
              reply.message AS reply_message,
              reply.message_type AS reply_message_type,
              reply_sender.email AS reply_sender_email,
               COALESCE(reply_student.full_name, reply_teacher.full_name, reply_parent.full_name, reply_admin.full_name, reply_sender.username, reply_sender.email) AS reply_sender_name
         FROM messages m
         JOIN users sender_user ON sender_user.id = m.sender_id
         LEFT JOIN messages reply ON reply.id = m.reply_to_message_id
         LEFT JOIN users reply_sender ON reply_sender.id = reply.sender_id
         LEFT JOIN students reply_student ON reply_student.user_id = reply_sender.id
         LEFT JOIN teachers reply_teacher ON reply_teacher.user_id = reply_sender.id
         LEFT JOIN parents reply_parent ON reply_parent.user_id = reply_sender.id
         LEFT JOIN admins reply_admin ON reply_admin.user_id = reply_sender.id
         WHERE m.group_id IS NULL
           AND (
             (m.sender_id = $1 AND m.receiver_id = $2)
             OR
             (m.sender_id = $2 AND m.receiver_id = $1)
           )
           AND ($3::timestamp IS NULL OR m.created_at < $3)
         ORDER BY m.created_at DESC
         LIMIT $4
       ) recent_messages
       ORDER BY created_at ASC`,
      [
        user.id,
        peer.id,
        before && !Number.isNaN(before.getTime()) ? before.toISOString() : null,
        limit,
      ]
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
  const replyToMessageId = req.body.replyToMessageId || null;
  const forwardedFromMessageId = req.body.forwardedFromMessageId || null;

  try {
    await ensureChatMessageFeatureSchema();
    const sender = await getUserByEmail(senderEmail);
    const receiver = await getUserByEmail(receiverEmail);
    if (!sender || !receiver) {
      return res.status(404).json({ error: "Sender or receiver was not found" });
    }

    const access = await ensureChatAccessAllowed(sender);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(sender.id, receiver.id);
    if (!canChat) {
      return res.status(403).json({ error: "You must be friends before chatting" });
    }

    if (!message.trim() && !mediaUrl) {
      return res.status(400).json({ error: "Message text or media is required" });
    }

    if (clientMessageId) {
      const existing = await pool.query(
        `SELECT id, sender_id, receiver_id, message, sender_role, created_at, is_read,
                delivered_at, read_at, message_type, media_url, thumbnail_url,
                duration_seconds, client_message_id, reply_to_message_id,
                forwarded_from_message_id, is_pinned, pinned_at, reactions
         FROM messages
         WHERE group_id IS NULL
           AND sender_id = $1
           AND receiver_id = $2
           AND client_message_id = $3
         LIMIT 1`,
        [sender.id, receiver.id, clientMessageId]
      );
      if (existing.rows.length > 0) {
        return res.status(200).json(existing.rows[0]);
      }
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
         client_message_id,
         reply_to_message_id,
         forwarded_from_message_id
       )
       VALUES ($1, $2, $3, false, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, sender_id, receiver_id, message, sender_role, created_at, is_read,
                 delivered_at, read_at, message_type, media_url, thumbnail_url,
                 duration_seconds, client_message_id, reply_to_message_id,
                 forwarded_from_message_id, is_pinned, pinned_at, reactions`,
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
        replyToMessageId,
        forwardedFromMessageId,
      ]
    );

    setTypingState(sender.id, receiver.id, false);

    await sendPushToUserIds([receiver.id], {
      title: sender.username || sender.email || "New message",
      body: message.trim() || "Sent you a message",
      data: {
        type: "chat_message",
        senderEmail: sender.email,
        receiverEmail: receiver.email,
        messageType,
      },
    });

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

    const access = await ensureChatAccessAllowed(reader);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
    }

    const canChat = await ensureAcceptedFriendshipOrFamily(reader.id, peer.id);
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

app.get("/chat/contact-profile/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  try {
    const profile = await getChatContactProfile(email);
    if (!profile) {
      return res.status(404).json({ error: "Contact not found" });
    }
    const viewerEmail = normalizeEmail(req.query.viewerEmail);
    if (viewerEmail) {
      const viewer = await getUserByEmail(viewerEmail);
      if (viewer) {
        profile.is_blocked_by_me = await areUsersBlocked(viewer.id, profile.id);
      }
    }

    res.json(profile);
  } catch (e) {
    console.error("Chat Contact Profile Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/contacts/unfriend", async (req, res) => {
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const peerEmail = normalizeEmail(req.body.peerEmail);
  try {
    const actor = await getUserByEmail(actorEmail);
    const peer = await getUserByEmail(peerEmail);
    if (!actor || !peer) {
      return res.status(404).json({ error: "User not found" });
    }
    await pool.query(
      `DELETE FROM friend_requests
       WHERE status = 'accepted'
         AND ((sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1))`,
      [actor.id, peer.id]
    );
    res.json({ success: true });
  } catch (e) {
    console.error("Unfriend Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/contacts/block", async (req, res) => {
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const peerEmail = normalizeEmail(req.body.peerEmail);
  const reason = String(req.body.reason || "").trim();
  try {
    const actor = await getUserByEmail(actorEmail);
    const peer = await getUserByEmail(peerEmail);
    if (!actor || !peer) {
      return res.status(404).json({ error: "User not found" });
    }
    await pool.query(
      `INSERT INTO blocked_users (blocker_user_id, blocked_user_id)
       VALUES ($1, $2)
       ON CONFLICT (blocker_user_id, blocked_user_id) DO NOTHING`,
      [actor.id, peer.id]
    );
    const admins = await pool.query(`SELECT id FROM users WHERE role = 'admin'`);
    for (const admin of admins.rows) {
      await pool.query(
        `INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
         VALUES ($1, $2, $3, 'user_block', false, NOW())`,
        [
          admin.id,
          "Student blocked a contact",
          `${actor.email} blocked ${peer.email}${reason ? `: ${reason}` : "."}`,
        ]
      );
    }
    res.json({ success: true });
  } catch (e) {
    console.error("Block User Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/contacts/unblock", async (req, res) => {
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const peerEmail = normalizeEmail(req.body.peerEmail);
  try {
    const actor = await getUserByEmail(actorEmail);
    const peer = await getUserByEmail(peerEmail);
    if (!actor || !peer) {
      return res.status(404).json({ error: "User not found" });
    }
    await pool.query(
      `DELETE FROM blocked_users
       WHERE blocker_user_id = $1
         AND blocked_user_id = $2`,
      [actor.id, peer.id]
    );
    res.json({ success: true });
  } catch (e) {
    console.error("Unblock User Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/contacts/report", async (req, res) => {
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const peerEmail = normalizeEmail(req.body.peerEmail);
  const reason = String(req.body.reason || "").trim();
  try {
    const actor = await getUserByEmail(actorEmail);
    const peer = await getUserByEmail(peerEmail);
    if (!actor || !peer) {
      return res.status(404).json({ error: "User not found" });
    }
    const admins = await pool.query(`SELECT id FROM users WHERE role = 'admin'`);
    for (const admin of admins.rows) {
      await pool.query(
        `INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
         VALUES ($1, $2, $3, 'user_report', false, NOW())`,
        [
          admin.id,
          "Student report submitted",
          `${actor.email} reported ${peer.email}${reason ? `: ${reason}` : "."}`,
        ]
      );
    }
    res.json({ success: true });
  } catch (e) {
    console.error("Report User Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/messages/:messageId/react", async (req, res) => {
  const messageId = req.params.messageId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const emoji = String(req.body.emoji || "").trim();

  if (!emoji) {
    return res.status(400).json({ error: "Emoji reaction is required" });
  }

  try {
    await ensureChatMessageFeatureSchema();
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "User not found" });
    }

    const messageResult = await pool.query(
      `SELECT id, sender_id, receiver_id, group_id, reactions
       FROM messages
       WHERE id = $1
       LIMIT 1`,
      [messageId]
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    const message = messageResult.rows[0];
    if (message.group_id) {
      const membership = await getGroupMembership(message.group_id, actor.id);
      if (!membership) {
        return res.status(403).json({ error: "You are not a member of this group" });
      }
    } else {
      const allowed = actor.id === message.sender_id || actor.id === message.receiver_id;
      if (!allowed) {
        return res.status(403).json({ error: "You cannot react to this message" });
      }
    }

    const reactions = normalizeReactionState(message.reactions);
    const currentUsers = Array.isArray(reactions[emoji]) ? reactions[emoji] : [];
    const actorKey = normalizeEmail(actor.email);
    if (currentUsers.includes(actorKey)) {
      reactions[emoji] = currentUsers.filter((value) => value !== actorKey);
      if (reactions[emoji].length === 0) {
        delete reactions[emoji];
      }
    } else {
      reactions[emoji] = [...currentUsers, actorKey];
    }

    const updated = await pool.query(
      `UPDATE messages
       SET reactions = $2::jsonb
       WHERE id = $1
       RETURNING id, reactions`,
      [messageId, JSON.stringify(reactions)]
    );

    res.json(updated.rows[0]);
  } catch (e) {
    console.error("React Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/chat/messages/:messageId/pin", async (req, res) => {
  const messageId = req.params.messageId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const shouldPin = req.body.isPinned === true;

  try {
    await ensureChatMessageFeatureSchema();
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "User not found" });
    }

    const messageResult = await pool.query(
      `SELECT id, sender_id, receiver_id, group_id
       FROM messages
       WHERE id = $1
       LIMIT 1`,
      [messageId]
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    const message = messageResult.rows[0];
    if (message.group_id) {
      const membership = await getGroupMembership(message.group_id, actor.id);
      if (!membership) {
        return res.status(403).json({ error: "You are not a member of this group" });
      }
    } else {
      const allowed = actor.id === message.sender_id || actor.id === message.receiver_id;
      if (!allowed) {
        return res.status(403).json({ error: "You cannot pin this message" });
      }
    }

    const updated = await pool.query(
      `UPDATE messages
       SET is_pinned = $2,
           pinned_at = CASE WHEN $2 THEN NOW() ELSE NULL END
       WHERE id = $1
       RETURNING id, is_pinned, pinned_at`,
      [messageId, shouldPin]
    );

    res.json(updated.rows[0]);
  } catch (e) {
    console.error("Pin Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/chat/messages/:messageId", async (req, res) => {
  const messageId = req.params.messageId;
  const actorEmail = normalizeEmail(req.body.actorEmail);

  try {
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "User not found" });
    }

    const messageResult = await pool.query(
      `SELECT id, sender_id
       FROM messages
       WHERE id = $1
       LIMIT 1`,
      [messageId]
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    const message = messageResult.rows[0];
    if (message.sender_id !== actor.id) {
      return res.status(403).json({ error: "Only the sender can delete this message" });
    }

    await pool.query(`DELETE FROM messages WHERE id = $1`, [messageId]);
    res.json({ ok: true });
  } catch (e) {
    console.error("Delete Message Error:", e);
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

    const access = await ensureChatAccessAllowed(user);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
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
    await ensureChatGroupRoleSchema(client);
    const creator = await getUserByEmail(creatorEmail);
    if (!creator) {
      return res.status(404).json({ error: "Creator not found" });
    }

    const access = await ensureChatAccessAllowed(creator);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
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
      const role = member.id === creator.id ? "admin" : "member";
      await client.query(
        `INSERT INTO chat_group_members (group_id, user_id, is_admin, role)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (group_id, user_id) DO NOTHING`,
        [group.id, member.id, member.id === creator.id, role]
      );
    }
    await insertGroupSystemMessage({
      client,
      groupId: group.id,
      actorId: creator.id,
      actorRole: creator.role,
      message: `${creator.email} created the group`,
    });
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
    await ensureChatGroupRoleSchema(client);
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "Actor not found" });
    }

    const access = await ensureChatAccessAllowed(actor);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
    }

    const membership = await getGroupMembership(groupId, actor.id, client);
    if (!canManageGroupMembers(membership)) {
      return res.status(403).json({ error: "Only a group admin or moderator can add members" });
    }

    const normalizedEmails = [...new Set(memberEmails.map(normalizeEmail))];
    const members = await client.query(
      `SELECT id
       FROM users
       WHERE email = ANY($1)`,
      [normalizedEmails]
    );

    for (const member of members.rows) {
      const addedUser = await client.query(
        `SELECT email FROM users WHERE id = $1 LIMIT 1`,
        [member.id]
      );
      await client.query(
        `INSERT INTO chat_group_members (group_id, user_id, is_admin, role)
         VALUES ($1, $2, false, 'member')
         ON CONFLICT (group_id, user_id) DO NOTHING`,
        [groupId, member.id]
      );
      const addedEmail = addedUser.rows[0]?.email;
      if (addedEmail) {
        await insertGroupSystemMessage({
          client,
          groupId,
          actorId: actor.id,
          actorRole: actor.role,
          message: `${actor.email} added ${addedEmail}`,
        });
      }
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
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 40, 1), 80);
  const before = req.query.before ? new Date(req.query.before) : null;
  try {
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const access = await ensureChatAccessAllowed(user);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
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
      `SELECT *
       FROM (
         SELECT m.id,
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
              m.reply_to_message_id,
              m.forwarded_from_message_id,
              COALESCE(m.is_pinned, false) AS is_pinned,
              m.pinned_at,
              COALESCE(m.reactions, '{}'::jsonb) AS reactions,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS sender_name,
              reply.message AS reply_message,
              reply.message_type AS reply_message_type,
              reply_sender.email AS reply_sender_email,
              COALESCE(rs.full_name, rt.full_name, rp.full_name, ra.full_name, reply_sender.username, reply_sender.email) AS reply_sender_name
         FROM messages m
         JOIN users u ON u.id = m.sender_id
         LEFT JOIN students s ON s.user_id = u.id
         LEFT JOIN teachers t ON t.user_id = u.id
         LEFT JOIN parents p ON p.user_id = u.id
         LEFT JOIN admins a ON a.user_id = u.id
         LEFT JOIN messages reply ON reply.id = m.reply_to_message_id
         LEFT JOIN users reply_sender ON reply_sender.id = reply.sender_id
         LEFT JOIN students rs ON rs.user_id = reply_sender.id
         LEFT JOIN teachers rt ON rt.user_id = reply_sender.id
         LEFT JOIN parents rp ON rp.user_id = reply_sender.id
         LEFT JOIN admins ra ON ra.user_id = reply_sender.id
         WHERE m.group_id = $1
           AND ($2::timestamp IS NULL OR m.created_at < $2)
         ORDER BY m.created_at DESC
         LIMIT $3
       ) recent_messages
       ORDER BY created_at ASC`,
      [
        groupId,
        before && !Number.isNaN(before.getTime()) ? before.toISOString() : null,
        limit,
      ]
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
  const replyToMessageId = req.body.replyToMessageId || null;
  const forwardedFromMessageId = req.body.forwardedFromMessageId || null;

  try {
    await ensureChatMessageFeatureSchema();
    const sender = await getUserByEmail(senderEmail);
    if (!sender) {
      return res.status(404).json({ error: "Sender not found" });
    }

    const access = await ensureChatAccessAllowed(sender);
    if (!access.ok) {
      return res.status(access.status).json({ error: access.error });
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

    const groupCheck = await pool.query(
      `SELECT is_closed FROM chat_groups WHERE id = $1 LIMIT 1`,
      [groupId]
    );
    if (groupCheck.rows.length === 0) {
      return res.status(404).json({ error: "Group not found" });
    }
    if (groupCheck.rows[0].is_closed === true) {
      return res.status(403).json({ error: "This group has been closed by the admin" });
    }

    if (!message.trim() && !mediaUrl) {
      return res.status(400).json({ error: "Message text or media is required" });
    }

    if (clientMessageId) {
      const existing = await pool.query(
        `SELECT *
         FROM messages
         WHERE group_id = $1
           AND sender_id = $2
           AND client_message_id = $3
         LIMIT 1`,
        [groupId, sender.id, clientMessageId]
      );
      if (existing.rows.length > 0) {
        return res.status(200).json(existing.rows[0]);
      }
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
         client_message_id,
         reply_to_message_id,
         forwarded_from_message_id
       )
       VALUES ($1, NULL, $2, $3, false, $4, $5, $6, $7, $8, $9, $10, $11)
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
        replyToMessageId,
        forwardedFromMessageId,
      ]
    );

    const membersResult = await pool.query(
      `SELECT user_id
       FROM chat_group_members
       WHERE group_id = $1
         AND user_id <> $2`,
      [groupId, sender.id]
    );

    await sendPushToUserIds(
      membersResult.rows.map((member) => member.user_id),
      {
        title: `New message in group`,
        body: message.trim() || "Shared media in the group",
        data: {
          type: "group_message",
          groupId,
          senderEmail: sender.email,
          messageType,
        },
      }
    );

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Send Group Message Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/groups/:groupId/details/:email", async (req, res) => {
  const groupId = req.params.groupId;
  const email = normalizeEmail(req.params.email);
  try {
    await ensureChatGroupRoleSchema();
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const membership = await getGroupMembership(groupId, user.id);
    if (!membership) {
      return res.status(403).json({ error: "You are not a member of this group" });
    }

    const result = await pool.query(
      `SELECT g.*,
              creator.email AS created_by_email,
              COALESCE(cs.full_name, ct.full_name, cp.full_name, ca.full_name, creator.username, creator.email) AS created_by_name,
              membership.is_admin,
              membership.role,
              (
                SELECT array_agg(lower(u.email))
                FROM chat_group_members gm
                JOIN users u ON u.id = gm.user_id
                WHERE gm.group_id = g.id
                  AND (gm.is_admin = true OR COALESCE(gm.role, 'member') = 'admin')
              ) AS admins
       FROM chat_groups g
       LEFT JOIN users creator ON creator.id = g.created_by
       LEFT JOIN students cs ON cs.user_id = creator.id
       LEFT JOIN teachers ct ON ct.user_id = creator.id
       LEFT JOIN parents cp ON cp.user_id = creator.id
       LEFT JOIN admins ca ON ca.user_id = creator.id
       JOIN chat_group_members membership ON membership.group_id = g.id AND membership.user_id = $2
       WHERE g.id = $1
       LIMIT 1`,
      [groupId, user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Group not found" });
    }

    res.json(result.rows[0]);
  } catch (e) {
    console.error("Get Group Details Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.get("/chat/groups/:groupId/members", async (req, res) => {
  const groupId = req.params.groupId;
  try {
    await ensureChatGroupRoleSchema();
    const result = await pool.query(
      `SELECT u.email,
              gm.user_id,
              gm.is_admin,
              COALESCE(gm.role, CASE WHEN gm.is_admin THEN 'admin' ELSE 'member' END) AS role,
              gm.joined_at,
              COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, u.email) AS display_name,
              COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url) AS profile_picture_url
       FROM chat_group_members gm
       JOIN users u ON u.id = gm.user_id
       LEFT JOIN students s ON s.user_id = u.id
       LEFT JOIN teachers t ON t.user_id = u.id
       LEFT JOIN parents p ON p.user_id = u.id
       LEFT JOIN admins a ON a.user_id = u.id
       WHERE gm.group_id = $1
       ORDER BY CASE COALESCE(gm.role, CASE WHEN gm.is_admin THEN 'admin' ELSE 'member' END)
           WHEN 'admin' THEN 0
           WHEN 'moderator' THEN 1
           ELSE 2
         END,
         display_name ASC`,
      [groupId]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("Get Group Members Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.patch("/chat/groups/:groupId/members/:memberEmail/role", async (req, res) => {
  const groupId = req.params.groupId;
  const memberEmail = normalizeEmail(req.params.memberEmail);
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const nextRole = String(req.body.role || "").trim().toLowerCase();

  if (!["member", "moderator"].includes(nextRole)) {
    return res.status(400).json({ error: "Role must be member or moderator" });
  }

  const client = await pool.connect();
  try {
    await ensureChatGroupRoleSchema(client);
    const actor = await getUserByEmail(actorEmail);
    const member = await getUserByEmail(memberEmail);
    if (!actor || !member) {
      return res.status(404).json({ error: "User not found" });
    }

    const actorMembership = await getGroupMembership(groupId, actor.id, client);
    if (!actorMembership || !(actorMembership.is_admin === true || actorMembership.role === "admin")) {
      return res.status(403).json({ error: "Only a group admin can update member roles" });
    }

    const memberMembership = await getGroupMembership(groupId, member.id, client);
    if (!memberMembership) {
      return res.status(404).json({ error: "Member not found in this group" });
    }
    if (memberMembership.is_admin === true || memberMembership.role === "admin") {
      return res.status(400).json({ error: "The group admin role cannot be changed here" });
    }

    const updated = await client.query(
      `UPDATE chat_group_members
       SET role = $3
       WHERE group_id = $1 AND user_id = $2
       RETURNING group_id, user_id, is_admin, role`,
      [groupId, member.id, nextRole]
    );
    await insertGroupSystemMessage({
      client,
      groupId,
      actorId: actor.id,
      actorRole: actor.role,
      message:
        nextRole === "moderator"
          ? `${actor.email} promoted ${member.email} to moderator`
          : `${actor.email} changed ${member.email} to member`,
    });

    res.json(updated.rows[0]);
  } catch (e) {
    console.error("Update Group Member Role Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.put("/chat/groups/:groupId", async (req, res) => {
  const groupId = req.params.groupId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const name = req.body.name == null ? undefined : String(req.body.name).trim();
  const description = req.body.description == null ? undefined : String(req.body.description).trim();
  const bio = req.body.bio == null ? undefined : String(req.body.bio).trim();
  const avatarUrl = req.body.avatarUrl == null ? undefined : req.body.avatarUrl;

  try {
    await ensureChatGroupRoleSchema();
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "Actor not found" });
    }

    const membership = await getGroupMembership(groupId, actor.id);
    if (!membership || !(membership.is_admin === true || membership.role === "admin")) {
      return res.status(403).json({ error: "Only a group admin can update group info" });
    }

    const updated = await pool.query(
      `UPDATE chat_groups
       SET name = COALESCE(NULLIF($2, ''), name),
           description = CASE WHEN $3 IS NULL THEN description ELSE $3 END,
           bio = CASE WHEN $4 IS NULL THEN bio ELSE $4 END,
           avatar_url = CASE WHEN $5 IS NULL THEN avatar_url ELSE $5 END,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING *`,
      [groupId, name, description, bio, avatarUrl]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "Group not found" });
    }

    res.json(updated.rows[0]);
  } catch (e) {
    console.error("Update Group Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/chat/groups/:groupId/members/:memberEmail", async (req, res) => {
  const groupId = req.params.groupId;
  const memberEmail = normalizeEmail(req.params.memberEmail);
  const actorEmail = normalizeEmail(req.body.actorEmail);
  const client = await pool.connect();

  try {
    await ensureChatGroupRoleSchema(client);
    const actor = await getUserByEmail(actorEmail);
    const member = await getUserByEmail(memberEmail);
    if (!actor || !member) {
      return res.status(404).json({ error: "User not found" });
    }

    const actorMembership = await getGroupMembership(groupId, actor.id, client);
    if (!canManageGroupMembers(actorMembership)) {
      return res.status(403).json({ error: "Only a group admin or moderator can remove members" });
    }

    const memberMembership = await getGroupMembership(groupId, member.id, client);
    if (!memberMembership) {
      return res.status(404).json({ error: "Member not found in this group" });
    }
    if (memberMembership.is_admin === true || memberMembership.role === "admin") {
      return res.status(400).json({ error: "The group admin cannot be removed from here" });
    }
    if (actorMembership.role === "moderator" && memberMembership.role === "moderator") {
      return res.status(403).json({ error: "Moderators cannot remove other moderators" });
    }

    await client.query(
      `DELETE FROM chat_group_members
       WHERE group_id = $1 AND user_id = $2`,
      [groupId, member.id]
    );
    await insertGroupSystemMessage({
      client,
      groupId,
      actorId: actor.id,
      actorRole: actor.role,
      message: `${actor.email} removed ${member.email}`,
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("Remove Group Member Error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.put("/chat/groups/:groupId/close", async (req, res) => {
  const groupId = req.params.groupId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  try {
    await ensureChatGroupRoleSchema();
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "Actor not found" });
    }

    const membership = await getGroupMembership(groupId, actor.id);
    if (!membership || !(membership.is_admin === true || membership.role === "admin")) {
      return res.status(403).json({ error: "Only a group admin can close the group" });
    }

    const updated = await pool.query(
      `UPDATE chat_groups
       SET is_closed = true,
           closed_at = CURRENT_TIMESTAMP,
           closed_by = $2,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING *`,
      [groupId, actor.id]
    );

    res.json(updated.rows[0] || { ok: true });
  } catch (e) {
    console.error("Close Group Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/chat/groups/:groupId", async (req, res) => {
  const groupId = req.params.groupId;
  const actorEmail = normalizeEmail(req.body.actorEmail);
  try {
    await ensureChatGroupRoleSchema();
    const actor = await getUserByEmail(actorEmail);
    if (!actor) {
      return res.status(404).json({ error: "Actor not found" });
    }

    const membership = await getGroupMembership(groupId, actor.id);
    if (!membership || !(membership.is_admin === true || membership.role === "admin")) {
      return res.status(403).json({ error: "Only a group admin can delete the group" });
    }

    await pool.query(`DELETE FROM chat_groups WHERE id = $1`, [groupId]);
    res.json({ ok: true });
  } catch (e) {
    console.error("Delete Group Error:", e);
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
  const {
    teacherEmail,
    hostEmail,
    title,
    subjectId,
    className,
    meetingLink,
    classTime
  } = req.body;
  const resolvedHostEmail = normalizeEmail(hostEmail || teacherEmail);

  if (!resolvedHostEmail || !title || !meetingLink || !classTime) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const hostUser = await pool.query(
      "SELECT id, role FROM users WHERE email = $1 LIMIT 1",
      [resolvedHostEmail]
    );
    if (hostUser.rows.length === 0) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const user = hostUser.rows[0];
    let teacherId = null;
    let resolvedClassName = typeof className === "string" ? className.trim() : null;

    if (user.role === 'teacher') {
      const teacher = await pool.query(
        "SELECT id, class_name FROM teachers WHERE user_id = $1 LIMIT 1",
        [user.id]
      );
      if (teacher.rows.length === 0) {
        return res.status(403).json({ error: "Teacher profile not found" });
      }
      teacherId = teacher.rows[0].id;
      resolvedClassName =
        resolvedClassName || String(teacher.rows[0].class_name || "").trim() || null;
    } else if (user.role === 'student') {
      const student = await pool.query(
        "SELECT class_name FROM students WHERE user_id = $1 LIMIT 1",
        [user.id]
      );
      if (student.rows.length === 0) {
        return res.status(403).json({ error: "Student profile not found" });
      }
      resolvedClassName =
        resolvedClassName || String(student.rows[0].class_name || "").trim() || null;
    } else {
      return res.status(403).json({ error: "Only teachers and students can create live classes" });
    }

    const result = await pool.query(
      `INSERT INTO live_classes (teacher_id, title, subject_id, meeting_link, class_time, class_name)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [teacherId, title, subjectId || null, meetingLink, classTime, resolvedClassName]
    );

    if (resolvedClassName) {
      const audience = await pool.query(
        `SELECT u.id
         FROM students s
         JOIN users u ON u.id = s.user_id
         WHERE LOWER(TRIM(COALESCE(s.class_name, ''))) = LOWER(TRIM($1))
           AND u.id <> $2`,
        [resolvedClassName, user.id]
      );

      const readableTime = new Date(classTime).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
      });
      const notificationTitle = "New live class scheduled";
      const notificationMessage = `${title} has been scheduled for ${readableTime}. Open Live Classes to join when it starts.`;

      for (const recipient of audience.rows) {
        await pool.query(
          `INSERT INTO notifications (user_id, title, message, type, is_read, created_at)
           VALUES ($1, $2, $3, 'live_class', false, NOW())`,
          [recipient.id, notificationTitle, notificationMessage]
        );
      }

      await sendPushToUserIds(
        audience.rows.map((item) => item.id),
        {
          title: notificationTitle,
          body: notificationMessage,
          data: {
            type: "live_class",
            live_class_id: String(result.rows[0].id || ""),
            class_name: resolvedClassName,
          },
        }
      );
    }

    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error("Create Live Class Error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/live-classes/:id/join", async (req, res) => {
  const liveClassId = req.params.id;
  const studentEmail = normalizeEmail(req.body.studentEmail);

  if (!liveClassId || !studentEmail) {
    return res.status(400).json({ error: "Live class id and student email are required" });
  }

  try {
    const studentResult = await pool.query(
      `SELECT s.id, s.class_name, s.full_name, u.id AS user_id
       FROM students s
       JOIN users u ON u.id = s.user_id
       WHERE u.email = $1
       LIMIT 1`,
      [studentEmail]
    );

    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const liveClassResult = await pool.query(
      `SELECT id, teacher_id, class_name, class_time, title
       FROM live_classes
       WHERE id = $1
       LIMIT 1`,
      [liveClassId]
    );

    if (liveClassResult.rows.length === 0) {
      return res.status(404).json({ error: "Live class not found" });
    }

    const student = studentResult.rows[0];
    const liveClass = liveClassResult.rows[0];

    if (
      liveClass.class_name &&
      String(liveClass.class_name).trim() !== "" &&
      String(student.class_name || "").trim().toLowerCase() !==
        String(liveClass.class_name || "").trim().toLowerCase()
    ) {
      return res.status(403).json({ error: "This live class does not belong to the student's class" });
    }

      const attendanceDate = (() => {
        const parsed = liveClass.class_time ? new Date(liveClass.class_time) : new Date();
        const y = parsed.getUTCFullYear();
      const m = String(parsed.getUTCMonth() + 1).padStart(2, "0");
      const d = String(parsed.getUTCDate()).padStart(2, "0");
      return `${y}-${m}-${d}`;
    })();

    const attendanceResult = await pool.query(
      `INSERT INTO attendance (student_id, date, status)
       VALUES ($1, $2, 'present')
       ON CONFLICT (student_id, date)
       DO UPDATE SET status = CASE
         WHEN attendance.status = 'absent' THEN 'present'
         ELSE attendance.status
       END
       RETURNING id, student_id, date, status`,
      [student.id, attendanceDate]
    );

      return res.status(200).json({
        ok: true,
        counts_for_attendance: true,
        host_type: liveClass.teacher_id ? "teacher" : "student",
        live_class_id: liveClass.id,
        attendance: attendanceResult.rows[0],
      });
  } catch (e) {
    console.error("Join Live Class Error:", e);
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
             t.class_name, t.teacher_number, t.profile_locked,
             u.email,
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

app.put("/teacher-profile/:email", async (req, res) => {
  const email = normalizeEmail(req.params.email);
  const {
    full_name,
    subject,
    class_name,
    phone,
    teacher_number,
    profile_picture_url,
  } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "A valid email address is required" });
  }

  if (!full_name || !teacher_number) {
    return res.status(400).json({
      error: "Full name and teacher number are required",
    });
  }

  try {
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
    if (user.role !== 'teacher') {
      return res.status(403).json({ error: "Only teacher accounts can update this profile" });
    }

    const existingProfile = await pool.query(
      "SELECT id, profile_locked, teacher_number, profile_picture_url FROM teachers WHERE user_id = $1 LIMIT 1",
      [user.id]
    );

    if (
      existingProfile.rows.length > 0 &&
      existingProfile.rows[0].profile_locked === true &&
      !hasAdminOverride
    ) {
      return res.status(403).json({
        error: "This teacher profile is locked. Ask an admin to unlock it.",
      });
    }

    const preservedPicture =
      typeof profile_picture_url === "string" && profile_picture_url.trim().length > 0
        ? profile_picture_url.trim()
        : (existingProfile.rows.length > 0
            ? existingProfile.rows[0].profile_picture_url || null
            : null);
    const preservedTeacherNumber =
      existingProfile.rows.length > 0 && existingProfile.rows[0].teacher_number
        ? existingProfile.rows[0].teacher_number
        : String(teacher_number).trim();

    await pool.query(
      `INSERT INTO teachers (
         user_id,
         teacher_number,
         full_name,
         subject,
         phone,
         profile_picture_url,
         class_name,
         profile_locked,
         updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, true, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET
         teacher_number = EXCLUDED.teacher_number,
         full_name = EXCLUDED.full_name,
         subject = EXCLUDED.subject,
         phone = EXCLUDED.phone,
         profile_picture_url = EXCLUDED.profile_picture_url,
         class_name = EXCLUDED.class_name,
         profile_locked = true,
         updated_at = NOW()`,
      [
        user.id,
        preservedTeacherNumber,
        String(full_name).trim(),
        subject ? String(subject).trim() : null,
        phone ? String(phone).trim() : null,
        preservedPicture,
        class_name ? String(class_name).trim() : null,
      ]
    );

    const profileResult = await pool.query(`
      SELECT t.full_name, t.subject, t.phone, t.profile_picture_url,
             t.class_name, t.teacher_number, t.profile_locked,
             u.email,
             COUNT(DISTINCT c.id) as total_classes,
             (SELECT COUNT(DISTINCT s.id)
              FROM students s
              WHERE s.class_name = t.class_name) as total_students
      FROM teachers t
      JOIN users u ON t.user_id = u.id
      LEFT JOIN classes c ON c.teacher_id = t.id
      WHERE u.email = $1
      GROUP BY t.id, u.email
      LIMIT 1`,
      [email]
    );

    res.status(200).json(profileResult.rows[0]);
  } catch (e) {
    console.error("Update Teacher Profile Error:", e);
    if (e.code === '23505') {
      return res.status(400).json({ error: "Teacher number is already in use" });
    }
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




