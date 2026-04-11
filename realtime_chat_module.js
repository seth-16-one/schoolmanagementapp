const express = require("express");
const { v4: uuidv4 } = require("uuid");

function createRealtimeChatModule({
  pool,
  getRequestIp,
}) {
  const router = express.Router();
  let schemaEnsured = false;
  const chatRateWindows = new Map();
  const otpRateWindows = new Map();
  const CHAT_WINDOW_MS = Number(process.env.CHAT_RATE_WINDOW_MS || 60 * 1000);
  const CHAT_LIMIT = Number(process.env.CHAT_RATE_LIMIT || 25);
  const OTP_WINDOW_MS = Number(process.env.RT_OTP_RATE_WINDOW_MS || 15 * 60 * 1000);
  const OTP_LIMIT = Number(process.env.RT_OTP_RATE_LIMIT || 5);

  function getApiKey() {
    return String(
      process.env.REALTIME_CHAT_API_KEY ||
        process.env.API_KEY ||
        process.env.OTP_API_KEY ||
        ""
    ).trim();
  }

  function requireApiKey(req, res, next) {
    const expected = getApiKey();
    if (!expected) {
      return res.status(500).json({ error: "REALTIME_CHAT_API_KEY is not configured" });
    }
    const provided = String(req.headers["x-api-key"] || "")
      .trim();
    if (!provided || provided !== expected) {
      return res.status(401).json({ error: "Invalid API key" });
    }
    next();
  }

  function cleanupWindow(store, windowMs) {
    const now = Date.now();
    for (const [key, timestamps] of store.entries()) {
      const next = timestamps.filter((item) => now - item < windowMs);
      if (next.length) {
        store.set(key, next);
      } else {
        store.delete(key);
      }
    }
  }

  function enforceRateLimit({ store, key, windowMs, limit, message }) {
    cleanupWindow(store, windowMs);
    const now = Date.now();
    const timestamps = store.get(key) || [];
    const recent = timestamps.filter((item) => now - item < windowMs);
    if (recent.length >= limit) {
      const error = new Error(message);
      error.statusCode = 429;
      throw error;
    }
    recent.push(now);
    store.set(key, recent);
  }

  function normalizeText(value) {
    return String(value || "").trim();
  }

  function normalizeEmail(value) {
    return normalizeText(value).toLowerCase();
  }

  function assertRequired(value, label) {
    if (!normalizeText(value)) {
      const error = new Error(`${label} is required`);
      error.statusCode = 400;
      throw error;
    }
  }

  function assertMessageContent(value) {
    const content = normalizeText(value);
    if (!content) {
      const error = new Error("Message content is required");
      error.statusCode = 400;
      throw error;
    }
    if (content.length > 4000) {
      const error = new Error("Message content is too long");
      error.statusCode = 400;
      throw error;
    }
    return content;
  }

  function normalizeMessageType(value) {
    const type = normalizeText(value).toLowerCase() || "text";
    if (!["text", "image", "audio"].includes(type)) {
      const error = new Error("Unsupported message type");
      error.statusCode = 400;
      throw error;
    }
    return type;
  }

  function normalizeMediaUrl(value) {
    const mediaUrl = String(value || "").trim();
    if (!mediaUrl) return null;
    if (mediaUrl.length > 2_000_000) {
      const error = new Error("Media payload is too large");
      error.statusCode = 400;
      throw error;
    }
    return mediaUrl;
  }

  function assertMessagePayload({ content, mediaUrl, messageType }) {
    const normalizedType = normalizeMessageType(messageType);
    const normalizedContent = normalizeText(content);
    const normalizedMediaUrl = normalizeMediaUrl(mediaUrl);
    if (!normalizedContent && !normalizedMediaUrl) {
      const error = new Error("Message content or media is required");
      error.statusCode = 400;
      throw error;
    }
    if (normalizedContent.length > 4000) {
      const error = new Error("Message content is too long");
      error.statusCode = 400;
      throw error;
    }
    return {
      content: normalizedContent,
      mediaUrl: normalizedMediaUrl,
      messageType: normalizedType,
    };
  }

  function assertStatus(value) {
    const status = normalizeText(value).toLowerCase();
    if (!["sent", "delivered", "seen"].includes(status)) {
      const error = new Error("Invalid message status");
      error.statusCode = 400;
      throw error;
    }
    return status;
  }

  function sanitizePagination(limit) {
    const value = Number(limit || 20);
    if (!Number.isFinite(value) || value <= 0) return 20;
    return Math.min(value, 50);
  }

  async function ensureSchema() {
    if (schemaEnsured) return;
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.realtime_conversations (
        id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        type text NOT NULL CHECK (type IN ('direct', 'group')),
        title text,
        description text,
        avatar_url text,
        created_by text NOT NULL,
        created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.realtime_conversation_members (
        id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
        user_id text NOT NULL,
        role text NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
        joined_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_read_message_id uuid,
        UNIQUE(conversation_id, user_id)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.realtime_messages (
        id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
        sender_id text NOT NULL,
        content text NOT NULL,
        message_type text NOT NULL DEFAULT 'text',
        media_url text,
        reactions jsonb NOT NULL DEFAULT '{}'::jsonb,
        group_id uuid REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
        status text NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'delivered', 'seen')),
        delivered_at timestamp without time zone,
        seen_at timestamp without time zone,
        created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS message_type text NOT NULL DEFAULT 'text'
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS media_url text
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS reactions jsonb NOT NULL DEFAULT '{}'::jsonb
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS reply_to_message_id uuid REFERENCES public.realtime_messages(id) ON DELETE SET NULL
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS is_pinned boolean NOT NULL DEFAULT false
    `);
    await pool.query(`
      ALTER TABLE public.realtime_messages
      ADD COLUMN IF NOT EXISTS pinned_at timestamp without time zone
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.realtime_typing_status (
        conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
        user_id text NOT NULL,
        is_typing boolean NOT NULL DEFAULT false,
        expires_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (conversation_id, user_id)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.realtime_presence (
        user_id text PRIMARY KEY,
        is_online boolean NOT NULL DEFAULT false,
        last_seen_at timestamp without time zone,
        updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_realtime_messages_conversation_created
      ON public.realtime_messages(conversation_id, created_at DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_realtime_messages_group_created
      ON public.realtime_messages(group_id, created_at DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_realtime_members_user_conversation
      ON public.realtime_conversation_members(user_id, conversation_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_realtime_typing_expires
      ON public.realtime_typing_status(expires_at)
    `);
    schemaEnsured = true;
  }

  async function ensureMembership(conversationId, userId) {
    const result = await pool.query(
      `SELECT role
       FROM public.realtime_conversation_members
       WHERE conversation_id = $1 AND user_id = $2
       LIMIT 1`,
      [conversationId, userId]
    );
    return result.rows[0] || null;
  }

  async function requireAdmin(conversationId, userId) {
    const member = await ensureMembership(conversationId, userId);
    if (!member || member.role !== "admin") {
      const error = new Error("Only group admins can perform this action");
      error.statusCode = 403;
      throw error;
    }
  }

  async function fetchMessages(req, res, conversationIdOverride = null) {
    try {
      await ensureSchema();
      const conversationId = normalizeText(conversationIdOverride || req.query.conversation_id);
      assertRequired(conversationId, "conversation_id");
      const limit = sanitizePagination(req.query.limit);
      const before = normalizeText(req.query.before);
      const params = [conversationId, limit];
      let beforeSql = "";
      if (before) {
        params.push(before);
        beforeSql = `AND created_at < $3::timestamp`;
      }
      const result = await pool.query(
        `SELECT id, conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, reactions, is_pinned, pinned_at, created_at, status, delivered_at, seen_at
         FROM public.realtime_messages
         WHERE conversation_id = $1
           ${beforeSql}
         ORDER BY created_at DESC
         LIMIT $2`,
        params
      );
      return res.status(200).json({
        items: result.rows.reverse(),
        hasMore: result.rows.length >= limit,
      });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  }

  async function createMessage(req, res, conversationIdOverride = null) {
    try {
      await ensureSchema();
      const conversationId = normalizeText(conversationIdOverride || req.body.conversation_id);
      const senderId = normalizeText(req.body.sender_id);
      const payload = assertMessagePayload({
        content: req.body.content,
        mediaUrl: req.body.media_url,
        messageType: req.body.message_type,
      });
      const replyToMessageId = normalizeText(req.body.reply_to_message_id) || null;
      assertRequired(conversationId, "conversation_id");
      assertRequired(senderId, "sender_id");
      enforceRateLimit({
        store: chatRateWindows,
        key: `${senderId}:${conversationId}`,
        windowMs: CHAT_WINDOW_MS,
        limit: CHAT_LIMIT,
        message: "Too many messages sent too quickly. Please slow down.",
      });

      const membership = await ensureMembership(conversationId, senderId);
      if (!membership) {
        const error = new Error("You are not a participant in this conversation");
        error.statusCode = 403;
        throw error;
      }

      if (replyToMessageId) {
        const replyExists = await pool.query(
          `SELECT id
           FROM public.realtime_messages
           WHERE id = $1 AND conversation_id = $2
           LIMIT 1`,
          [replyToMessageId, conversationId]
        );
        if (!replyExists.rows.length) {
          const error = new Error("Reply target was not found in this conversation");
          error.statusCode = 404;
          throw error;
        }
      }

      const result = await pool.query(
        `INSERT INTO public.realtime_messages (
           conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, group_id, status
         )
         SELECT $1, $2, $3, $4, $5, $6,
                CASE WHEN c.type = 'group' THEN c.id ELSE NULL END,
                'sent'
         FROM public.realtime_conversations c
         WHERE c.id = $1
         RETURNING id, conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, reactions, is_pinned, pinned_at, created_at, status, delivered_at, seen_at`,
        [conversationId, senderId, payload.content || "", payload.messageType, payload.mediaUrl, replyToMessageId]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Conversation not found" });
      }
      return res.status(201).json(result.rows[0]);
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  }

  router.use(requireApiKey);

  router.get("/health", async (_req, res) => {
    await ensureSchema();
    return res.status(200).json({ ok: true, service: "realtime-chat-module" });
  });

  router.post("/otp/rate-check", async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      assertRequired(email, "Email");
      enforceRateLimit({
        store: otpRateWindows,
        key: `${email}:${getRequestIp(req) || "unknown"}`,
        windowMs: OTP_WINDOW_MS,
        limit: OTP_LIMIT,
        message: "Too many OTP requests. Try again later.",
      });
      return res.status(200).json({
        ok: true,
        limit: OTP_LIMIT,
        windowMinutes: Math.round(OTP_WINDOW_MS / 60000),
      });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.get("/messages", async (req, res) => {
    return fetchMessages(req, res);
  });

  router.get("/conversations", async (req, res) => {
    try {
      await ensureSchema();
      const memberId = normalizeText(req.query.member_id);
      assertRequired(memberId, "member_id");
      const result = await pool.query(
        `SELECT c.id,
                c.type,
                c.title,
                c.description,
                c.avatar_url,
                c.created_by,
                c.created_at,
                c.updated_at,
                COALESCE(last_message.content, '') AS last_message,
                last_message.created_at AS last_message_at,
                COALESCE(unread.unread_count, 0)::int AS unread_count
         FROM public.realtime_conversations c
         JOIN public.realtime_conversation_members viewer
           ON viewer.conversation_id = c.id AND viewer.user_id = $1
         LEFT JOIN LATERAL (
           SELECT rm.id, rm.content, rm.created_at
           FROM public.realtime_messages rm
           WHERE rm.conversation_id = c.id
           ORDER BY rm.created_at DESC
           LIMIT 1
         ) last_message ON true
         LEFT JOIN LATERAL (
           SELECT COUNT(*) AS unread_count
           FROM public.realtime_messages rm
           LEFT JOIN public.realtime_messages last_read
             ON last_read.id = viewer.last_read_message_id
           WHERE rm.conversation_id = c.id
             AND rm.sender_id <> $1
             AND (
               viewer.last_read_message_id IS NULL OR
               rm.created_at > COALESCE(last_read.created_at, TO_TIMESTAMP(0))
             )
         ) unread ON true
         ORDER BY COALESCE(last_message.created_at, c.created_at) DESC`,
        [memberId]
      );
      return res.status(200).json({ items: result.rows });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/conversations/direct", async (req, res) => {
    const client = await pool.connect();
    try {
      await ensureSchema();
      const userAId = normalizeText(req.body.user_a_id);
      const userBId = normalizeText(req.body.user_b_id);
      assertRequired(userAId, "user_a_id");
      assertRequired(userBId, "user_b_id");
      if (userAId === userBId) {
        return res.status(400).json({ error: "Direct conversation requires two different users" });
      }

      await client.query("BEGIN");
      const existing = await client.query(
        `SELECT c.id, c.type, c.title, c.description, c.avatar_url, c.created_by, c.created_at, c.updated_at
         FROM public.realtime_conversations c
         JOIN public.realtime_conversation_members m1
           ON m1.conversation_id = c.id AND m1.user_id = $1
         JOIN public.realtime_conversation_members m2
           ON m2.conversation_id = c.id AND m2.user_id = $2
         WHERE c.type = 'direct'
         LIMIT 1`,
        [userAId, userBId]
      );
      if (existing.rows.length) {
        await client.query("COMMIT");
        return res.status(200).json(existing.rows[0]);
      }

      const created = await client.query(
        `INSERT INTO public.realtime_conversations (type, created_by)
         VALUES ('direct', $1)
         RETURNING id, type, title, description, avatar_url, created_by, created_at, updated_at`,
        [userAId]
      );
      const conversation = created.rows[0];
      for (const memberId of [userAId, userBId]) {
        await client.query(
          `INSERT INTO public.realtime_conversation_members (conversation_id, user_id, role)
           VALUES ($1, $2, 'member')`,
          [conversation.id, memberId]
        );
      }
      await client.query("COMMIT");
      return res.status(201).json(conversation);
    } catch (e) {
      await client.query("ROLLBACK");
      return res.status(e.statusCode || 500).json({ error: e.message });
    } finally {
      client.release();
    }
  });

  router.post("/messages", async (req, res) => {
    return createMessage(req, res);
  });

  router.patch("/messages/:messageId/status", async (req, res) => {
    try {
      await ensureSchema();
      const messageId = normalizeText(req.params.messageId);
      const status = assertStatus(req.body.status);
      const actorId = normalizeText(req.body.actor_id);
      assertRequired(messageId, "messageId");
      assertRequired(actorId, "actor_id");

      const timestamps = {
        sent: "NULL",
        delivered: "CURRENT_TIMESTAMP",
        seen: "CURRENT_TIMESTAMP",
      };

      const result = await pool.query(
        `UPDATE public.realtime_messages m
         SET status = $2,
             delivered_at = CASE
               WHEN $2 IN ('delivered','seen') AND delivered_at IS NULL THEN CURRENT_TIMESTAMP
               ELSE delivered_at
             END,
             seen_at = CASE
               WHEN $2 = 'seen' THEN CURRENT_TIMESTAMP
               ELSE seen_at
             END
         WHERE m.id = $1
           AND EXISTS (
             SELECT 1
             FROM public.realtime_conversation_members cm
             WHERE cm.conversation_id = m.conversation_id
               AND cm.user_id = $3
           )
         RETURNING id, conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, reactions, is_pinned, pinned_at, created_at, status, delivered_at, seen_at`,
        [messageId, status, actorId]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Message not found or access denied" });
      }
      return res.status(200).json(result.rows[0]);
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/typing", async (req, res) => {
    try {
      await ensureSchema();
      const conversationId = normalizeText(req.body.conversation_id);
      const userId = normalizeText(req.body.user_id);
      const isTyping = req.body.is_typing === true;
      assertRequired(conversationId, "conversation_id");
      assertRequired(userId, "user_id");
      const membership = await ensureMembership(conversationId, userId);
      if (!membership) {
        return res.status(403).json({ error: "You are not a participant in this conversation" });
      }
      const expiresAt = new Date(Date.now() + 5000);
      await pool.query(
        `INSERT INTO public.realtime_typing_status (
           conversation_id, user_id, is_typing, expires_at, updated_at
         ) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
         ON CONFLICT (conversation_id, user_id)
         DO UPDATE SET
           is_typing = EXCLUDED.is_typing,
           expires_at = EXCLUDED.expires_at,
           updated_at = CURRENT_TIMESTAMP`,
        [conversationId, userId, isTyping, expiresAt]
      );
      return res.status(200).json({ ok: true, expiresAt: expiresAt.toISOString() });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.get("/typing/:conversationId", async (req, res) => {
    try {
      await ensureSchema();
      const conversationId = normalizeText(req.params.conversationId);
      const viewerId = normalizeText(req.query.viewer_id);
      assertRequired(conversationId, "conversationId");
      const result = await pool.query(
        `SELECT user_id, is_typing, expires_at, updated_at
         FROM public.realtime_typing_status
         WHERE conversation_id = $1
           AND is_typing = true
           AND expires_at > CURRENT_TIMESTAMP
           ${viewerId ? "AND user_id <> $2" : ""}`,
        viewerId ? [conversationId, viewerId] : [conversationId]
      );
      return res.status(200).json({ items: result.rows });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/presence", async (req, res) => {
    try {
      await ensureSchema();
      const userId = normalizeText(req.body.user_id);
      const isOnline = req.body.is_online === true;
      assertRequired(userId, "user_id");
      await pool.query(
        `INSERT INTO public.realtime_presence (user_id, is_online, last_seen_at, updated_at)
         VALUES ($1, $2, CASE WHEN $2 THEN NULL ELSE CURRENT_TIMESTAMP END, CURRENT_TIMESTAMP)
         ON CONFLICT (user_id)
         DO UPDATE SET
           is_online = EXCLUDED.is_online,
           last_seen_at = CASE WHEN EXCLUDED.is_online THEN realtime_presence.last_seen_at ELSE CURRENT_TIMESTAMP END,
           updated_at = CURRENT_TIMESTAMP`,
        [userId, isOnline]
      );
      return res.status(200).json({ user_id: userId, is_online: isOnline });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.get("/presence/:userId", async (req, res) => {
    try {
      await ensureSchema();
      const userId = normalizeText(req.params.userId);
      assertRequired(userId, "userId");
      const result = await pool.query(
        `SELECT user_id, is_online, last_seen_at, updated_at
         FROM public.realtime_presence
         WHERE user_id = $1
         LIMIT 1`,
        [userId]
      );
      return res.status(200).json(
        result.rows[0] || {
          user_id: userId,
          is_online: false,
          last_seen_at: null,
        }
      );
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.get("/groups", async (req, res) => {
    try {
      await ensureSchema();
      const memberId = normalizeText(req.query.member_id);
      assertRequired(memberId, "member_id");
      const result = await pool.query(
        `SELECT c.id, c.title AS name, c.description, c.avatar_url, c.created_by, c.created_at, c.updated_at,
                COALESCE(last_message.content, '') AS last_message,
                last_message.created_at AS last_message_at,
                COUNT(members.id)::int AS member_count
         FROM public.realtime_conversations c
         JOIN public.realtime_conversation_members viewer
           ON viewer.conversation_id = c.id AND viewer.user_id = $1
         LEFT JOIN public.realtime_conversation_members members
           ON members.conversation_id = c.id
         LEFT JOIN LATERAL (
           SELECT rm.content, rm.created_at
           FROM public.realtime_messages rm
           WHERE rm.conversation_id = c.id
           ORDER BY rm.created_at DESC
           LIMIT 1
         ) last_message ON true
         WHERE c.type = 'group'
         GROUP BY c.id, last_message.content, last_message.created_at
         ORDER BY COALESCE(last_message.created_at, c.created_at) DESC`,
        [memberId]
      );
      return res.status(200).json({ items: result.rows });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/conversations/:conversationId/read", async (req, res) => {
    try {
      await ensureSchema();
      const conversationId = normalizeText(req.params.conversationId);
      const userId = normalizeText(req.body.user_id);
      const messageId = normalizeText(req.body.message_id);
      assertRequired(conversationId, "conversationId");
      assertRequired(userId, "user_id");
      assertRequired(messageId, "message_id");

      await pool.query(
        `UPDATE public.realtime_conversation_members
         SET last_read_message_id = $3
         WHERE conversation_id = $1 AND user_id = $2`,
        [conversationId, userId, messageId]
      );
      await pool.query(
        `UPDATE public.realtime_messages
         SET status = 'seen',
             delivered_at = COALESCE(delivered_at, CURRENT_TIMESTAMP),
             seen_at = CURRENT_TIMESTAMP
         WHERE conversation_id = $1
           AND id <= $2::uuid
           AND sender_id <> $3`,
        [conversationId, messageId, userId]
      );
      return res.status(200).json({ success: true });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/groups", async (req, res) => {
    const client = await pool.connect();
    try {
      await ensureSchema();
      const createdBy = normalizeText(req.body.created_by);
      const name = normalizeText(req.body.name);
      const description = normalizeText(req.body.description);
      const avatarUrl = normalizeText(req.body.avatar_url) || null;
      const participantIds = Array.isArray(req.body.participant_ids)
        ? req.body.participant_ids.map(normalizeText).filter(Boolean)
        : [];
      assertRequired(createdBy, "created_by");
      assertRequired(name, "name");
      await client.query("BEGIN");
      const groupResult = await client.query(
        `INSERT INTO public.realtime_conversations (
           type, title, description, avatar_url, created_by
         ) VALUES ('group', $1, $2, $3, $4)
         RETURNING id, type, title, description, avatar_url, created_by, created_at, updated_at`,
        [name, description || null, avatarUrl, createdBy]
      );
      const group = groupResult.rows[0];
      const members = Array.from(new Set([createdBy, ...participantIds]));
      for (const memberId of members) {
        await client.query(
          `INSERT INTO public.realtime_conversation_members (
             conversation_id, user_id, role
           ) VALUES ($1, $2, $3)
           ON CONFLICT (conversation_id, user_id) DO NOTHING`,
          [group.id, memberId, memberId === createdBy ? "admin" : "member"]
        );
      }
      await client.query("COMMIT");
      return res.status(201).json(group);
    } catch (e) {
      await client.query("ROLLBACK");
      return res.status(e.statusCode || 500).json({ error: e.message });
    } finally {
      client.release();
    }
  });

  router.get("/groups/:groupId", async (req, res) => {
    try {
      await ensureSchema();
      const groupId = normalizeText(req.params.groupId);
      assertRequired(groupId, "groupId");
      const groupResult = await pool.query(
        `SELECT id, title AS name, description, avatar_url, created_by, created_at, updated_at
         FROM public.realtime_conversations
         WHERE id = $1 AND type = 'group'
         LIMIT 1`,
        [groupId]
      );
      if (!groupResult.rows.length) {
        return res.status(404).json({ error: "Group not found" });
      }
      const membersResult = await pool.query(
        `SELECT m.user_id,
                m.role,
                m.joined_at,
                COALESCE(s.full_name, t.full_name, p.full_name, a.full_name, u.username, m.user_id) AS display_name,
                COALESCE(s.profile_picture_url, t.profile_picture_url, p.profile_picture_url, a.profile_picture_url, NULL) AS avatar_url
         FROM public.realtime_conversation_members m
         LEFT JOIN users u ON LOWER(TRIM(u.email)) = LOWER(TRIM(m.user_id))
         LEFT JOIN students s ON s.user_id = u.id
         LEFT JOIN teachers t ON t.user_id = u.id
         LEFT JOIN parents p ON p.user_id = u.id
         LEFT JOIN admins a ON a.user_id = u.id
         WHERE m.conversation_id = $1
         ORDER BY m.role DESC, m.joined_at ASC`,
        [groupId]
      );
      return res.status(200).json({
        ...groupResult.rows[0],
        members: membersResult.rows,
      });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.patch("/groups/:groupId", async (req, res) => {
    try {
      await ensureSchema();
      const groupId = normalizeText(req.params.groupId);
      const actorId = normalizeText(req.body.actor_id);
      const name = normalizeText(req.body.name);
      const description = normalizeText(req.body.description);
      const avatarUrl = normalizeText(req.body.avatar_url);
      assertRequired(groupId, "groupId");
      assertRequired(actorId, "actor_id");
      await requireAdmin(groupId, actorId);
      const result = await pool.query(
        `UPDATE public.realtime_conversations
         SET title = COALESCE(NULLIF($2, ''), title),
             description = COALESCE($3, description),
             avatar_url = COALESCE($4, avatar_url),
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $1 AND type = 'group'
         RETURNING id, title AS name, description, avatar_url, created_by, created_at, updated_at`,
        [groupId, name, description || null, avatarUrl || null]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Group not found" });
      }
      return res.status(200).json(result.rows[0]);
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.post("/groups/:groupId/members", async (req, res) => {
    try {
      await ensureSchema();
      const groupId = normalizeText(req.params.groupId);
      const actorId = normalizeText(req.body.actor_id);
      const userId = normalizeText(req.body.user_id);
      const role = normalizeText(req.body.role).toLowerCase() || "member";
      assertRequired(groupId, "groupId");
      assertRequired(actorId, "actor_id");
      assertRequired(userId, "user_id");
      await requireAdmin(groupId, actorId);
      if (!["admin", "member"].includes(role)) {
        return res.status(400).json({ error: "Role must be admin or member" });
      }
      const result = await pool.query(
        `INSERT INTO public.realtime_conversation_members (
           conversation_id, user_id, role
         ) VALUES ($1, $2, $3)
         ON CONFLICT (conversation_id, user_id)
         DO UPDATE SET role = EXCLUDED.role
         RETURNING user_id, role, joined_at`,
        [groupId, userId, role]
      );
      return res.status(200).json(result.rows[0]);
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.delete("/groups/:groupId/members/:memberId", async (req, res) => {
    try {
      await ensureSchema();
      const groupId = normalizeText(req.params.groupId);
      const memberId = normalizeText(req.params.memberId);
      const actorId = normalizeText(req.query.actor_id);
      assertRequired(groupId, "groupId");
      assertRequired(memberId, "memberId");
      assertRequired(actorId, "actor_id");
      await requireAdmin(groupId, actorId);
      if (actorId === memberId) {
        return res.status(400).json({ error: "Use role transfer before removing yourself" });
      }
      await pool.query(
        `DELETE FROM public.realtime_conversation_members
         WHERE conversation_id = $1 AND user_id = $2`,
        [groupId, memberId]
      );
      return res.status(200).json({ success: true });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.get("/groups/:groupId/messages", async (req, res) => {
    return fetchMessages(req, res, req.params.groupId);
  });

  router.post("/groups/:groupId/messages", async (req, res) => {
    return createMessage(req, res, req.params.groupId);
  });

  router.post("/messages/:messageId/reaction", async (req, res) => {
    try {
      await ensureSchema();
      const messageId = normalizeText(req.params.messageId);
      const actorId = normalizeText(req.body.actor_id);
      const emoji = normalizeText(req.body.emoji);
      assertRequired(messageId, "messageId");
      assertRequired(actorId, "actor_id");
      assertRequired(emoji, "emoji");

      const existing = await pool.query(
        `SELECT m.id, m.reactions
         FROM public.realtime_messages m
         WHERE m.id = $1
           AND EXISTS (
             SELECT 1
             FROM public.realtime_conversation_members cm
             WHERE cm.conversation_id = m.conversation_id
               AND cm.user_id = $2
           )
         LIMIT 1`,
        [messageId, actorId]
      );
      if (!existing.rows.length) {
        return res.status(404).json({ error: "Message not found or access denied" });
      }

      const reactions = existing.rows[0].reactions && typeof existing.rows[0].reactions === "object"
        ? { ...existing.rows[0].reactions }
        : {};

      if (reactions[actorId] === emoji) {
        delete reactions[actorId];
      } else {
        reactions[actorId] = emoji;
      }

      const updated = await pool.query(
        `UPDATE public.realtime_messages
         SET reactions = $2::jsonb
         WHERE id = $1
         RETURNING id, conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, reactions, is_pinned, pinned_at, created_at, status, delivered_at, seen_at`,
        [messageId, JSON.stringify(reactions)]
      );

      return res.status(200).json(updated.rows[0]);
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.delete("/messages/:messageId", async (req, res) => {
    try {
      await ensureSchema();
      const messageId = normalizeText(req.params.messageId);
      const actorId = normalizeText(req.body.actor_id || req.query.actor_id);
      assertRequired(messageId, "messageId");
      assertRequired(actorId, "actor_id");

      const result = await pool.query(
        `DELETE FROM public.realtime_messages m
         WHERE m.id = $1
           AND EXISTS (
             SELECT 1
             FROM public.realtime_conversation_members cm
             WHERE cm.conversation_id = m.conversation_id
               AND cm.user_id = $2
               AND (
                 m.sender_id = $2 OR
                 cm.role = 'admin'
               )
           )
         RETURNING id`,
        [messageId, actorId]
      );

      if (!result.rows.length) {
        return res.status(404).json({ error: "Message not found or delete not allowed" });
      }

      return res.status(200).json({ success: true, id: messageId });
    } catch (e) {
      return res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  router.patch("/messages/:messageId/pin", async (req, res) => {
    const client = await pool.connect();
    try {
      await ensureSchema();
      const messageId = normalizeText(req.params.messageId);
      const actorId = normalizeText(req.body.actor_id);
      const isPinned = req.body.is_pinned === true;
      assertRequired(messageId, "messageId");
      assertRequired(actorId, "actor_id");

      const messageResult = await client.query(
        `SELECT m.id, m.conversation_id, m.sender_id, cm.role
         FROM public.realtime_messages m
         JOIN public.realtime_conversation_members cm
           ON cm.conversation_id = m.conversation_id
         WHERE m.id = $1
           AND cm.user_id = $2
         LIMIT 1`,
        [messageId, actorId]
      );
      if (!messageResult.rows.length) {
        return res.status(404).json({ error: "Message not found or access denied" });
      }

      const target = messageResult.rows[0];
      if (target.sender_id !== actorId && target.role !== "admin") {
        return res.status(403).json({ error: "Only the sender or a group admin can pin this message" });
      }

      await client.query("BEGIN");
      if (isPinned) {
        await client.query(
          `UPDATE public.realtime_messages
           SET is_pinned = false,
               pinned_at = NULL
           WHERE conversation_id = $1`,
          [target.conversation_id]
        );
      }

      const updated = await client.query(
        `UPDATE public.realtime_messages
         SET is_pinned = $2,
             pinned_at = CASE WHEN $2 THEN CURRENT_TIMESTAMP ELSE NULL END
         WHERE id = $1
         RETURNING id, conversation_id, sender_id, content, message_type, media_url, reply_to_message_id, reactions, is_pinned, pinned_at, created_at, status, delivered_at, seen_at`,
        [messageId, isPinned]
      );
      await client.query("COMMIT");
      return res.status(200).json(updated.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");
      return res.status(e.statusCode || 500).json({ error: e.message });
    } finally {
      client.release();
    }
  });

  return router;
}

module.exports = {
  createRealtimeChatModule,
};
