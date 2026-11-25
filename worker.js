const registerHandler=(()=>{const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return `pbkdf2_sha256$100000$${toBase64(salt)}$${toBase64(new Uint8Array(bits))}`;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64(new Uint8Array(digest));
}

async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) return json({ success: false, error: "Database is not configured." }, 500);

    const input = await request.json();
    const fullName = String(input.full_name || "").trim();
    const phone = String(input.phone_number || "").trim();
    const email = String(input.email || "").trim().toLowerCase();
    const password = String(input.password || "");

    if (fullName.length < 2 || fullName.length > 100) {
      return json({ success: false, error: "Enter your full name (2–100 characters)." }, 400);
    }
    if (!/^\+?[0-9]{9,15}$/.test(phone)) {
      return json({ success: false, error: "Enter a valid mobile number, using digits and an optional +." }, 400);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return json({ success: false, error: "Enter a valid email address." }, 400);
    }
    if (password.length < 10 || password.length > 128) {
      return json({ success: false, error: "Password must be at least 10 characters." }, 400);
    }

    const userId = crypto.randomUUID();
    const sessionToken = toBase64(crypto.getRandomValues(new Uint8Array(32)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const tokenHash = await sha256(sessionToken);
    const passwordHash = await hashPassword(password);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users
          (id, full_name, email, phone_number, password_hash, account_status,
           locked_bonus_ugx, available_balance_ugx)
         VALUES (?, ?, ?, ?, ?, 'active', 5000, 0)`
      ).bind(userId, fullName, email, phone, passwordHash),
      env.DB.prepare(
        `INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES (?, ?, ?)`
      ).bind(tokenHash, userId, expiresAt),
      env.DB.prepare(
        `INSERT INTO wallet_transactions
          (id, user_id, transaction_type, amount_ugx, balance_bucket,
           transaction_status, reference, notes)
         VALUES (?, ?, 'welcome_bonus_locked', 5000, 'locked', 'pending', ?, ?)`
      ).bind(crypto.randomUUID(), userId, `WELCOME-${userId}`, "Promotional welcome bonus; locked pending eligibility review")
    ]);

    return json(
      {
        success: true,
        userId,
        message: "Account created. Your 5,000 UGX welcome bonus is locked until eligibility is verified.",
      },
      201,
      {
        "Set-Cookie": `trainai_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
        "Cache-Control": "no-store",
      }
    );
  } catch (error) {
    const message = String(error?.message || "");
    if (/UNIQUE constraint failed/i.test(message)) {
      return json({ success: false, error: "That email address or phone number is already registered." }, 409);
    }
    return json({ success: false, error: "Registration could not be completed. Please try again." }, 500);
  }
}

return onRequestPost;})();
const userHandler=(()=>{function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function readCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  let binary = "";
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({ success: false, error: "Database is not configured." }, 500);
    }

    const token = readCookie(request, "trainai_session");
    if (!token) {
      return json({ success: false, error: "Please sign in again." }, 401);
    }

    const tokenHash = await hashToken(token);
    const session = await env.DB.prepare(
      "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).first();

    if (!session || !session.expires_at || Date.parse(session.expires_at) <= Date.now()) {
      return json({ success: false, error: "Your session has expired. Please sign in again." }, 401);
    }

    const user = await env.DB.prepare(
      `SELECT id, full_name, phone_number, locked_bonus_ugx,
              available_balance_ugx, surveys_completed
       FROM users
       WHERE id = ? AND account_status = 'active'`
    ).bind(session.user_id).first();

    if (!user) {
      return json({ success: false, error: "Account not found or inactive." }, 404);
    }

    const [surveyResult, responseResult, transactionResult] = await Promise.all([
      env.DB.prepare(
        `SELECT id, title, description, reward_ugx, category,
                questions_json, is_onboarding
         FROM surveys
         WHERE is_active = 1
         ORDER BY is_onboarding DESC, created_at ASC`
      ).all(),
      env.DB.prepare(
        "SELECT survey_id FROM survey_responses WHERE user_id = ?"
      ).bind(user.id).all(),
      env.DB.prepare(
        `SELECT transaction_type, amount_ugx, transaction_status,
                balance_bucket, notes, created_at
         FROM wallet_transactions
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 50`
      ).bind(user.id).all(),
    ]);

    const surveys = surveyResult.results || [];
    const completedIds = (responseResult.results || []).map(row => row.survey_id);
    const ledger = (transactionResult.results || []).map(row => ({
      type: row.transaction_type,
      status: row.transaction_status,
      amount_ugx: row.amount_ugx,
      balance_bucket: row.balance_bucket,
      details: row.notes,
      created_at: row.created_at,
    }));

    return json({
      success: true,
      user,
      surveys,
      completedIds,
      ledger,
    });
  } catch (error) {
    return json(
      { success: false, error: "Unable to load your dashboard right now." },
      500
    );
  }
}

return onRequestGet;})();
const submitHandler=(()=>{function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return null;
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) return json({ success: false, error: "Database is not configured." }, 500);

    const token = readCookie(request, "trainai_session");
    if (!token) return json({ success: false, error: "Please sign in again." }, 401);

    const tokenHash = await hashToken(token);
    const session = await env.DB.prepare(
      "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).first();

    if (!session || Date.parse(session.expires_at) <= Date.now()) {
      return json({ success: false, error: "Your session has expired. Please sign in again." }, 401);
    }

    const user = await env.DB.prepare(
      "SELECT id, account_status FROM users WHERE id = ?"
    ).bind(session.user_id).first();

    if (!user || user.account_status !== "active") {
      return json({ success: false, error: "This account cannot submit surveys." }, 403);
    }

    const body = await request.json();
    const surveyId = String(body.surveyId || "");
    const answers = body.answers;

    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(surveyId)) {
      return json({ success: false, error: "Invalid survey." }, 400);
    }
    if (!Array.isArray(answers) || answers.length < 1 || answers.length > 50) {
      return json({ success: false, error: "Please answer all survey questions." }, 400);
    }

    const survey = await env.DB.prepare(
      "SELECT id, questions_json, is_active FROM surveys WHERE id = ?"
    ).bind(surveyId).first();

    if (!survey || survey.is_active !== 1) {
      return json({ success: false, error: "This survey is not available." }, 404);
    }

    let questions;
    try {
      questions = JSON.parse(survey.questions_json || "[]");
    } catch {
      return json({ success: false, error: "This survey is not configured correctly." }, 500);
    }

    if (!Array.isArray(questions) || questions.length !== answers.length || questions.length === 0) {
      return json({ success: false, error: "Your answers do not match the survey questions." }, 400);
    }

    const normalized = [];
    for (let index = 0; index < questions.length; index++) {
      const answer = answers[index];
      if (!answer || answer.question !== index || !["A", "B"].includes(answer.choice)) {
        return json({ success: false, error: "Please provide one valid answer to every question." }, 400);
      }
      normalized.push({ question: index, choice: answer.choice });
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM survey_responses WHERE user_id = ? AND survey_id = ?"
    ).bind(user.id, surveyId).first();
    if (existing) {
      return json({ success: false, error: "You have already submitted this survey." }, 409);
    }

    await env.DB.prepare(
      `INSERT INTO survey_responses
        (id, user_id, survey_id, answers_json, review_status)
       VALUES (?, ?, ?, ?, 'pending')`
    ).bind(crypto.randomUUID(), user.id, surveyId, JSON.stringify(normalized)).run();

    return json({
      success: true,
      status: "pending",
      message: "Your answers have been received and are awaiting review. Any survey reward will only be credited if your submission is approved.",
    }, 201);
  } catch (error) {
    const message = String(error?.message || "");
    if (/UNIQUE constraint failed/i.test(message)) {
      return json({ success: false, error: "You have already submitted this survey." }, 409);
    }
    return json({ success: false, error: "We could not submit your answers. Please try again." }, 500);
  }
}

return onRequestPost;})();
const withdrawHandler=(()=>{function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return null;
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function normalizeUgandanPhone(value) {
  const digits = String(value || "").replace(/[\s()-]/g, "");
  if (!/^(?:\+?256|0)?[37]\d{8}$/.test(digits)) return null;

  const national = digits.replace(/^\+?256/, "").replace(/^0/, "");
  return "+256" + national;
}

async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return json({ success: false, error: "Database is not configured." }, 500);
    }

    // Reject cross-origin browser submissions. SameSite cookies provide an
    // additional layer of CSRF protection.
    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json({ success: false, error: "Invalid request origin." }, 403);
    }

    // The signed-in session, not a client-supplied userId, identifies the user.
    const token = readCookie(request, "trainai_session");
    if (!token) {
      return json({ success: false, error: "Please sign in again." }, 401);
    }

    const tokenHash = await hashToken(token);
    const session = await env.DB.prepare(
      "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).first();

    if (!session || !session.expires_at || Date.parse(session.expires_at) <= Date.now()) {
      return json({ success: false, error: "Your session has expired. Please sign in again." }, 401);
    }

    const user = await env.DB.prepare(
      "SELECT id, available_balance_ugx FROM users WHERE id = ? AND account_status = 'active'"
    ).bind(session.user_id).first();

    if (!user) {
      return json({ success: false, error: "Account not found or inactive." }, 403);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, error: "Invalid request body." }, 400);
    }

    const network = String(body.network || "").trim().toUpperCase();
    const phone = normalizeUgandanPhone(body.phone);
    const amount = body.amount;

    if (!["MTN", "AIRTEL"].includes(network)) {
      return json({ success: false, error: "Choose MTN or Airtel Money." }, 400);
    }
    if (!phone) {
      return json({ success: false, error: "Enter a valid Ugandan mobile number." }, 400);
    }
    if (!Number.isSafeInteger(amount) || amount < 10000) {
      return json({ success: false, error: "Minimum withdrawal request is 10,000 UGX." }, 400);
    }
    if (amount > user.available_balance_ugx) {
      return json({ success: false, error: "Insufficient available balance." }, 400);
    }

    const withdrawalId = crypto.randomUUID();
    const transactionId = crypto.randomUUID();
    const reference = "WITHDRAWAL-" + withdrawalId;

    // D1 batch runs transactionally. The request and history row are only
    // inserted if the conditional balance deduction succeeds.
    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE users
         SET available_balance_ugx = available_balance_ugx - ?,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?
           AND account_status = 'active'
           AND available_balance_ugx >= ?`
      ).bind(amount, user.id, amount),

      env.DB.prepare(
        `INSERT INTO withdrawal_requests
          (id, user_id, amount_ugx, mobile_money_network,
           mobile_money_number, request_status)
         SELECT ?, ?, ?, ?, ?, 'pending'
         WHERE EXISTS (
           SELECT 1 FROM users
           WHERE id = ? AND available_balance_ugx >= 0
         )
           AND changes() = 1`
      ).bind(withdrawalId, user.id, amount, network, phone, user.id),

      env.DB.prepare(
        `INSERT INTO wallet_transactions
          (id, user_id, transaction_type, amount_ugx, balance_bucket,
           transaction_status, reference, notes)
         SELECT ?, ?, 'withdrawal', ?, 'available', 'pending', ?, ?
         WHERE EXISTS (
           SELECT 1 FROM withdrawal_requests
           WHERE id = ? AND user_id = ? AND request_status = 'pending'
         )`
      ).bind(
        transactionId,
        user.id,
        amount,
        reference,
        network + " withdrawal to " + phone + " (awaiting admin review)",
        withdrawalId,
        user.id
      ),
    ]);

    if (results?.[0]?.meta?.changes !== 1 || results?.[1]?.meta?.changes !== 1) {
      return json({ success: false, error: "Insufficient balance or withdrawal could not be created. Refresh your wallet and try again." }, 409);
    }

    return json({
      success: true,
      status: "pending",
      withdrawalId,
      message: "Your withdrawal request has been received and is awaiting review. This is not a payment confirmation.",
    }, 201);
  } catch (error) {
    return json(
      { success: false, error: "We could not submit your withdrawal. Please try again." },
      500
    );
  }
}

return onRequestPost;})();
const adminReviewHandler=(()=>{function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function authorized(request, env) {
  const expected = env.ADMIN_API_KEY;
  const supplied = request.headers.get("Authorization") || "";
  if (!expected || !supplied.startsWith("Bearer ")) return false;
  const actual = supplied.slice(7);
  if (actual.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) mismatch |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return mismatch === 0;
}

async function onRequest({ request, env }) {
  if (!env.DB) return json({ success: false, error: "Database is not configured." }, 500);
  if (!authorized(request, env)) return json({ success: false, error: "Admin key is missing or incorrect." }, 401);

  if (request.method === "GET") {
    try {
      const { results } = await env.DB.prepare(
        `SELECT r.id, r.user_id, r.survey_id, r.answers_json, r.submitted_at,
                s.title AS survey_title, s.reward_ugx, s.questions_json,
                u.full_name, u.email
         FROM survey_responses r
         JOIN surveys s ON s.id = r.survey_id
         JOIN users u ON u.id = r.user_id
         WHERE r.review_status = 'pending'
         ORDER BY r.submitted_at ASC
         LIMIT 100`
      ).all();
      return json({ success: true, submissions: results || [] });
    } catch {
      return json({ success: false, error: "Could not load pending submissions." }, 500);
    }
  }

  if (request.method !== "POST") {
    return json({ success: false, error: "Method not allowed." }, 405);
  }

  try {
    const body = await request.json();
    const responseId = String(body.responseId || "");
    const decision = String(body.decision || "");
    if (!/^[0-9a-f-]{36}$/i.test(responseId) || !["approve", "reject"].includes(decision)) {
      return json({ success: false, error: "Choose a valid submission and decision." }, 400);
    }

    const reviewedAt = new Date().toISOString() + "-" + crypto.randomUUID();
    const pending = await env.DB.prepare(
      `SELECT r.id, r.user_id, r.survey_id, r.review_status, s.reward_ugx, s.title
       FROM survey_responses r JOIN surveys s ON s.id = r.survey_id
       WHERE r.id = ?`
    ).bind(responseId).first();

    if (!pending) return json({ success: false, error: "Submission not found." }, 404);
    if (pending.review_status !== "pending") {
      return json({ success: false, error: "This submission has already been reviewed." }, 409);
    }

    if (decision === "reject") {
      const result = await env.DB.prepare(
        "UPDATE survey_responses SET review_status = 'rejected', reviewed_at = ? WHERE id = ? AND review_status = 'pending'"
      ).bind(reviewedAt, responseId).run();
      if (!result.meta || result.meta.changes !== 1) {
        return json({ success: false, error: "Another administrator has already reviewed this submission." }, 409);
      }
      return json({ success: true, decision: "rejected", message: "Submission rejected. No reward was credited." });
    }

    // One atomic D1 batch: claim this pending review, then credit only that unique review claim.
    const reference = "SURVEY-APPROVED-" + responseId;
    const batch = await env.DB.batch([
      env.DB.prepare(
        "UPDATE survey_responses SET review_status = 'approved', reviewed_at = ? WHERE id = ? AND review_status = 'pending'"
      ).bind(reviewedAt, responseId),
      env.DB.prepare(
        `UPDATE users
         SET available_balance_ugx = available_balance_ugx + (
           SELECT reward_ugx FROM surveys WHERE id = ?
         ),
         surveys_completed = surveys_completed + 1,
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?
           AND EXISTS (
             SELECT 1 FROM survey_responses
             WHERE id = ? AND review_status = 'approved' AND reviewed_at = ?
           )`
      ).bind(pending.survey_id, pending.user_id, responseId, reviewedAt),
      env.DB.prepare(
        `INSERT INTO wallet_transactions
          (id, user_id, transaction_type, amount_ugx, balance_bucket,
           transaction_status, reference, notes)
         SELECT ?, ?, 'survey_reward', reward_ugx, 'available',
                'completed', ?, ?
         FROM surveys
         WHERE id = ?
           AND EXISTS (
             SELECT 1 FROM survey_responses
             WHERE id = ? AND review_status = 'approved' AND reviewed_at = ?
           )
           AND NOT EXISTS (
             SELECT 1 FROM wallet_transactions WHERE reference = ?
           )`
      ).bind(crypto.randomUUID(), pending.user_id, reference,
        "Approved survey: " + pending.title, pending.survey_id, responseId, reviewedAt, reference),
    ]);

    const claimChanges = batch?.[0]?.meta?.changes;
    if (claimChanges !== 1) {
      return json({ success: false, error: "Another administrator has already reviewed this submission." }, 409);
    }
    return json({
      success: true,
      decision: "approved",
      creditedUGX: pending.reward_ugx,
      message: "Submission approved. The survey reward was added to the user's available balance.",
    });
  } catch (error) {
    return json({ success: false, error: "The review could not be completed. Please try again." }, 500);
  }
}

return onRequest;})();
const adminWithdrawalsHandler=(()=>{function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function authorized(request, env) {
  const expected = env.ADMIN_API_KEY;
  const supplied = request.headers.get("Authorization") || "";
  if (!expected || !supplied.startsWith("Bearer ")) return false;

  const actual = supplied.slice(7);
  if (actual.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return mismatch === 0;
}

async function onRequest({ request, env }) {
  if (!env.DB) return json({ success: false, error: "Database is not configured." }, 500);
  if (!authorized(request, env)) {
    return json({ success: false, error: "Admin key is missing or incorrect." }, 401);
  }

  if (request.method === "GET") {
    try {
      const { results } = await env.DB.prepare(
        `SELECT w.id, w.user_id, w.amount_ugx, w.mobile_money_network,
                w.mobile_money_number, w.request_status, w.created_at,
                u.full_name, u.email
         FROM withdrawal_requests w
         JOIN users u ON u.id = w.user_id
         WHERE w.request_status = 'pending'
         ORDER BY w.created_at ASC
         LIMIT 100`
      ).all();

      return json({ success: true, withdrawals: results || [] });
    } catch {
      return json({ success: false, error: "Could not load pending withdrawals." }, 500);
    }
  }

  if (request.method !== "POST") {
    return json({ success: false, error: "Method not allowed." }, 405);
  }

  try {
    const body = await request.json();
    const withdrawalId = String(body.withdrawalId || "");
    const decision = String(body.decision || "");

    if (!/^[0-9a-f-]{36}$/i.test(withdrawalId) ||
        !["paid", "reject"].includes(decision)) {
      return json({ success: false, error: "Choose a valid withdrawal and decision." }, 400);
    }

    const withdrawal = await env.DB.prepare(
      `SELECT w.id, w.user_id, w.amount_ugx, w.request_status,
              EXISTS (
                SELECT 1 FROM wallet_transactions t
                WHERE t.reference = 'WITHDRAWAL-' || w.id
                  AND t.user_id = w.user_id
                  AND t.transaction_type = 'withdrawal'
                  AND t.transaction_status = 'pending'
              ) AS has_pending_transaction,
              EXISTS (SELECT 1 FROM users u WHERE u.id = w.user_id) AS has_user
       FROM withdrawal_requests w WHERE w.id = ?`
    ).bind(withdrawalId).first();

    if (!withdrawal) return json({ success: false, error: "Withdrawal not found." }, 404);
    if (withdrawal.request_status !== "pending") {
      return json({ success: false, error: "This withdrawal has already been processed." }, 409);
    }
    if (!withdrawal.has_pending_transaction || !withdrawal.has_user) {
      return json({ success: false, error: "This request is missing a matching wallet transaction or user record. Please investigate before processing." }, 409);
    }

    const marker = new Date().toISOString() + "-" + crypto.randomUUID();
    const reference = "WITHDRAWAL-" + withdrawalId;

    if (decision === "paid") {
      // Only use this action after the Mobile Money transfer has actually succeeded.
      const results = await env.DB.batch([
        env.DB.prepare(
          `UPDATE withdrawal_requests
           SET request_status = 'paid', processed_at = ?
           WHERE id = ? AND request_status = 'pending'`
        ).bind(marker, withdrawalId),

        env.DB.prepare(
          `UPDATE wallet_transactions
           SET transaction_status = 'completed',
               notes = COALESCE(notes, '') || ' | Marked paid by admin after manual payment confirmation.'
           WHERE reference = ? AND user_id = ?
             AND transaction_type = 'withdrawal'
             AND transaction_status = 'pending'
             AND EXISTS (
               SELECT 1 FROM withdrawal_requests
               WHERE id = ? AND request_status = 'paid' AND processed_at = ?
             )`
        ).bind(reference, withdrawal.user_id, withdrawalId, marker),
      ]);

      if (results?.[0]?.meta?.changes !== 1) {
        return json({ success: false, error: "Another administrator has already processed this withdrawal." }, 409);
      }
      if (results?.[1]?.meta?.changes !== 1) {
        return json({ success: false, error: "Withdrawal status changed, but its wallet transaction needs investigation. Do not pay again." }, 500);
      }

      return json({
        success: true,
        decision: "paid",
        message: "Withdrawal marked as paid. Confirm that the Mobile Money transfer was successful.",
      });
    }

    // Rejection restores the amount to available balance and records a refund.
    // The unique reference and conditional status change prevent double refunds.
    const refundReference = "WITHDRAWAL-REFUND-" + withdrawalId;
    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE withdrawal_requests
         SET request_status = 'rejected', processed_at = ?,
             admin_note = 'Rejected by administrator; funds refunded to available balance.'
         WHERE id = ? AND request_status = 'pending'`
      ).bind(marker, withdrawalId),

      env.DB.prepare(
        `UPDATE users
         SET available_balance_ugx = available_balance_ugx + ?,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?
           AND EXISTS (
             SELECT 1 FROM withdrawal_requests
             WHERE id = ? AND request_status = 'rejected' AND processed_at = ?
           )`
      ).bind(withdrawal.amount_ugx, withdrawal.user_id, withdrawalId, marker),

      env.DB.prepare(
        `UPDATE wallet_transactions
         SET transaction_status = 'reversed',
             notes = COALESCE(notes, '') || ' | Rejected; amount refunded to available balance.'
         WHERE reference = ? AND user_id = ?
           AND transaction_type = 'withdrawal'
           AND transaction_status = 'pending'
           AND EXISTS (
             SELECT 1 FROM withdrawal_requests
             WHERE id = ? AND request_status = 'rejected' AND processed_at = ?
           )`
      ).bind(reference, withdrawal.user_id, withdrawalId, marker),

      env.DB.prepare(
        `INSERT INTO wallet_transactions
          (id, user_id, transaction_type, amount_ugx, balance_bucket,
           transaction_status, reference, notes)
         SELECT ?, ?, 'adjustment', ?, 'available', 'completed', ?,
                'Refund for rejected withdrawal'
         WHERE EXISTS (
           SELECT 1 FROM withdrawal_requests
           WHERE id = ? AND request_status = 'rejected' AND processed_at = ?
         )
           AND NOT EXISTS (
             SELECT 1 FROM wallet_transactions WHERE reference = ?
           )`
      ).bind(
        crypto.randomUUID(), withdrawal.user_id, withdrawal.amount_ugx,
        refundReference, withdrawalId, marker, refundReference
      ),
    ]);

    if (results?.[0]?.meta?.changes !== 1) {
      return json({ success: false, error: "Another administrator has already processed this withdrawal." }, 409);
    }
    if (results?.[1]?.meta?.changes !== 1 ||
        results?.[2]?.meta?.changes !== 1 ||
        results?.[3]?.meta?.changes !== 1) {
      return json({ success: false, error: "The refund needs investigation. Do not retry or manually adjust the balance." }, 500);
    }

    return json({
      success: true,
      decision: "rejected",
      refundedUGX: withdrawal.amount_ugx,
      message: "Withdrawal rejected. The amount has been returned to the user's available balance.",
    });
  } catch {
    return json({ success: false, error: "The withdrawal could not be processed. Please try again." }, 500);
  }
}

return onRequest;})();
const PAGES={
  "index.html": "<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"description\" content=\"Help evaluate AI answers, check Luganda translations, and take part in AI training surveys with TrainAI Uganda.\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>TrainAI Uganda — Teach AI & Earn UGX</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"bg-slate-950 text-slate-100 font-sans antialiased\">\n  <nav class=\"border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50\">\n    <div class=\"max-w-5xl mx-auto px-6 py-4 flex justify-between items-center\">\n      <a href=\"/\" class=\"text-xl font-bold tracking-tight text-sky-400\">TrainAI<span class=\"text-slate-100\">.ug</span></a>\n      <div class=\"flex items-center gap-4\">\n        <a href=\"/dashboard.html\" class=\"text-sm text-slate-300 hover:text-white\">Dashboard</a>\n        <a href=\"/register.html\" class=\"bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition\">Get Started</a>\n      </div>\n    </div>\n  </nav>\n\n  <main class=\"max-w-4xl mx-auto px-6 py-20 text-center\">\n    <span class=\"inline-block bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-semibold px-3 py-1 rounded-full mb-6\">\n      5,000 UGX WELCOME BONUS — LOCKED UNTIL ELIGIBILITY IS MET\n    </span>\n    <h1 class=\"text-4xl md:text-6xl font-extrabold tracking-tight mb-6 leading-tight\">\n      Train Smarter AI Models. <br><span class=\"text-sky-400\">Earn Rewards in UGX.</span>\n    </h1>\n    <p class=\"text-slate-400 text-lg max-w-2xl mx-auto mb-10\">\n      Help improve artificial intelligence by rating AI responses, checking local-language translations, and completing feedback surveys from your phone or computer.\n    </p>\n    <div class=\"flex flex-col sm:flex-row justify-center gap-4\">\n      <a href=\"/register.html\" class=\"bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-8 py-4 rounded-xl text-lg shadow-lg shadow-sky-500/20 transition\">\n        Create a Free Account\n      </a>\n      <a href=\"#how-it-works\" class=\"bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-8 py-4 rounded-xl text-lg transition\">\n        How It Works\n      </a>\n    </div>\n\n    <div id=\"how-it-works\" class=\"grid md:grid-cols-3 gap-6 mt-24 text-left\">\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 01</div>\n        <h2 class=\"text-lg font-bold mb-2\">Create a Free Account</h2>\n        <p class=\"text-slate-400 text-sm\">Register with your details. A 5,000 UGX promotional bonus is recorded as locked and is not immediately withdrawable.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 02</div>\n        <h2 class=\"text-lg font-bold mb-2\">Complete AI Surveys</h2>\n        <p class=\"text-slate-400 text-sm\">Compare AI answers, assess factual accuracy, and review translations. Advertised task rewards are subject to valid submission and review.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 03</div>\n        <h2 class=\"text-lg font-bold mb-2\">Request a Withdrawal</h2>\n        <p class=\"text-slate-400 text-sm\">Eligible available balances may be requested through MTN MoMo or Airtel Money once payment processing is configured and funded.</p>\n      </div>\n    </div>\n\n    <p class=\"text-slate-500 text-xs leading-relaxed max-w-2xl mx-auto mt-10\">\n      Rewards are promotional or task-based and are not guaranteed income. The welcome bonus is locked until the published eligibility conditions are met. Survey submissions may be reviewed before rewards become available. Withdrawals are not available until the payment system is operational and funds are available.\n    </p>\n  </main>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "register.html": "<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Register — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center px-4 py-10\">\n  <main class=\"max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-xl\">\n    <div class=\"text-center mb-6\">\n      <span class=\"bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-bold px-3 py-1 rounded-full\">5,000 UGX LOCKED WELCOME BONUS</span>\n      <h1 class=\"text-2xl font-bold mt-4\">Create Your Trainer Account</h1>\n      <p class=\"text-slate-400 text-sm mt-2\">Register to get started with AI training surveys.</p>\n    </div>\n\n    <form id=\"registerForm\" class=\"space-y-4\">\n      <div>\n        <label for=\"fullName\" class=\"block text-xs font-medium text-slate-400 mb-1\">Full Name</label>\n        <input type=\"text\" id=\"fullName\" name=\"full_name\" required autocomplete=\"name\" maxlength=\"120\" placeholder=\"e.g. Kato Mukasa\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"phone\" class=\"block text-xs font-medium text-slate-400 mb-1\">Mobile Money Number (MTN / Airtel)</label>\n        <input type=\"tel\" id=\"phone\" name=\"phone_number\" required autocomplete=\"tel\" inputmode=\"tel\" maxlength=\"20\" placeholder=\"0770000000\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"email\" class=\"block text-xs font-medium text-slate-400 mb-1\">Email Address</label>\n        <input type=\"email\" id=\"email\" name=\"email\" required autocomplete=\"email\" maxlength=\"254\" placeholder=\"you@example.com\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"password\" class=\"block text-xs font-medium text-slate-400 mb-1\">Password</label>\n        <input type=\"password\" id=\"password\" name=\"password\" required autocomplete=\"new-password\" minlength=\"10\" maxlength=\"128\" placeholder=\"At least 10 characters\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n        <p class=\"text-slate-500 text-xs mt-1\">Use at least 10 characters. Never reuse your email password.</p>\n      </div>\n\n      <p id=\"errorMsg\" role=\"alert\" aria-live=\"polite\" class=\"text-rose-400 text-xs hidden\"></p>\n      <p id=\"successMsg\" role=\"status\" aria-live=\"polite\" class=\"text-emerald-400 text-xs hidden\"></p>\n\n      <button type=\"submit\" id=\"submitBtn\"\n        class=\"w-full bg-sky-500 hover:bg-sky-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-bold py-3 rounded-lg transition mt-2\">\n        Register & Start Survey →\n      </button>\n    </form>\n\n    <p class=\"text-slate-500 text-xs leading-relaxed mt-5\">\n      The welcome bonus is promotional and locked until the published eligibility conditions are met. It is not immediately withdrawable. Task rewards are subject to valid submission and review.\n    </p>\n    <p class=\"text-center text-sm text-slate-400 mt-5\">Already registered? <a href=\"/dashboard.html\" class=\"text-sky-400 hover:text-sky-300\">Go to dashboard</a></p>\n  </main>\n\n  <script>\n    const form = document.getElementById(\"registerForm\");\n    const button = document.getElementById(\"submitBtn\");\n    const errorMessage = document.getElementById(\"errorMsg\");\n    const successMessage = document.getElementById(\"successMsg\");\n\n    form.addEventListener(\"submit\", async (event) => {\n      event.preventDefault();\n      errorMessage.classList.add(\"hidden\");\n      successMessage.classList.add(\"hidden\");\n\n      if (!form.reportValidity()) return;\n\n      button.disabled = true;\n      button.textContent = \"Creating your account...\";\n\n      try {\n        const response = await fetch(\"/api/register\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({\n            full_name: document.getElementById(\"fullName\").value.trim(),\n            phone_number: document.getElementById(\"phone\").value.trim(),\n            email: document.getElementById(\"email\").value.trim(),\n            password: document.getElementById(\"password\").value\n          })\n        });\n\n        const data = await response.json().catch(() => ({}));\n        if (!response.ok || !data.success || !data.userId) {\n          throw new Error(data.error || \"We couldn't create your account. Please try again.\");\n        }\n\n        localStorage.setItem(\"trainai_user_id\", data.userId);\n        successMessage.textContent = \"Account created. Opening your first survey...\";\n        successMessage.classList.remove(\"hidden\");\n        window.location.href = \"/survey.html?id=onboarding\";\n      } catch (error) {\n        errorMessage.textContent = error.message || \"Something went wrong. Please try again.\";\n        errorMessage.classList.remove(\"hidden\");\n        button.disabled = false;\n        button.textContent = \"Register & Start Survey →\";\n      }\n    });\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "dashboard.html": "<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Dashboard — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"max-w-5xl mx-auto px-6 py-4 flex justify-between items-center gap-4\">\n      <a href=\"/dashboard.html\" class=\"text-xl font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <div class=\"flex items-center gap-4\">\n        <a href=\"/wallet.html\" class=\"bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg text-sm font-medium\">Wallet</a>\n        <button type=\"button\" id=\"logoutBtn\" class=\"text-xs text-slate-400 hover:text-white\">Logout</button>\n      </div>\n    </div>\n  </nav>\n\n  <main class=\"max-w-5xl mx-auto px-6 py-10\">\n    <div class=\"mb-8\">\n      <h1 class=\"text-2xl font-bold\" id=\"welcomeText\">Welcome, Trainer</h1>\n      <p class=\"text-slate-400 text-sm mt-1\">Complete available AI surveys. Rewards are credited after valid submissions are reviewed.</p>\n    </div>\n\n    <section aria-label=\"Account summary\" class=\"grid md:grid-cols-3 gap-6 mb-10\">\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Available Balance</div>\n        <div class=\"text-3xl font-extrabold text-emerald-400 mt-2\" id=\"availBalance\">— UGX</div>\n        <a href=\"/wallet.html\" class=\"inline-block text-xs text-sky-400 mt-3 hover:underline\">Wallet and withdrawals →</a>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Locked Welcome Bonus</div>\n        <div class=\"text-3xl font-extrabold text-amber-400 mt-2\" id=\"lockedBalance\">— UGX</div>\n        <p class=\"text-xs text-slate-400 mt-3\" id=\"unlockHint\">Locked until eligibility requirements are met.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Surveys Completed</div>\n        <div class=\"text-3xl font-extrabold text-sky-400 mt-2\" id=\"surveyCount\">—</div>\n        <div class=\"w-full bg-slate-800 h-2 rounded-full mt-3 overflow-hidden\">\n          <div id=\"progressBar\" class=\"bg-sky-400 h-full transition-all\" style=\"width:0%\"></div>\n        </div>\n      </div>\n    </section>\n\n    <section>\n      <h2 class=\"text-lg font-bold mb-4\">Available AI Training Surveys</h2>\n      <div id=\"surveyList\" class=\"grid md:grid-cols-2 gap-4\" aria-live=\"polite\">\n        <p class=\"text-slate-400 text-sm\">Loading surveys...</p>\n      </div>\n      <p id=\"pageError\" role=\"alert\" class=\"text-rose-400 text-sm mt-4 hidden\"></p>\n    </section>\n  </main>\n\n  <script>\n    const userId = localStorage.getItem(\"trainai_user_id\");\n    const surveyList = document.getElementById(\"surveyList\");\n    const pageError = document.getElementById(\"pageError\");\n\n    function logout() {\n      localStorage.removeItem(\"trainai_user_id\");\n      window.location.href = \"/index.html\";\n    }\n\n    document.getElementById(\"logoutBtn\").addEventListener(\"click\", logout);\n\n    function formatUGX(value) {\n      const amount = Number(value);\n      return (Number.isFinite(amount) ? amount : 0).toLocaleString(\"en-UG\") + \" UGX\";\n    }\n\n    function escapeHTML(value) {\n      return String(value ?? \"\").replace(/[&<>\"']/g, (char) => ({\n        \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\"\n      })[char]);\n    }\n\n    function showError(message) {\n      pageError.textContent = message;\n      pageError.classList.remove(\"hidden\");\n    }\n\n    async function loadDashboard() {\n      if (!userId) {\n        window.location.href = \"/register.html\";\n        return;\n      }\n\n      try {\n        const res = await fetch(\"/api/user?userId=\" + encodeURIComponent(userId), {\n          headers: { \"Accept\": \"application/json\" }\n        });\n        const data = await res.json().catch(() => ({}));\n\n        if (res.status === 401 || res.status === 403 || !data.success) {\n          logout();\n          return;\n        }\n        if (!res.ok) throw new Error(data.error || \"Could not load your account.\");\n\n        const user = data.user || {};\n        const surveys = Array.isArray(data.surveys) ? data.surveys : [];\n        const completedIds = Array.isArray(data.completedIds) ? data.completedIds : [];\n        const completedCount = Number(user.surveys_completed) || 0;\n\n        document.getElementById(\"welcomeText\").textContent =\n          \"Welcome, \" + (user.full_name || \"Trainer\");\n        document.getElementById(\"availBalance\").textContent =\n          formatUGX(user.available_balance_ugx);\n        document.getElementById(\"lockedBalance\").textContent =\n          formatUGX(user.locked_bonus_ugx);\n        document.getElementById(\"surveyCount\").textContent =\n          completedCount + \" / \" + surveys.length;\n\n        const progress = surveys.length\n          ? Math.min(100, Math.round((completedCount / surveys.length) * 100))\n          : 0;\n        document.getElementById(\"progressBar\").style.width = progress + \"%\";\n\n        document.getElementById(\"unlockHint\").textContent =\n          Number(user.locked_bonus_ugx) === 0\n            ? \"Your bonus has been unlocked.\"\n            : \"Bonus remains locked until the eligibility requirements are verified.\";\n\n        if (!surveys.length) {\n          surveyList.innerHTML = '<p class=\"text-slate-400 text-sm\">There are no active surveys right now. Please check again later.</p>';\n          return;\n        }\n\n        surveyList.innerHTML = surveys.map((survey) => {\n          const done = completedIds.includes(survey.id);\n          const surveyId = encodeURIComponent(String(survey.id));\n          return `\n            <article class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl flex justify-between items-center gap-4\">\n              <div class=\"min-w-0\">\n                <span class=\"text-xs font-semibold text-sky-400 uppercase\">${escapeHTML(survey.category || \"General\")}</span>\n                <h3 class=\"font-bold text-base mt-1\">${escapeHTML(survey.title || \"AI survey\")}</h3>\n                <div class=\"text-emerald-400 font-bold text-sm mt-2\">Up to ${formatUGX(survey.reward_ugx)}</div>\n                <p class=\"text-slate-500 text-xs mt-1\">Reward subject to valid completion and review.</p>\n              </div>\n              ${done\n                ? '<span class=\"shrink-0 bg-slate-800 text-slate-400 text-xs font-semibold px-4 py-2 rounded-lg\">Submitted ✓</span>'\n                : '<a href=\"/survey.html?id=' + surveyId + '\" class=\"shrink-0 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm px-5 py-2.5 rounded-lg transition\">Start</a>'\n              }\n            </article>\n          `;\n        }).join(\"\");\n      } catch (error) {\n        showError(error.message || \"Something went wrong while loading your dashboard.\");\n        surveyList.innerHTML = \"\";\n      }\n    }\n\n    loadDashboard();\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "survey.html": "<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>AI Training Survey — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-4xl items-center justify-between px-5 py-4\">\n      <a href=\"/dashboard.html\" class=\"text-sm text-sky-400 hover:underline\">← Back to Dashboard</a>\n      <span class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></span>\n    </div>\n  </nav>\n\n  <main class=\"mx-auto max-w-3xl px-4 py-8 sm:px-6\">\n    <div class=\"mb-6 flex flex-wrap items-center justify-between gap-3\">\n      <span id=\"categoryBadge\" class=\"rounded-full bg-sky-500/10 px-3 py-1 text-xs font-bold uppercase text-sky-300\">AI TRAINING</span>\n      <span id=\"rewardBadge\" class=\"rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-bold text-emerald-300\">Potential reward: — UGX</span>\n    </div>\n\n    <section class=\"rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl sm:p-8\">\n      <h1 id=\"surveyTitle\" class=\"text-2xl font-bold\">Loading survey…</h1>\n      <p id=\"surveyDescription\" class=\"mt-2 text-sm leading-6 text-slate-400\">Please wait while we load the task.</p>\n\n      <div class=\"mt-5 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-amber-200\">\n        Your answers are submitted for review. A displayed reward is not credited until the submission is checked and approved. Do not submit personal or payment details in your answers.\n      </div>\n\n      <form id=\"surveyForm\" class=\"mt-7 space-y-7\">\n        <p id=\"loadingMessage\" class=\"text-sm text-slate-400\">Loading questions…</p>\n        <div id=\"questionList\" class=\"space-y-7\"></div>\n        <p id=\"formMessage\" role=\"status\" class=\"hidden rounded-lg p-3 text-sm\"></p>\n        <button id=\"submitButton\" type=\"submit\" disabled class=\"w-full rounded-xl bg-sky-500 px-5 py-4 font-bold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50\">\n          Submit answers for review\n        </button>\n      </form>\n    </section>\n  </main>\n\n  <script>\n    const params = new URLSearchParams(window.location.search);\n    const surveyId = params.get(\"id\") || \"onboarding\";\n    const form = document.getElementById(\"surveyForm\");\n    const questionList = document.getElementById(\"questionList\");\n    const submitButton = document.getElementById(\"submitButton\");\n    const formMessage = document.getElementById(\"formMessage\");\n    let currentQuestions = [];\n\n    function showMessage(message, isError = true) {\n      formMessage.textContent = message;\n      formMessage.className = \"rounded-lg p-3 text-sm \" + (isError\n        ? \"border border-rose-500/30 bg-rose-500/10 text-rose-300\"\n        : \"border border-emerald-500/30 bg-emerald-500/10 text-emerald-300\");\n    }\n\n    function addChoice(container, questionIndex, choice, answerText) {\n      const label = document.createElement(\"label\");\n      label.className = \"flex cursor-pointer gap-3 rounded-xl border border-slate-700 bg-slate-950 p-4 transition hover:border-sky-400\";\n      const radio = document.createElement(\"input\");\n      radio.type = \"radio\";\n      radio.name = \"question_\" + questionIndex;\n      radio.value = choice;\n      radio.required = true;\n      radio.className = \"mt-1 accent-sky-400\";\n      const text = document.createElement(\"span\");\n      text.className = \"text-sm leading-6 text-slate-300\";\n      text.textContent = answerText;\n      label.append(radio, text);\n      container.append(label);\n    }\n\n    async function loadSurvey() {\n      try {\n        const response = await fetch(\"/api/user\", { credentials: \"same-origin\" });\n        const data = await response.json();\n        if (response.status === 401) {\n          window.location.href = \"/register.html\";\n          return;\n        }\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load your account.\");\n        const survey = (data.surveys || []).find(item => item.id === surveyId);\n        if (!survey) throw new Error(\"This survey is unavailable or has already been removed.\");\n\n        document.getElementById(\"surveyTitle\").textContent = survey.title;\n        document.getElementById(\"surveyDescription\").textContent = survey.description || \"Compare the two AI responses and choose the one that best answers the prompt.\";\n        document.getElementById(\"categoryBadge\").textContent = survey.category || \"AI TRAINING\";\n        document.getElementById(\"rewardBadge\").textContent = \"Potential reward: \" + Number(survey.reward_ugx).toLocaleString() + \" UGX\";\n\n        if ((data.completedIds || []).includes(surveyId)) {\n          throw new Error(\"You have already submitted this survey.\");\n        }\n\n        currentQuestions = JSON.parse(survey.questions_json || \"[]\");\n        if (!Array.isArray(currentQuestions) || currentQuestions.length === 0) {\n          throw new Error(\"This survey has no questions yet. Please check back later.\");\n        }\n\n        questionList.replaceChildren();\n        currentQuestions.forEach((item, index) => {\n          const section = document.createElement(\"section\");\n          section.className = \"border-t border-slate-800 pt-6\";\n          const heading = document.createElement(\"h2\");\n          heading.className = \"mb-4 font-semibold leading-6\";\n          heading.textContent = (index + 1) + \". \" + item.q;\n          const choices = document.createElement(\"div\");\n          choices.className = \"grid gap-3 md:grid-cols-2\";\n          addChoice(choices, index, \"A\", item.a);\n          addChoice(choices, index, \"B\", item.b);\n          section.append(heading, choices);\n          questionList.append(section);\n        });\n        document.getElementById(\"loadingMessage\").remove();\n        submitButton.disabled = false;\n      } catch (error) {\n        document.getElementById(\"loadingMessage\").textContent = error.message;\n        submitButton.classList.add(\"hidden\");\n      }\n    }\n\n    form.addEventListener(\"submit\", async event => {\n      event.preventDefault();\n      const answers = [];\n      for (let index = 0; index < currentQuestions.length; index++) {\n        const selected = form.querySelector('input[name=\"question_' + index + '\"]:checked');\n        if (!selected) {\n          showMessage(\"Please answer every question before submitting.\");\n          return;\n        }\n        answers.push({ question: index, choice: selected.value });\n      }\n\n      submitButton.disabled = true;\n      submitButton.textContent = \"Submitting for review…\";\n      formMessage.classList.add(\"hidden\");\n\n      try {\n        const response = await fetch(\"/api/submit\", {\n          method: \"POST\",\n          credentials: \"same-origin\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({ surveyId, answers })\n        });\n        const result = await response.json();\n        if (!response.ok || !result.success) throw new Error(result.error || \"Submission failed.\");\n        showMessage(result.message || \"Your answers have been submitted for review.\", false);\n        submitButton.textContent = \"Submitted\";\n        const back = document.createElement(\"a\");\n        back.href = \"/dashboard.html\";\n        back.textContent = \"Return to dashboard\";\n        back.className = \"mt-4 inline-block font-semibold text-sky-400 hover:underline\";\n        form.append(back);\n      } catch (error) {\n        showMessage(error.message);\n        submitButton.disabled = false;\n        submitButton.textContent = \"Submit answers for review\";\n      }\n    });\n\n    loadSurvey();\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "wallet.html": "<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Wallet & Withdrawals — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"max-w-4xl mx-auto px-6 py-4 flex justify-between items-center gap-4\">\n      <a href=\"/dashboard.html\" class=\"text-sm text-sky-400 hover:underline\">← Back to Dashboard</a>\n      <span class=\"font-bold\">Trainer Wallet</span>\n    </div>\n  </nav>\n\n  <main class=\"max-w-4xl mx-auto px-6 py-10 grid md:grid-cols-2 gap-8\">\n    <section class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n      <h1 class=\"text-lg font-bold mb-1\">Request Mobile Money Withdrawal</h1>\n      <p class=\"text-xs text-slate-400 mb-6\">Minimum request: 10,000 UGX. A request is not a guaranteed or instant payout.</p>\n\n      <div class=\"bg-slate-950 p-4 rounded-xl mb-6 border border-slate-800\">\n        <div class=\"text-xs text-slate-400\">Available Balance</div>\n        <div id=\"walletBalance\" class=\"text-2xl font-extrabold text-emerald-400 mt-1\">Loading...</div>\n      </div>\n\n      <form id=\"withdrawForm\" class=\"space-y-4\">\n        <div>\n          <label for=\"network\" class=\"block text-xs text-slate-400 mb-1\">Mobile Money Network</label>\n          <select id=\"network\" required class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\">\n            <option value=\"MTN\">MTN Mobile Money</option>\n            <option value=\"AIRTEL\">Airtel Money</option>\n          </select>\n        </div>\n        <div>\n          <label for=\"payoutPhone\" class=\"block text-xs text-slate-400 mb-1\">Phone Number</label>\n          <input type=\"tel\" id=\"payoutPhone\" required autocomplete=\"tel\" inputmode=\"tel\" maxlength=\"20\" placeholder=\"0770000000\" class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\" />\n        </div>\n        <div>\n          <label for=\"amount\" class=\"block text-xs text-slate-400 mb-1\">Amount (UGX)</label>\n          <input type=\"number\" id=\"amount\" min=\"10000\" step=\"1\" required placeholder=\"10000\" class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\" />\n        </div>\n        <p id=\"formMessage\" role=\"alert\" aria-live=\"polite\" class=\"text-sm hidden\"></p>\n        <button id=\"withdrawButton\" type=\"submit\" class=\"w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-bold py-3 rounded-lg transition\">\n          Submit Withdrawal Request\n        </button>\n      </form>\n      <p class=\"text-xs text-slate-500 leading-relaxed mt-5\">Withdrawals will only be processed when the platform's payment system is configured, funded and operational. Never pay a fee to unlock a withdrawal.</p>\n    </section>\n\n    <section class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n      <h2 class=\"text-lg font-bold mb-4\">Earnings & Transaction History</h2>\n      <div id=\"ledgerList\" class=\"space-y-3 text-sm\" aria-live=\"polite\">\n        <p class=\"text-slate-400\">Loading transactions...</p>\n      </div>\n      <p id=\"historyError\" role=\"alert\" class=\"text-rose-400 text-xs mt-4 hidden\"></p>\n    </section>\n  </main>\n\n  <script>\n    const userId = localStorage.getItem(\"trainai_user_id\");\n    const balanceElement = document.getElementById(\"walletBalance\");\n    const ledgerList = document.getElementById(\"ledgerList\");\n    const form = document.getElementById(\"withdrawForm\");\n    const submitButton = document.getElementById(\"withdrawButton\");\n    const formMessage = document.getElementById(\"formMessage\");\n    const historyError = document.getElementById(\"historyError\");\n\n    if (!userId) {\n      window.location.href = \"/register.html\";\n    }\n\n    function formatUGX(value) {\n      const amount = Number(value);\n      return (Number.isFinite(amount) ? amount : 0).toLocaleString(\"en-UG\") + \" UGX\";\n    }\n\n    function escapeHTML(value) {\n      return String(value ?? \"\").replace(/[&<>\"']/g, (char) => ({\n        \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\"\n      })[char]);\n    }\n\n    function showFormMessage(message, success) {\n      formMessage.textContent = message;\n      formMessage.className = \"text-sm \" + (success ? \"text-emerald-400\" : \"text-rose-400\");\n    }\n\n    async function loadWallet() {\n      try {\n        const res = await fetch(\"/api/user?userId=\" + encodeURIComponent(userId), {\n          headers: { \"Accept\": \"application/json\" }\n        });\n        const data = await res.json().catch(() => ({}));\n        if (res.status === 401 || res.status === 403 || !data.success) {\n          localStorage.removeItem(\"trainai_user_id\");\n          window.location.href = \"/register.html\";\n          return;\n        }\n        if (!res.ok) throw new Error(data.error || \"Unable to load wallet.\");\n\n        const user = data.user || {};\n        balanceElement.textContent = formatUGX(user.available_balance_ugx);\n        document.getElementById(\"payoutPhone\").value = user.phone_number || \"\";\n\n        const ledger = Array.isArray(data.ledger) ? data.ledger : [];\n        if (!ledger.length) {\n          ledgerList.innerHTML = '<p class=\"text-slate-400\">No transactions yet.</p>';\n          return;\n        }\n\n        ledgerList.innerHTML = ledger.map((item) => {\n          const type = item.transaction_type || item.type || \"transaction\";\n          const status = item.transaction_status || item.status || \"pending\";\n          const amount = item.amount_ugx;\n          return `\n            <div class=\"bg-slate-950 border border-slate-800 p-3 rounded-xl flex justify-between items-center gap-3\">\n              <div class=\"min-w-0\">\n                <div class=\"font-semibold text-xs\">${escapeHTML(String(type).replace(/_/g, \" \"))}</div>\n                <div class=\"text-xs text-slate-500\">${escapeHTML(status)}</div>\n              </div>\n              <div class=\"font-bold text-emerald-400 whitespace-nowrap\">${formatUGX(amount)}</div>\n            </div>\n          `;\n        }).join(\"\");\n      } catch (error) {\n        balanceElement.textContent = \"Unavailable\";\n        ledgerList.innerHTML = \"\";\n        historyError.textContent = error.message || \"Could not load transaction history.\";\n        historyError.classList.remove(\"hidden\");\n      }\n    }\n\n    form.addEventListener(\"submit\", async (event) => {\n      event.preventDefault();\n      formMessage.className = \"text-sm hidden\";\n\n      const amount = Number(document.getElementById(\"amount\").value);\n      const phone = document.getElementById(\"payoutPhone\").value.trim();\n      const network = document.getElementById(\"network\").value;\n\n      if (!Number.isSafeInteger(amount) || amount < 10000) {\n        showFormMessage(\"The minimum withdrawal request is 10,000 UGX.\", false);\n        return;\n      }\n      if (!phone) {\n        showFormMessage(\"Enter the mobile money phone number.\", false);\n        return;\n      }\n\n      submitButton.disabled = true;\n      submitButton.textContent = \"Sending request...\";\n\n      try {\n        const res = await fetch(\"/api/withdraw\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({ userId, network, phone, amount })\n        });\n        const data = await res.json().catch(() => ({}));\n        if (!res.ok || !data.success) {\n          throw new Error(data.error || \"Withdrawal request could not be submitted.\");\n        }\n        showFormMessage(data.message || \"Your withdrawal request was received.\", true);\n        document.getElementById(\"amount\").value = \"\";\n        await loadWallet();\n      } catch (error) {\n        showFormMessage(error.message || \"Something went wrong. Please try again.\", false);\n      } finally {\n        submitButton.disabled = false;\n        submitButton.textContent = \"Submit Withdrawal Request\";\n      }\n    });\n\n    if (userId) loadWallet();\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "admin.html": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#0b1220\" />\n  <title>Admin Review — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <header class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-5xl items-center justify-between px-5 py-4\">\n      <a href=\"/\" class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <nav class=\"flex items-center gap-4 text-xs font-semibold\"><a href=\"/admin.html\" class=\"text-slate-300 hover:text-sky-300\">Survey review</a><a href=\"/admin-withdrawals.html\" class=\"text-sky-300 hover:text-white\">Withdrawals</a></nav>\n    </div>\n  </header>\n  <main class=\"mx-auto max-w-5xl px-4 py-8 sm:px-6\">\n    <section class=\"mb-7 rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\">\n      <h1 class=\"text-2xl font-bold\">Submission review</h1>\n      <p class=\"mt-2 text-sm leading-6 text-slate-400\">Enter the administrator key configured privately in Cloudflare. This page does not save the key in your browser.</p>\n      <form id=\"authForm\" class=\"mt-5 flex flex-col gap-3 sm:flex-row\">\n        <input id=\"adminKey\" type=\"password\" autocomplete=\"off\" required placeholder=\"Admin API key\" class=\"min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-sky-400\" />\n        <button class=\"rounded-xl bg-sky-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-sky-400\" type=\"submit\">Load submissions</button>\n      </form>\n      <p id=\"status\" role=\"status\" class=\"mt-3 text-sm text-slate-400\">Admin access is required.</p>\n    </section>\n    <div class=\"mb-4 flex items-center justify-between\">\n      <h2 class=\"text-lg font-bold\">Pending submissions</h2>\n      <button id=\"refreshButton\" type=\"button\" class=\"hidden rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-sky-400\">Refresh</button>\n    </div>\n    <section id=\"submissionList\" class=\"space-y-5\"></section>\n    <p class=\"mt-8 text-xs leading-5 text-slate-500\">Approve only after checking the submitted answers. Approval credits the survey reward once. Rejection does not credit a reward. The welcome bonus is not unlocked by this action.</p>\n  </main>\n\n  <script>\n    let adminKey = \"\";\n    const list = document.getElementById(\"submissionList\");\n    const statusLine = document.getElementById(\"status\");\n    const refreshButton = document.getElementById(\"refreshButton\");\n\n    function node(tag, className, text) {\n      const element = document.createElement(tag);\n      if (className) element.className = className;\n      if (text !== undefined) element.textContent = text;\n      return element;\n    }\n\n    function setStatus(message, error = false) {\n      statusLine.textContent = message;\n      statusLine.className = \"mt-3 text-sm \" + (error ? \"text-rose-300\" : \"text-slate-400\");\n    }\n\n    async function loadSubmissions() {\n      if (!adminKey) return;\n      setStatus(\"Loading pending submissions…\");\n      refreshButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/review\", {\n          headers: { \"Authorization\": \"Bearer \" + adminKey },\n          cache: \"no-store\"\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load submissions.\");\n        list.replaceChildren();\n        const submissions = data.submissions || [];\n        if (!submissions.length) {\n          list.append(node(\"div\", \"rounded-2xl border border-slate-800 bg-slate-900 p-6 text-sm text-slate-400\", \"There are no pending submissions.\"));\n        }\n        submissions.forEach(item => renderSubmission(item));\n        setStatus(submissions.length + \" pending submission(s) loaded.\");\n        refreshButton.classList.remove(\"hidden\");\n      } catch (error) {\n        setStatus(error.message, true);\n        if (responseUnauthorized(error)) {\n          adminKey = \"\";\n          document.getElementById(\"adminKey\").value = \"\";\n        }\n      } finally {\n        refreshButton.disabled = false;\n      }\n    }\n\n    function responseUnauthorized(error) {\n      return /key is missing or incorrect/i.test(error.message);\n    }\n\n    function renderSubmission(item) {\n      const card = node(\"article\", \"rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\");\n      const top = node(\"div\", \"flex flex-wrap items-start justify-between gap-3\");\n      const details = node(\"div\", \"min-w-0\");\n      details.append(\n        node(\"h3\", \"text-lg font-bold\", item.survey_title || \"Survey\"),\n        node(\"p\", \"mt-1 text-sm text-slate-400\", (item.full_name || \"User\") + \" · \" + (item.email || \"No email\")),\n        node(\"p\", \"mt-1 text-xs text-slate-500\", \"Submitted: \" + (item.submitted_at || \"Unknown\"))\n      );\n      top.append(details, node(\"span\", \"rounded-full bg-emerald-500/10 px-3 py-1 text-sm font-semibold text-emerald-300\", Number(item.reward_ugx || 0).toLocaleString() + \" UGX potential reward\"));\n      card.append(top);\n\n      let questions = [];\n      let answers = [];\n      try { questions = JSON.parse(item.questions_json || \"[]\"); } catch {}\n      try { answers = JSON.parse(item.answers_json || \"[]\"); } catch {}\n      const answerBlock = node(\"div\", \"mt-5 space-y-4\");\n      questions.forEach((question, index) => {\n        const answer = answers.find(entry => entry.question === index);\n        const chosen = answer?.choice;\n        const chosenText = chosen === \"A\" ? question.a : chosen === \"B\" ? question.b : \"No valid answer recorded\";\n        const section = node(\"div\", \"rounded-xl border border-slate-800 bg-slate-950 p-4\");\n        section.append(\n          node(\"p\", \"text-sm font-semibold text-slate-200\", (index + 1) + \". \" + (question.q || \"Question\")),\n          node(\"p\", \"mt-2 text-sm leading-6 text-sky-200\", \"Selected \" + (chosen || \"—\") + \": \" + chosenText)\n        );\n        answerBlock.append(section);\n      });\n      card.append(answerBlock);\n\n      const actions = node(\"div\", \"mt-5 flex flex-wrap gap-3\");\n      const approve = node(\"button\", \"rounded-xl bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-400 disabled:opacity-50\", \"Approve and credit reward\");\n      const reject = node(\"button\", \"rounded-xl border border-rose-500/40 px-5 py-3 text-sm font-semibold text-rose-300 hover:bg-rose-500/10 disabled:opacity-50\", \"Reject\");\n      approve.type = reject.type = \"button\";\n      approve.addEventListener(\"click\", () => review(item.id, \"approve\", approve, reject));\n      reject.addEventListener(\"click\", () => review(item.id, \"reject\", approve, reject));\n      actions.append(approve, reject);\n      card.append(actions);\n      list.append(card);\n    }\n\n    async function review(responseId, decision, approveButton, rejectButton) {\n      const promptText = decision === \"approve\"\n        ? \"Approve this submission and credit its survey reward?\"\n        : \"Reject this submission? No reward will be credited.\";\n      if (!window.confirm(promptText)) return;\n      approveButton.disabled = rejectButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/review\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\", \"Authorization\": \"Bearer \" + adminKey },\n          body: JSON.stringify({ responseId, decision })\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Review failed.\");\n        setStatus(data.message || \"Review completed.\");\n        await loadSubmissions();\n      } catch (error) {\n        setStatus(error.message, true);\n        approveButton.disabled = rejectButton.disabled = false;\n      }\n    }\n\n    document.getElementById(\"authForm\").addEventListener(\"submit\", event => {\n      event.preventDefault();\n      adminKey = document.getElementById(\"adminKey\").value.trim();\n      loadSubmissions();\n    });\n    refreshButton.addEventListener(\"click\", loadSubmissions);\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n",
  "admin-withdrawals.html": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#0b1220\" />\n  <title>Withdrawal Review — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n  <link rel=\"manifest\" href=\"/manifest.json\" />\n  <meta name=\"theme-color\" content=\"#0ea5e9\" />\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <header class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-5xl items-center justify-between px-5 py-4\">\n      <a href=\"/admin.html\" class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <span class=\"text-xs font-semibold uppercase tracking-wider text-slate-400\">Withdrawal administration</span>\n    </div>\n  </header>\n\n  <main class=\"mx-auto max-w-5xl px-4 py-8 sm:px-6\">\n    <section class=\"mb-7 rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\">\n      <h1 class=\"text-2xl font-bold\">Withdrawal requests</h1>\n      <p class=\"mt-2 text-sm leading-6 text-slate-400\">\n        Enter the private administrator key. This page does not save it in your browser.\n        Verify each transfer in your Mobile Money account before marking it paid.\n      </p>\n      <form id=\"authForm\" class=\"mt-5 flex flex-col gap-3 sm:flex-row\">\n        <input id=\"adminKey\" type=\"password\" autocomplete=\"off\" required placeholder=\"Admin API key\"\n          class=\"min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-sky-400\" />\n        <button class=\"rounded-xl bg-sky-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-sky-400\" type=\"submit\">Load requests</button>\n      </form>\n      <p id=\"status\" role=\"status\" class=\"mt-3 text-sm text-slate-400\">Admin access is required.</p>\n    </section>\n\n    <div class=\"mb-4 flex items-center justify-between gap-3\">\n      <h2 class=\"text-lg font-bold\">Pending withdrawals</h2>\n      <button id=\"refreshButton\" type=\"button\" class=\"hidden rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-sky-400\">Refresh</button>\n    </div>\n    <section id=\"withdrawalList\" class=\"space-y-4\"></section>\n    <p class=\"mt-8 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-amber-200\">\n      Important: marking a request as paid only updates your app records. It does not send Mobile Money.\n      Send the payment manually through the correct MTN or Airtel channel, confirm success, then mark it paid.\n      Rejecting a request automatically refunds the amount to the user's available wallet balance.\n    </p>\n  </main>\n\n  <script>\n    let adminKey = \"\";\n    const list = document.getElementById(\"withdrawalList\");\n    const statusLine = document.getElementById(\"status\");\n    const refreshButton = document.getElementById(\"refreshButton\");\n\n    function node(tag, className, text) {\n      const element = document.createElement(tag);\n      if (className) element.className = className;\n      if (text !== undefined) element.textContent = text;\n      return element;\n    }\n\n    function setStatus(message, error = false) {\n      statusLine.textContent = message;\n      statusLine.className = \"mt-3 text-sm \" + (error ? \"text-rose-300\" : \"text-slate-400\");\n    }\n\n    async function loadWithdrawals() {\n      if (!adminKey) return;\n      setStatus(\"Loading pending withdrawals…\");\n      refreshButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/withdrawals\", {\n          headers: { \"Authorization\": \"Bearer \" + adminKey },\n          cache: \"no-store\"\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load withdrawals.\");\n        list.replaceChildren();\n        const withdrawals = data.withdrawals || [];\n        if (!withdrawals.length) {\n          list.append(node(\"div\", \"rounded-2xl border border-slate-800 bg-slate-900 p-6 text-sm text-slate-400\", \"There are no pending withdrawal requests.\"));\n        }\n        withdrawals.forEach(renderWithdrawal);\n        setStatus(withdrawals.length + \" pending withdrawal(s) loaded.\");\n        refreshButton.classList.remove(\"hidden\");\n      } catch (error) {\n        setStatus(error.message, true);\n        if (/key is missing or incorrect/i.test(error.message)) {\n          adminKey = \"\";\n          document.getElementById(\"adminKey\").value = \"\";\n        }\n      } finally {\n        refreshButton.disabled = false;\n      }\n    }\n\n    function renderWithdrawal(item) {\n      const card = node(\"article\", \"rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\");\n      const top = node(\"div\", \"flex flex-wrap items-start justify-between gap-3\");\n      const info = node(\"div\", \"min-w-0\");\n      info.append(\n        node(\"h3\", \"text-lg font-bold\", (item.full_name || \"User\") + \" · \" + (item.email || \"No email\")),\n        node(\"p\", \"mt-1 text-sm text-slate-400\", \"Requested: \" + (item.created_at || \"Unknown\")),\n        node(\"p\", \"mt-1 text-xs text-slate-500 break-all\", \"Request ID: \" + item.id)\n      );\n      top.append(\n        info,\n        node(\"span\", \"rounded-full bg-amber-500/10 px-3 py-1 text-sm font-bold text-amber-300\",\n          Number(item.amount_ugx || 0).toLocaleString() + \" UGX\")\n      );\n      card.append(top);\n\n      const destination = node(\"div\", \"mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4\");\n      destination.append(\n        node(\"p\", \"text-xs uppercase tracking-wider text-slate-500\", \"Payment destination\"),\n        node(\"p\", \"mt-1 text-base font-bold\", item.mobile_money_network + \" Money\"),\n        node(\"p\", \"mt-1 text-lg font-semibold text-sky-200\", item.mobile_money_number)\n      );\n      card.append(destination);\n\n      const actions = node(\"div\", \"mt-5 flex flex-wrap gap-3\");\n      const paid = node(\"button\", \"rounded-xl bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-400 disabled:opacity-50\", \"Mark paid\");\n      const reject = node(\"button\", \"rounded-xl border border-rose-500/40 px-5 py-3 text-sm font-semibold text-rose-300 hover:bg-rose-500/10 disabled:opacity-50\", \"Reject and refund\");\n      paid.type = reject.type = \"button\";\n      paid.addEventListener(\"click\", () => processWithdrawal(item, \"paid\", paid, reject));\n      reject.addEventListener(\"click\", () => processWithdrawal(item, \"reject\", paid, reject));\n      actions.append(paid, reject);\n      card.append(actions);\n      list.append(card);\n    }\n\n    async function processWithdrawal(item, decision, paidButton, rejectButton) {\n      const message = decision === \"paid\"\n        ? \"Only continue if you have already sent and confirmed \" + Number(item.amount_ugx).toLocaleString() + \" UGX to \" + item.mobile_money_network + \" number \" + item.mobile_money_number + \". Mark this request as paid?\"\n        : \"Reject this withdrawal? \" + Number(item.amount_ugx).toLocaleString() + \" UGX will be refunded to the user's available wallet balance.\";\n      if (!window.confirm(message)) return;\n\n      paidButton.disabled = rejectButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/withdrawals\", {\n          method: \"POST\",\n          headers: {\n            \"Content-Type\": \"application/json\",\n            \"Authorization\": \"Bearer \" + adminKey\n          },\n          body: JSON.stringify({ withdrawalId: item.id, decision })\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not process withdrawal.\");\n        setStatus(data.message || \"Withdrawal processed.\");\n        await loadWithdrawals();\n      } catch (error) {\n        setStatus(error.message, true);\n        paidButton.disabled = rejectButton.disabled = false;\n      }\n    }\n\n    document.getElementById(\"authForm\").addEventListener(\"submit\", event => {\n      event.preventDefault();\n      adminKey = document.getElementById(\"adminKey\").value.trim();\n      loadWithdrawals();\n    });\n    refreshButton.addEventListener(\"click\", loadWithdrawals);\n  </script>\n  <script>\n    if (\"serviceWorker\" in navigator) {\n      navigator.serviceWorker.register(\"/sw.js\");\n    }\n  </script>\n</body>\n</html>\n"
};
const sec={"X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","X-Frame-Options":"DENY","Cache-Control":"no-store"};
export default {async fetch(request,env){const url=new URL(request.url),path=url.pathname;const routes={"/api/register":registerHandler,"/api/user":userHandler,"/api/submit":submitHandler,"/api/withdraw":withdrawHandler,"/api/admin/review":adminReviewHandler,"/api/admin/withdrawals":adminWithdrawalsHandler};if(routes[path]){try{const r=await routes[path]({request,env});const h=new Headers(r.headers);h.set("X-Content-Type-Options","nosniff");h.set("Referrer-Policy","strict-origin-when-cross-origin");return new Response(r.body,{status:r.status,statusText:r.statusText,headers:h});}catch(e){return Response.json({success:false,error:"The request could not be completed."},{status:500,headers:sec});}}if(path.startsWith("/api/"))return Response.json({success:false,error:"API route not found."},{status:404,headers:sec});let key=path==="/"?"index.html":path.replace(/^\//,"");if(!key.endsWith(".html"))key+=".html";const html=PAGES[key];if(!html)return new Response("Not found",{status:404,headers:sec});return new Response(html,{headers:{...sec,"Content-Type":"text/html; charset=utf-8"}});}};