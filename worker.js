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
    const normalizedPhone = authTools.normalizePhone(phone);
    if (!normalizedPhone) {
      return json({ success: false, error: "Enter a valid Ugandan MTN or Airtel number." }, 400);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return json({ success: false, error: "Enter a valid email address." }, 400);
    }
    if (password.length < 10 || password.length > 128) {
      return json({ success: false, error: "Password must be at least 10 characters." }, 400);
    }

    const referralInput = String(input.referral_code || "").trim().toUpperCase();
    let referredBy = null;
    if (referralInput) {
      const referrer = await env.DB.prepare("SELECT referral_code FROM users WHERE referral_code = ?").bind(referralInput).first();
      if (!referrer) return json({ success: false, error: "That referral code is not valid." }, 400);
      referredBy = referralInput;
    }
    const referralCode = "TAI-" + Array.from(crypto.getRandomValues(new Uint8Array(4))).map(x => x.toString(16).padStart(2,"0")).join("").toUpperCase();
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
           locked_bonus_ugx, available_balance_ugx, referral_code, referred_by)
         VALUES (?, ?, ?, ?, ?, 'active', 5000, 0, ?, ?)`
      ).bind(userId, fullName, email, normalizedPhone, passwordHash, referralCode, referredBy),
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
      `SELECT id, full_name, email, phone_number, locked_bonus_ugx,
              available_balance_ugx, surveys_completed, payout_name,
              payout_number, payout_network, payout_locked, referral_code
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
        "SELECT survey_id, review_status, submitted_at FROM survey_responses WHERE user_id = ?"
      ).bind(user.id).all(),
      env.DB.prepare(
        `SELECT transaction_type, amount_ugx, transaction_status,
                balance_bucket, notes, reference, created_at
         FROM wallet_transactions
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 50`
      ).bind(user.id).all(),
    ]);

    const surveys = surveyResult.results || [];
    const responseRows = responseResult.results || [];
    const completedIds = responseRows.map(row => row.survey_id);
    const approvedRows = responseRows.filter(row => row.review_status === "approved");
    const rejectedRows = responseRows.filter(row => row.review_status === "rejected");
    const reviewedCount = approvedRows.length + rejectedRows.length;
    const approvedDays = new Set(approvedRows.map(row => String(row.submitted_at || "").slice(0,10)));
    let currentStreak = 0;
    let day = new Date();
    let dayKey = day.toISOString().slice(0,10);
    if (!approvedDays.has(dayKey)) { day.setUTCDate(day.getUTCDate()-1); dayKey = day.toISOString().slice(0,10); }
    while (approvedDays.has(dayKey)) {
      currentStreak++;
      day.setUTCDate(day.getUTCDate()-1);
      dayKey = day.toISOString().slice(0,10);
    }
    const ledger = (transactionResult.results || []).map(row => ({
      type: row.transaction_type,
      status: row.transaction_status,
      amount_ugx: row.amount_ugx,
      balance_bucket: row.balance_bucket,
      details: row.notes,
      reference: row.reference,
      created_at: row.created_at,
    }));

    user.approved_task_count = approvedRows.length;
    user.rejected_task_count = rejectedRows.length;
    user.quality_score = reviewedCount ? Math.round(approvedRows.length / reviewedCount * 100) : null;
    user.current_streak = currentStreak;
    user.bonus_progress = Math.min(3, approvedRows.length);

    return json({
      success: true,
      user,
      surveys,
      completedIds,
      ledger,
      approved_task_count: approvedRows.length,
      rejected_task_count: rejectedRows.length,
      quality_score: reviewedCount ? Math.round(approvedRows.length / reviewedCount * 100) : null,
      current_streak: currentStreak,
      bonus_progress: Math.min(3, approvedRows.length),
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
      if (!answer || answer.question !== index || !["A", "B", "TIE"].includes(answer.choice)) {
        return json({ success: false, error: "Please provide one valid answer to every question." }, 400);
      }
      const feedback = ["Accurate", "Natural Luganda", "Hallucination"].includes(answer.feedback) ? answer.feedback : null;
      normalized.push({ question: index, choice: answer.choice, feedback });
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
  let national = String(value || "").replace(/[^0-9]/g, "");
  if (national.startsWith("256")) national = national.slice(3);
  else if (national.startsWith("0")) national = national.slice(1);
  if (!/^(70|74|75|76|77|78|39)\d{7}$/.test(national)) return null;
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
      "SELECT id, available_balance_ugx, payout_name, payout_number, payout_network, payout_locked FROM users WHERE id = ? AND account_status = 'active'"
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
    if (!user.payout_locked || !user.payout_number || !user.payout_network) {
      return json({ success: false, error: "Verify and lock your Mobile Money payout account in Settings first." }, 409);
    }
    if (network !== user.payout_network || phone !== user.payout_number) {
      return json({ success: false, error: "Withdrawal destination must match your locked payout account." }, 400);
    }
    if (!Number.isSafeInteger(amount) || amount < 25000) {
      return json({ success: false, error: "Minimum withdrawal request is 25,000 UGX." }, 400);
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
      platformFeeUGX: 0,
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

const authTools = (() => {
  function readToken(request) {
    const header = request.headers.get("Cookie") || "";
    for (const part of header.split(";")) {
      const i = part.indexOf("=");
      if (i >= 0 && part.slice(0, i).trim() === "trainai_session") return part.slice(i + 1).trim();
    }
    return null;
  }
  async function tokenHash(token) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    let binary = "";
    for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
    return btoa(binary);
  }
  async function userFor(request, env) {
    const token = readToken(request);
    if (!token) return null;
    const hash = await tokenHash(token);
    const row = await env.DB.prepare(
      "SELECT s.user_id, s.expires_at, u.account_status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?"
    ).bind(hash).first();
    if (!row || row.account_status !== "active" || Date.parse(row.expires_at) <= Date.now()) return null;
    return { id: row.user_id, token, hash };
  }
  function normalizePhone(value) {
    let digits = String(value || "").replace(/[^0-9]/g, "");
    if (digits.startsWith("256")) digits = digits.slice(3);
    else if (digits.startsWith("0")) digits = digits.slice(1);
    if (!/^(70|74|75|76|77|78|39)\d{7}$/.test(digits)) return null;
    return "+256" + digits;
  }
  function detectNetwork(phone) {
    const national = String(phone || "").replace(/^\+256/, "");
    if (/^(76|77|78|39)/.test(national)) return "MTN";
    if (/^(70|74|75)/.test(national)) return "AIRTEL";
    return null;
  }
  function json(body, status = 200, headers = {}) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
    });
  }
  return { readToken, tokenHash, userFor, normalizePhone, detectNetwork, json };
})();

const loginHandler = (() => {
  async function verifyPassword(password, stored) {
    const parts = String(stored || "").split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
    const iterations = Number(parts[1]);
    if (!Number.isSafeInteger(iterations) || iterations < 10000 || iterations > 1000000) return false;
    const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
    const salt = decode(parts[2]), expected = decode(parts[3]);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256));
    if (bits.length !== expected.length) return false;
    let mismatch = 0;
    for (let i = 0; i < bits.length; i++) mismatch |= bits[i] ^ expected[i];
    return mismatch === 0;
  }
  return async ({ request, env }) => {
    if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
    if (!env.DB) return authTools.json({ success: false, error: "Database is not configured." }, 500);
    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) return authTools.json({ success: false, error: "Invalid request origin." }, 403);
    try {
      const body = await request.json();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) {
        return authTools.json({ success: false, error: "Enter a valid email and password." }, 400);
      }
      const user = await env.DB.prepare("SELECT id, password_hash, account_status FROM users WHERE email=?").bind(email).first();
      if (!user || user.account_status !== "active" || !(await verifyPassword(password, user.password_hash))) {
        return authTools.json({ success: false, error: "Email or password is incorrect." }, 401);
      }
      const token = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      const hash = await authTools.tokenHash(token);
      const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(hash, user.id, expires).run();
      return authTools.json({ success: true, message: "Signed in successfully." }, 200, {
        "Set-Cookie": "trainai_session=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800"
      });
    } catch {
      return authTools.json({ success: false, error: "Sign-in could not be completed. Please try again." }, 500);
    }
  };
})();

const authHandler = async ({ request, env }) => {
  if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
  try {
    const body = await request.clone().json();
    if (String(body.action || "").toLowerCase() === "register") return registerHandler({ request, env });
    return loginHandler({ request, env });
  } catch {
    return authTools.json({ success: false, error: "Invalid authentication request." }, 400);
  }
};

const logoutHandler = async ({ request, env }) => {
  const token = authTools.readToken(request);
  if (token && env.DB) {
    const hash = await authTools.tokenHash(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(hash).run();
  }
  return authTools.json({ success: true }, 200, {
    "Set-Cookie": "trainai_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  });
};

const profileHandler = async ({ request, env }) => {
  const auth = await authTools.userFor(request, env);
  if (!auth) return authTools.json({ success: false, error: "Please sign in again." }, 401);
  if (request.method === "GET") {
    const user = await env.DB.prepare(
      "SELECT full_name,email,phone_number,payout_name,payout_number,payout_network,payout_locked FROM users WHERE id=?"
    ).bind(auth.id).first();
    return authTools.json({ success: true, profile: user });
  }
  if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return authTools.json({ success: false, error: "Invalid request origin." }, 403);
  try {
    const body = await request.json();
    const name = String(body.payout_name || "").trim();
    const network = String(body.payout_network || "").trim().toUpperCase();
    const phone = authTools.normalizePhone(body.payout_number);
    if (name.length < 2 || name.length > 120) return authTools.json({ success: false, error: "Enter the Mobile Money account holder name." }, 400);
    if (!phone || !["MTN","AIRTEL"].includes(network)) return authTools.json({ success: false, error: "Enter a valid Ugandan MTN or Airtel number." }, 400);
    if (authTools.detectNetwork(phone) !== network) return authTools.json({ success: false, error: "The selected network does not match the number prefix." }, 400);
    const result = await env.DB.prepare(
      "UPDATE users SET payout_name=?,payout_number=?,payout_network=?,payout_locked=1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND payout_locked=0"
    ).bind(name, phone, network, auth.id).run();
    if (result.meta?.changes !== 1) return authTools.json({ success: false, error: "Your payout account is already locked. Contact support for a correction." }, 409);
    return authTools.json({ success: true, message: "Payout account saved and locked. TrainAI cannot verify account ownership with the Mobile Money operator." });
  } catch {
    return authTools.json({ success: false, error: "Payout details could not be saved." }, 500);
  }
};

const tasksStartHandler = async ({ request, env }) => {
  const auth = await authTools.userFor(request, env);
  if (!auth) return authTools.json({ success: false, error: "Please sign in again." }, 401);
  if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return authTools.json({ success: false, error: "Invalid request origin." }, 403);
  try {
    const body = await request.json();
    const surveyId = String(body.surveyId || "");
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(surveyId)) return authTools.json({ success: false, error: "Choose a valid task." }, 400);
    const survey = await env.DB.prepare("SELECT id FROM surveys WHERE id=? AND is_active=1").bind(surveyId).first();
    if (!survey) return authTools.json({ success: false, error: "This task is not available." }, 404);
    const existing = await env.DB.prepare("SELECT id FROM survey_responses WHERE user_id=? AND survey_id=?").bind(auth.id, surveyId).first();
    if (existing) return authTools.json({ success: false, error: "You have already submitted this task." }, 409);
    const attemptId = crypto.randomUUID();
    const started = new Date().toISOString();
    const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    await env.DB.prepare("INSERT INTO task_attempts(id,user_id,survey_id,started_at,expires_at) VALUES(?,?,?,?,?)")
      .bind(attemptId, auth.id, surveyId, started, expires).run();
    return authTools.json({ success: true, attemptId, startedAt: started, minimumSeconds: 10 });
  } catch {
    return authTools.json({ success: false, error: "Could not start this task. Please try again." }, 500);
  }
};

const submissionHandler = async ({ request, env }) => {
  const auth = await authTools.userFor(request, env);
  if (!auth) return authTools.json({ success: false, error: "Please sign in again." }, 401);
  if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return authTools.json({ success: false, error: "Invalid request origin." }, 403);
  try {
    const body = await request.json();
    const attemptId = String(body.attemptId || "");
    const surveyId = String(body.surveyId || "");
    if (!/^[0-9a-f-]{36}$/i.test(attemptId)) return authTools.json({ success: false, error: "Start the task before submitting." }, 400);
    const attempt = await env.DB.prepare(
      "SELECT started_at,expires_at,submitted_at FROM task_attempts WHERE id=? AND user_id=? AND survey_id=?"
    ).bind(attemptId, auth.id, surveyId).first();
    if (!attempt) return authTools.json({ success: false, error: "Task attempt not found. Reopen the task." }, 404);
    if (attempt.submitted_at) return authTools.json({ success: false, error: "This task attempt has already been submitted." }, 409);
    if (Date.parse(attempt.expires_at) <= Date.now()) return authTools.json({ success: false, error: "This task attempt expired. Start the task again." }, 410);
    if (Date.now() - Date.parse(attempt.started_at) < 10000) return authTools.json({ success: false, error: "Please spend at least 10 seconds reviewing the task before submitting." }, 429);
    const forwarded = new Request(request.url, {
      method: "POST",
      headers: request.headers,
      body: JSON.stringify({ surveyId, answers: body.answers })
    });
    const result = await submitHandler({ request: forwarded, env });
    if (result.status >= 200 && result.status < 300) {
      await env.DB.prepare("UPDATE task_attempts SET submitted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND user_id=? AND submitted_at IS NULL")
        .bind(attemptId, auth.id).run();
    }
    return result;
  } catch {
    return authTools.json({ success: false, error: "Submission could not be completed." }, 500);
  }
};

const supportHandler = async ({ request, env }) => {
  const auth = await authTools.userFor(request, env);
  if (!auth) return authTools.json({ success: false, error: "Please sign in again." }, 401);
  if (request.method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT id,subject,message,ticket_status,created_at,updated_at FROM support_tickets WHERE user_id=? ORDER BY created_at DESC LIMIT 50"
    ).bind(auth.id).all();
    return authTools.json({ success: true, tickets: rows.results || [] });
  }
  if (request.method !== "POST") return authTools.json({ success: false, error: "Method not allowed." }, 405);
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return authTools.json({ success: false, error: "Invalid request origin." }, 403);
  try {
    const body = await request.json();
    const subject = String(body.subject || "").trim();
    const message = String(body.message || "").trim();
    if (subject.length < 4 || subject.length > 120 || message.length < 10 || message.length > 3000) {
      return authTools.json({ success: false, error: "Enter a subject and a message of at least 10 characters." }, 400);
    }
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO support_tickets(id,user_id,subject,message) VALUES(?,?,?,?)")
      .bind(id, auth.id, subject, message).run();
    return authTools.json({ success: true, ticketId: id, message: "Your support ticket has been received." }, 201);
  } catch {
    return authTools.json({ success: false, error: "Support ticket could not be submitted." }, 500);
  }
};

const referralsHandler = async ({ request, env }) => {
  const auth = await authTools.userFor(request, env);
  if (!auth) return authTools.json({ success: false, error: "Please sign in again." }, 401);
  const row = await env.DB.prepare(
    "SELECT referral_code,(SELECT COUNT(*) FROM users referred WHERE referred.referred_by=users.referral_code) AS referral_count FROM users WHERE id=?"
  ).bind(auth.id).first();
  return authTools.json({ success: true, referral_code: row?.referral_code || null, referral_count: Number(row?.referral_count || 0) });
};

const PAGES={"index.html":"<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"description\" content=\"Help evaluate AI answers, check Luganda translations, and take part in AI training surveys with TrainAI Uganda.\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>TrainAI Uganda — Teach AI & Earn UGX</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"bg-slate-950 text-slate-100 font-sans antialiased\">\n  <nav class=\"border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50\">\n    <div class=\"max-w-5xl mx-auto px-6 py-4 flex justify-between items-center\">\n      <a href=\"/\" class=\"text-xl font-bold tracking-tight text-sky-400\">TrainAI<span class=\"text-slate-100\">.ug</span></a>\n      <div class=\"flex items-center gap-4\">\n        <a href=\"/dashboard.html\" class=\"text-sm text-slate-300 hover:text-white\">Dashboard</a>\n        <a href=\"/register.html\" class=\"bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition\">Get Started</a>\n      </div>\n    </div>\n  </nav>\n\n  <main class=\"max-w-4xl mx-auto px-6 py-20 text-center\">\n    <span class=\"inline-block bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-semibold px-3 py-1 rounded-full mb-6\">\n      5,000 UGX WELCOME BONUS — LOCKED UNTIL ELIGIBILITY IS MET\n    </span>\n    <h1 class=\"text-4xl md:text-6xl font-extrabold tracking-tight mb-6 leading-tight\">\n      Train Smarter AI Models. <br><span class=\"text-sky-400\">Earn Rewards in UGX.</span>\n    </h1>\n    <p class=\"text-slate-400 text-lg max-w-2xl mx-auto mb-10\">\n      Help improve artificial intelligence by rating AI responses, checking local-language translations, and completing feedback surveys from your phone or computer.\n    </p>\n    <div class=\"flex flex-col sm:flex-row justify-center gap-4\">\n      <a href=\"/register.html\" class=\"bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-8 py-4 rounded-xl text-lg shadow-lg shadow-sky-500/20 transition\">\n        Create a Free Account\n      </a>\n      <a href=\"#how-it-works\" class=\"bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-8 py-4 rounded-xl text-lg transition\">\n        How It Works\n      </a>\n    </div>\n\n    <div id=\"how-it-works\" class=\"grid md:grid-cols-3 gap-6 mt-24 text-left\">\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 01</div>\n        <h2 class=\"text-lg font-bold mb-2\">Create a Free Account</h2>\n        <p class=\"text-slate-400 text-sm\">Register with your details. A 5,000 UGX promotional bonus is recorded as locked and is not immediately withdrawable.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 02</div>\n        <h2 class=\"text-lg font-bold mb-2\">Complete AI Surveys</h2>\n        <p class=\"text-slate-400 text-sm\">Compare AI answers, assess factual accuracy, and review translations. Advertised task rewards are subject to valid submission and review.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-sky-400 font-bold text-sm mb-2\">STEP 03</div>\n        <h2 class=\"text-lg font-bold mb-2\">Request a Withdrawal</h2>\n        <p class=\"text-slate-400 text-sm\">Eligible available balances may be requested through MTN MoMo or Airtel Money once payment processing is configured and funded.</p>\n      </div>\n    </div>\n\n    <p class=\"text-slate-500 text-xs leading-relaxed max-w-2xl mx-auto mt-10\">\n      Rewards are promotional or task-based and are not guaranteed income. The welcome bonus is locked until the published eligibility conditions are met. Survey submissions may be reviewed before rewards become available. Withdrawals are not available until the payment system is operational and funds are available.\n    </p>\n  </main>\n</body>\n</html>\n","register.html":"<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Register — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center px-4 py-10\">\n  <main class=\"max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-xl\">\n    <div class=\"text-center mb-6\">\n      <span class=\"bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-bold px-3 py-1 rounded-full\">5,000 UGX LOCKED WELCOME BONUS</span>\n      <h1 class=\"text-2xl font-bold mt-4\">Create Your Trainer Account</h1>\n      <p class=\"text-slate-400 text-sm mt-2\">Register to get started with AI training surveys.</p>\n    </div>\n\n    <form id=\"registerForm\" class=\"space-y-4\">\n      <div>\n        <label for=\"fullName\" class=\"block text-xs font-medium text-slate-400 mb-1\">Full Name</label>\n        <input type=\"text\" id=\"fullName\" name=\"full_name\" required autocomplete=\"name\" maxlength=\"120\" placeholder=\"e.g. Kato Mukasa\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"phone\" class=\"block text-xs font-medium text-slate-400 mb-1\">Mobile Money Number (MTN / Airtel)</label>\n        <input type=\"tel\" id=\"phone\" name=\"phone_number\" required autocomplete=\"tel\" inputmode=\"tel\" maxlength=\"20\" placeholder=\"0770000000\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"email\" class=\"block text-xs font-medium text-slate-400 mb-1\">Email Address</label>\n        <input type=\"email\" id=\"email\" name=\"email\" required autocomplete=\"email\" maxlength=\"254\" placeholder=\"you@example.com\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n      </div>\n      <div>\n        <label for=\"password\" class=\"block text-xs font-medium text-slate-400 mb-1\">Password</label>\n        <input type=\"password\" id=\"password\" name=\"password\" required autocomplete=\"new-password\" minlength=\"10\" maxlength=\"128\" placeholder=\"At least 10 characters\"\n          class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-sky-400\" />\n        <p class=\"text-slate-500 text-xs mt-1\">Use at least 10 characters. Never reuse your email password.</p>\n      </div>\n\n      <p id=\"errorMsg\" role=\"alert\" aria-live=\"polite\" class=\"text-rose-400 text-xs hidden\"></p>\n      <p id=\"successMsg\" role=\"status\" aria-live=\"polite\" class=\"text-emerald-400 text-xs hidden\"></p>\n\n      <button type=\"submit\" id=\"submitBtn\"\n        class=\"w-full bg-sky-500 hover:bg-sky-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-bold py-3 rounded-lg transition mt-2\">\n        Register & Start Survey →\n      </button>\n    </form>\n\n    <p class=\"text-slate-500 text-xs leading-relaxed mt-5\">\n      The welcome bonus is promotional and locked until the published eligibility conditions are met. It is not immediately withdrawable. Task rewards are subject to valid submission and review.\n    </p>\n    <p class=\"text-center text-sm text-slate-400 mt-5\">Already registered? <a href=\"/dashboard.html\" class=\"text-sky-400 hover:text-sky-300\">Go to dashboard</a></p>\n  </main>\n\n  <script>\n    const form = document.getElementById(\"registerForm\");\n    const button = document.getElementById(\"submitBtn\");\n    const errorMessage = document.getElementById(\"errorMsg\");\n    const successMessage = document.getElementById(\"successMsg\");\n\n    form.addEventListener(\"submit\", async (event) => {\n      event.preventDefault();\n      errorMessage.classList.add(\"hidden\");\n      successMessage.classList.add(\"hidden\");\n\n      if (!form.reportValidity()) return;\n\n      button.disabled = true;\n      button.textContent = \"Creating your account...\";\n\n      try {\n        const response = await fetch(\"/api/register\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({\n            full_name: document.getElementById(\"fullName\").value.trim(),\n            phone_number: document.getElementById(\"phone\").value.trim(),\n            email: document.getElementById(\"email\").value.trim(),\n            password: document.getElementById(\"password\").value\n          })\n        });\n\n        const data = await response.json().catch(() => ({}));\n        if (!response.ok || !data.success || !data.userId) {\n          throw new Error(data.error || \"We couldn't create your account. Please try again.\");\n        }\n\n        localStorage.setItem(\"trainai_user_id\", data.userId);\n        successMessage.textContent = \"Account created. Opening your first survey...\";\n        successMessage.classList.remove(\"hidden\");\n        window.location.href = \"/survey.html?id=onboarding\";\n      } catch (error) {\n        errorMessage.textContent = error.message || \"Something went wrong. Please try again.\";\n        errorMessage.classList.remove(\"hidden\");\n        button.disabled = false;\n        button.textContent = \"Register & Start Survey →\";\n      }\n    });\n  </script>\n</body>\n</html>\n","dashboard.html":"<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Dashboard — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"max-w-5xl mx-auto px-6 py-4 flex justify-between items-center gap-4\">\n      <a href=\"/dashboard.html\" class=\"text-xl font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <div class=\"flex items-center gap-4\">\n        <a href=\"/wallet.html\" class=\"bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg text-sm font-medium\">Wallet</a>\n        <button type=\"button\" id=\"logoutBtn\" class=\"text-xs text-slate-400 hover:text-white\">Logout</button>\n      </div>\n    </div>\n  </nav>\n\n  <main class=\"max-w-5xl mx-auto px-6 py-10\">\n    <div class=\"mb-8\">\n      <h1 class=\"text-2xl font-bold\" id=\"welcomeText\">Welcome, Trainer</h1>\n      <p class=\"text-slate-400 text-sm mt-1\">Complete available AI surveys. Rewards are credited after valid submissions are reviewed.</p>\n    </div>\n\n    <section aria-label=\"Account summary\" class=\"grid md:grid-cols-3 gap-6 mb-10\">\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Available Balance</div>\n        <div class=\"text-3xl font-extrabold text-emerald-400 mt-2\" id=\"availBalance\">— UGX</div>\n        <a href=\"/wallet.html\" class=\"inline-block text-xs text-sky-400 mt-3 hover:underline\">Wallet and withdrawals →</a>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Locked Welcome Bonus</div>\n        <div class=\"text-3xl font-extrabold text-amber-400 mt-2\" id=\"lockedBalance\">— UGX</div>\n        <p class=\"text-xs text-slate-400 mt-3\" id=\"unlockHint\">Locked until eligibility requirements are met.</p>\n      </div>\n      <div class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n        <div class=\"text-xs text-slate-400 uppercase font-semibold\">Surveys Completed</div>\n        <div class=\"text-3xl font-extrabold text-sky-400 mt-2\" id=\"surveyCount\">—</div>\n        <div class=\"w-full bg-slate-800 h-2 rounded-full mt-3 overflow-hidden\">\n          <div id=\"progressBar\" class=\"bg-sky-400 h-full transition-all\" style=\"width:0%\"></div>\n        </div>\n      </div>\n    </section>\n\n    <section>\n      <h2 class=\"text-lg font-bold mb-4\">Available AI Training Surveys</h2>\n      <div id=\"surveyList\" class=\"grid md:grid-cols-2 gap-4\" aria-live=\"polite\">\n        <p class=\"text-slate-400 text-sm\">Loading surveys...</p>\n      </div>\n      <p id=\"pageError\" role=\"alert\" class=\"text-rose-400 text-sm mt-4 hidden\"></p>\n    </section>\n  </main>\n\n  <script>\n    const userId = localStorage.getItem(\"trainai_user_id\");\n    const surveyList = document.getElementById(\"surveyList\");\n    const pageError = document.getElementById(\"pageError\");\n\n    function logout() {\n      localStorage.removeItem(\"trainai_user_id\");\n      window.location.href = \"/index.html\";\n    }\n\n    document.getElementById(\"logoutBtn\").addEventListener(\"click\", logout);\n\n    function formatUGX(value) {\n      const amount = Number(value);\n      return (Number.isFinite(amount) ? amount : 0).toLocaleString(\"en-UG\") + \" UGX\";\n    }\n\n    function escapeHTML(value) {\n      return String(value ?? \"\").replace(/[&<>\"']/g, (char) => ({\n        \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\"\n      })[char]);\n    }\n\n    function showError(message) {\n      pageError.textContent = message;\n      pageError.classList.remove(\"hidden\");\n    }\n\n    async function loadDashboard() {\n      if (!userId) {\n        window.location.href = \"/register.html\";\n        return;\n      }\n\n      try {\n        const res = await fetch(\"/api/user?userId=\" + encodeURIComponent(userId), {\n          headers: { \"Accept\": \"application/json\" }\n        });\n        const data = await res.json().catch(() => ({}));\n\n        if (res.status === 401 || res.status === 403 || !data.success) {\n          logout();\n          return;\n        }\n        if (!res.ok) throw new Error(data.error || \"Could not load your account.\");\n\n        const user = data.user || {};\n        const surveys = Array.isArray(data.surveys) ? data.surveys : [];\n        const completedIds = Array.isArray(data.completedIds) ? data.completedIds : [];\n        const completedCount = Number(user.surveys_completed) || 0;\n\n        document.getElementById(\"welcomeText\").textContent =\n          \"Welcome, \" + (user.full_name || \"Trainer\");\n        document.getElementById(\"availBalance\").textContent =\n          formatUGX(user.available_balance_ugx);\n        document.getElementById(\"lockedBalance\").textContent =\n          formatUGX(user.locked_bonus_ugx);\n        document.getElementById(\"surveyCount\").textContent =\n          completedCount + \" / \" + surveys.length;\n\n        const progress = surveys.length\n          ? Math.min(100, Math.round((completedCount / surveys.length) * 100))\n          : 0;\n        document.getElementById(\"progressBar\").style.width = progress + \"%\";\n\n        document.getElementById(\"unlockHint\").textContent =\n          Number(user.locked_bonus_ugx) === 0\n            ? \"Your bonus has been unlocked.\"\n            : \"Bonus remains locked until the eligibility requirements are verified.\";\n\n        if (!surveys.length) {\n          surveyList.innerHTML = '<p class=\"text-slate-400 text-sm\">There are no active surveys right now. Please check again later.</p>';\n          return;\n        }\n\n        surveyList.innerHTML = surveys.map((survey) => {\n          const done = completedIds.includes(survey.id);\n          const surveyId = encodeURIComponent(String(survey.id));\n          return `\n            <article class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl flex justify-between items-center gap-4\">\n              <div class=\"min-w-0\">\n                <span class=\"text-xs font-semibold text-sky-400 uppercase\">${escapeHTML(survey.category || \"General\")}</span>\n                <h3 class=\"font-bold text-base mt-1\">${escapeHTML(survey.title || \"AI survey\")}</h3>\n                <div class=\"text-emerald-400 font-bold text-sm mt-2\">Up to ${formatUGX(survey.reward_ugx)}</div>\n                <p class=\"text-slate-500 text-xs mt-1\">Reward subject to valid completion and review.</p>\n              </div>\n              ${done\n                ? '<span class=\"shrink-0 bg-slate-800 text-slate-400 text-xs font-semibold px-4 py-2 rounded-lg\">Submitted ✓</span>'\n                : '<a href=\"/survey.html?id=' + surveyId + '\" class=\"shrink-0 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm px-5 py-2.5 rounded-lg transition\">Start</a>'\n              }\n            </article>\n          `;\n        }).join(\"\");\n      } catch (error) {\n        showError(error.message || \"Something went wrong while loading your dashboard.\");\n        surveyList.innerHTML = \"\";\n      }\n    }\n\n    loadDashboard();\n  </script>\n</body>\n</html>\n","survey.html":"<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>AI Training Survey — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-4xl items-center justify-between px-5 py-4\">\n      <a href=\"/dashboard.html\" class=\"text-sm text-sky-400 hover:underline\">← Back to Dashboard</a>\n      <span class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></span>\n    </div>\n  </nav>\n\n  <main class=\"mx-auto max-w-3xl px-4 py-8 sm:px-6\">\n    <div class=\"mb-6 flex flex-wrap items-center justify-between gap-3\">\n      <span id=\"categoryBadge\" class=\"rounded-full bg-sky-500/10 px-3 py-1 text-xs font-bold uppercase text-sky-300\">AI TRAINING</span>\n      <span id=\"rewardBadge\" class=\"rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-bold text-emerald-300\">Potential reward: — UGX</span>\n    </div>\n\n    <section class=\"rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl sm:p-8\">\n      <h1 id=\"surveyTitle\" class=\"text-2xl font-bold\">Loading survey…</h1>\n      <p id=\"surveyDescription\" class=\"mt-2 text-sm leading-6 text-slate-400\">Please wait while we load the task.</p>\n\n      <div class=\"mt-5 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-amber-200\">\n        Your answers are submitted for review. A displayed reward is not credited until the submission is checked and approved. Do not submit personal or payment details in your answers.\n      </div>\n\n      <form id=\"surveyForm\" class=\"mt-7 space-y-7\">\n        <p id=\"loadingMessage\" class=\"text-sm text-slate-400\">Loading questions…</p>\n        <div id=\"questionList\" class=\"space-y-7\"></div>\n        <p id=\"formMessage\" role=\"status\" class=\"hidden rounded-lg p-3 text-sm\"></p>\n        <button id=\"submitButton\" type=\"submit\" disabled class=\"w-full rounded-xl bg-sky-500 px-5 py-4 font-bold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50\">\n          Submit answers for review\n        </button>\n      </form>\n    </section>\n  </main>\n\n  <script>\n    const params = new URLSearchParams(window.location.search);\n    const surveyId = params.get(\"id\") || \"onboarding\";\n    const form = document.getElementById(\"surveyForm\");\n    const questionList = document.getElementById(\"questionList\");\n    const submitButton = document.getElementById(\"submitButton\");\n    const formMessage = document.getElementById(\"formMessage\");\n    let currentQuestions = [];\n\n    function showMessage(message, isError = true) {\n      formMessage.textContent = message;\n      formMessage.className = \"rounded-lg p-3 text-sm \" + (isError\n        ? \"border border-rose-500/30 bg-rose-500/10 text-rose-300\"\n        : \"border border-emerald-500/30 bg-emerald-500/10 text-emerald-300\");\n    }\n\n    function addChoice(container, questionIndex, choice, answerText) {\n      const label = document.createElement(\"label\");\n      label.className = \"flex cursor-pointer gap-3 rounded-xl border border-slate-700 bg-slate-950 p-4 transition hover:border-sky-400\";\n      const radio = document.createElement(\"input\");\n      radio.type = \"radio\";\n      radio.name = \"question_\" + questionIndex;\n      radio.value = choice;\n      radio.required = true;\n      radio.className = \"mt-1 accent-sky-400\";\n      const text = document.createElement(\"span\");\n      text.className = \"text-sm leading-6 text-slate-300\";\n      text.textContent = answerText;\n      label.append(radio, text);\n      container.append(label);\n    }\n\n    async function loadSurvey() {\n      try {\n        const response = await fetch(\"/api/user\", { credentials: \"same-origin\" });\n        const data = await response.json();\n        if (response.status === 401) {\n          window.location.href = \"/register.html\";\n          return;\n        }\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load your account.\");\n        const survey = (data.surveys || []).find(item => item.id === surveyId);\n        if (!survey) throw new Error(\"This survey is unavailable or has already been removed.\");\n\n        document.getElementById(\"surveyTitle\").textContent = survey.title;\n        document.getElementById(\"surveyDescription\").textContent = survey.description || \"Compare the two AI responses and choose the one that best answers the prompt.\";\n        document.getElementById(\"categoryBadge\").textContent = survey.category || \"AI TRAINING\";\n        document.getElementById(\"rewardBadge\").textContent = \"Potential reward: \" + Number(survey.reward_ugx).toLocaleString() + \" UGX\";\n\n        if ((data.completedIds || []).includes(surveyId)) {\n          throw new Error(\"You have already submitted this survey.\");\n        }\n\n        currentQuestions = JSON.parse(survey.questions_json || \"[]\");\n        if (!Array.isArray(currentQuestions) || currentQuestions.length === 0) {\n          throw new Error(\"This survey has no questions yet. Please check back later.\");\n        }\n\n        questionList.replaceChildren();\n        currentQuestions.forEach((item, index) => {\n          const section = document.createElement(\"section\");\n          section.className = \"border-t border-slate-800 pt-6\";\n          const heading = document.createElement(\"h2\");\n          heading.className = \"mb-4 font-semibold leading-6\";\n          heading.textContent = (index + 1) + \". \" + item.q;\n          const choices = document.createElement(\"div\");\n          choices.className = \"grid gap-3 md:grid-cols-2\";\n          addChoice(choices, index, \"A\", item.a);\n          addChoice(choices, index, \"B\", item.b);\n          section.append(heading, choices);\n          questionList.append(section);\n        });\n        document.getElementById(\"loadingMessage\").remove();\n        submitButton.disabled = false;\n      } catch (error) {\n        document.getElementById(\"loadingMessage\").textContent = error.message;\n        submitButton.classList.add(\"hidden\");\n      }\n    }\n\n    form.addEventListener(\"submit\", async event => {\n      event.preventDefault();\n      const answers = [];\n      for (let index = 0; index < currentQuestions.length; index++) {\n        const selected = form.querySelector('input[name=\"question_' + index + '\"]:checked');\n        if (!selected) {\n          showMessage(\"Please answer every question before submitting.\");\n          return;\n        }\n        answers.push({ question: index, choice: selected.value });\n      }\n\n      submitButton.disabled = true;\n      submitButton.textContent = \"Submitting for review…\";\n      formMessage.classList.add(\"hidden\");\n\n      try {\n        const response = await fetch(\"/api/submit\", {\n          method: \"POST\",\n          credentials: \"same-origin\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({ surveyId, answers })\n        });\n        const result = await response.json();\n        if (!response.ok || !result.success) throw new Error(result.error || \"Submission failed.\");\n        showMessage(result.message || \"Your answers have been submitted for review.\", false);\n        submitButton.textContent = \"Submitted\";\n        const back = document.createElement(\"a\");\n        back.href = \"/dashboard.html\";\n        back.textContent = \"Return to dashboard\";\n        back.className = \"mt-4 inline-block font-semibold text-sky-400 hover:underline\";\n        form.append(back);\n      } catch (error) {\n        showMessage(error.message);\n        submitButton.disabled = false;\n        submitButton.textContent = \"Submit answers for review\";\n      }\n    });\n\n    loadSurvey();\n  </script>\n</body>\n</html>\n","wallet.html":"<!DOCTYPE html>\n<html lang=\"en\" class=\"dark\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#020617\" />\n  <title>Wallet & Withdrawals — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"bg-slate-950 text-slate-100 min-h-screen\">\n  <nav class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"max-w-4xl mx-auto px-6 py-4 flex justify-between items-center gap-4\">\n      <a href=\"/dashboard.html\" class=\"text-sm text-sky-400 hover:underline\">← Back to Dashboard</a>\n      <span class=\"font-bold\">Trainer Wallet</span>\n    </div>\n  </nav>\n\n  <main class=\"max-w-4xl mx-auto px-6 py-10 grid md:grid-cols-2 gap-8\">\n    <section class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n      <h1 class=\"text-lg font-bold mb-1\">Request Mobile Money Withdrawal</h1>\n      <p class=\"text-xs text-slate-400 mb-6\">Minimum request: 10,000 UGX. A request is not a guaranteed or instant payout.</p>\n\n      <div class=\"bg-slate-950 p-4 rounded-xl mb-6 border border-slate-800\">\n        <div class=\"text-xs text-slate-400\">Available Balance</div>\n        <div id=\"walletBalance\" class=\"text-2xl font-extrabold text-emerald-400 mt-1\">Loading...</div>\n      </div>\n\n      <form id=\"withdrawForm\" class=\"space-y-4\">\n        <div>\n          <label for=\"network\" class=\"block text-xs text-slate-400 mb-1\">Mobile Money Network</label>\n          <select id=\"network\" required class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\">\n            <option value=\"MTN\">MTN Mobile Money</option>\n            <option value=\"AIRTEL\">Airtel Money</option>\n          </select>\n        </div>\n        <div>\n          <label for=\"payoutPhone\" class=\"block text-xs text-slate-400 mb-1\">Phone Number</label>\n          <input type=\"tel\" id=\"payoutPhone\" required autocomplete=\"tel\" inputmode=\"tel\" maxlength=\"20\" placeholder=\"0770000000\" class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\" />\n        </div>\n        <div>\n          <label for=\"amount\" class=\"block text-xs text-slate-400 mb-1\">Amount (UGX)</label>\n          <input type=\"number\" id=\"amount\" min=\"10000\" step=\"1\" required placeholder=\"10000\" class=\"w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm\" />\n        </div>\n        <p id=\"formMessage\" role=\"alert\" aria-live=\"polite\" class=\"text-sm hidden\"></p>\n        <button id=\"withdrawButton\" type=\"submit\" class=\"w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-bold py-3 rounded-lg transition\">\n          Submit Withdrawal Request\n        </button>\n      </form>\n      <p class=\"text-xs text-slate-500 leading-relaxed mt-5\">Withdrawals will only be processed when the platform's payment system is configured, funded and operational. Never pay a fee to unlock a withdrawal.</p>\n    </section>\n\n    <section class=\"bg-slate-900 border border-slate-800 p-6 rounded-2xl\">\n      <h2 class=\"text-lg font-bold mb-4\">Earnings & Transaction History</h2>\n      <div id=\"ledgerList\" class=\"space-y-3 text-sm\" aria-live=\"polite\">\n        <p class=\"text-slate-400\">Loading transactions...</p>\n      </div>\n      <p id=\"historyError\" role=\"alert\" class=\"text-rose-400 text-xs mt-4 hidden\"></p>\n    </section>\n  </main>\n\n  <script>\n    const userId = localStorage.getItem(\"trainai_user_id\");\n    const balanceElement = document.getElementById(\"walletBalance\");\n    const ledgerList = document.getElementById(\"ledgerList\");\n    const form = document.getElementById(\"withdrawForm\");\n    const submitButton = document.getElementById(\"withdrawButton\");\n    const formMessage = document.getElementById(\"formMessage\");\n    const historyError = document.getElementById(\"historyError\");\n\n    if (!userId) {\n      window.location.href = \"/register.html\";\n    }\n\n    function formatUGX(value) {\n      const amount = Number(value);\n      return (Number.isFinite(amount) ? amount : 0).toLocaleString(\"en-UG\") + \" UGX\";\n    }\n\n    function escapeHTML(value) {\n      return String(value ?? \"\").replace(/[&<>\"']/g, (char) => ({\n        \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\"\n      })[char]);\n    }\n\n    function showFormMessage(message, success) {\n      formMessage.textContent = message;\n      formMessage.className = \"text-sm \" + (success ? \"text-emerald-400\" : \"text-rose-400\");\n    }\n\n    async function loadWallet() {\n      try {\n        const res = await fetch(\"/api/user?userId=\" + encodeURIComponent(userId), {\n          headers: { \"Accept\": \"application/json\" }\n        });\n        const data = await res.json().catch(() => ({}));\n        if (res.status === 401 || res.status === 403 || !data.success) {\n          localStorage.removeItem(\"trainai_user_id\");\n          window.location.href = \"/register.html\";\n          return;\n        }\n        if (!res.ok) throw new Error(data.error || \"Unable to load wallet.\");\n\n        const user = data.user || {};\n        balanceElement.textContent = formatUGX(user.available_balance_ugx);\n        document.getElementById(\"payoutPhone\").value = user.phone_number || \"\";\n\n        const ledger = Array.isArray(data.ledger) ? data.ledger : [];\n        if (!ledger.length) {\n          ledgerList.innerHTML = '<p class=\"text-slate-400\">No transactions yet.</p>';\n          return;\n        }\n\n        ledgerList.innerHTML = ledger.map((item) => {\n          const type = item.transaction_type || item.type || \"transaction\";\n          const status = item.transaction_status || item.status || \"pending\";\n          const amount = item.amount_ugx;\n          return `\n            <div class=\"bg-slate-950 border border-slate-800 p-3 rounded-xl flex justify-between items-center gap-3\">\n              <div class=\"min-w-0\">\n                <div class=\"font-semibold text-xs\">${escapeHTML(String(type).replace(/_/g, \" \"))}</div>\n                <div class=\"text-xs text-slate-500\">${escapeHTML(status)}</div>\n              </div>\n              <div class=\"font-bold text-emerald-400 whitespace-nowrap\">${formatUGX(amount)}</div>\n            </div>\n          `;\n        }).join(\"\");\n      } catch (error) {\n        balanceElement.textContent = \"Unavailable\";\n        ledgerList.innerHTML = \"\";\n        historyError.textContent = error.message || \"Could not load transaction history.\";\n        historyError.classList.remove(\"hidden\");\n      }\n    }\n\n    form.addEventListener(\"submit\", async (event) => {\n      event.preventDefault();\n      formMessage.className = \"text-sm hidden\";\n\n      const amount = Number(document.getElementById(\"amount\").value);\n      const phone = document.getElementById(\"payoutPhone\").value.trim();\n      const network = document.getElementById(\"network\").value;\n\n      if (!Number.isSafeInteger(amount) || amount < 10000) {\n        showFormMessage(\"The minimum withdrawal request is 10,000 UGX.\", false);\n        return;\n      }\n      if (!phone) {\n        showFormMessage(\"Enter the mobile money phone number.\", false);\n        return;\n      }\n\n      submitButton.disabled = true;\n      submitButton.textContent = \"Sending request...\";\n\n      try {\n        const res = await fetch(\"/api/withdraw\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\" },\n          body: JSON.stringify({ userId, network, phone, amount })\n        });\n        const data = await res.json().catch(() => ({}));\n        if (!res.ok || !data.success) {\n          throw new Error(data.error || \"Withdrawal request could not be submitted.\");\n        }\n        showFormMessage(data.message || \"Your withdrawal request was received.\", true);\n        document.getElementById(\"amount\").value = \"\";\n        await loadWallet();\n      } catch (error) {\n        showFormMessage(error.message || \"Something went wrong. Please try again.\", false);\n      } finally {\n        submitButton.disabled = false;\n        submitButton.textContent = \"Submit Withdrawal Request\";\n      }\n    });\n\n    if (userId) loadWallet();\n  </script>\n</body>\n</html>\n","admin.html":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#0b1220\" />\n  <title>Admin Review — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <header class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-5xl items-center justify-between px-5 py-4\">\n      <a href=\"/\" class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <nav class=\"flex items-center gap-4 text-xs font-semibold\"><a href=\"/admin.html\" class=\"text-slate-300 hover:text-sky-300\">Survey review</a><a href=\"/admin-withdrawals.html\" class=\"text-sky-300 hover:text-white\">Withdrawals</a></nav>\n    </div>\n  </header>\n  <main class=\"mx-auto max-w-5xl px-4 py-8 sm:px-6\">\n    <section class=\"mb-7 rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\">\n      <h1 class=\"text-2xl font-bold\">Submission review</h1>\n      <p class=\"mt-2 text-sm leading-6 text-slate-400\">Enter the administrator key configured privately in Cloudflare. This page does not save the key in your browser.</p>\n      <form id=\"authForm\" class=\"mt-5 flex flex-col gap-3 sm:flex-row\">\n        <input id=\"adminKey\" type=\"password\" autocomplete=\"off\" required placeholder=\"Admin API key\" class=\"min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-sky-400\" />\n        <button class=\"rounded-xl bg-sky-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-sky-400\" type=\"submit\">Load submissions</button>\n      </form>\n      <p id=\"status\" role=\"status\" class=\"mt-3 text-sm text-slate-400\">Admin access is required.</p>\n    </section>\n    <div class=\"mb-4 flex items-center justify-between\">\n      <h2 class=\"text-lg font-bold\">Pending submissions</h2>\n      <button id=\"refreshButton\" type=\"button\" class=\"hidden rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-sky-400\">Refresh</button>\n    </div>\n    <section id=\"submissionList\" class=\"space-y-5\"></section>\n    <p class=\"mt-8 text-xs leading-5 text-slate-500\">Approve only after checking the submitted answers. Approval credits the survey reward once. Rejection does not credit a reward. The third approved task automatically unlocks the 5,000 UGX welcome bonus.</p>\n  </main>\n\n  <script>\n    let adminKey = \"\";\n    const list = document.getElementById(\"submissionList\");\n    const statusLine = document.getElementById(\"status\");\n    const refreshButton = document.getElementById(\"refreshButton\");\n\n    function node(tag, className, text) {\n      const element = document.createElement(tag);\n      if (className) element.className = className;\n      if (text !== undefined) element.textContent = text;\n      return element;\n    }\n\n    function setStatus(message, error = false) {\n      statusLine.textContent = message;\n      statusLine.className = \"mt-3 text-sm \" + (error ? \"text-rose-300\" : \"text-slate-400\");\n    }\n\n    async function loadSubmissions() {\n      if (!adminKey) return;\n      setStatus(\"Loading pending submissions…\");\n      refreshButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/review\", {\n          headers: { \"Authorization\": \"Bearer \" + adminKey },\n          cache: \"no-store\"\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load submissions.\");\n        list.replaceChildren();\n        const submissions = data.submissions || [];\n        if (!submissions.length) {\n          list.append(node(\"div\", \"rounded-2xl border border-slate-800 bg-slate-900 p-6 text-sm text-slate-400\", \"There are no pending submissions.\"));\n        }\n        submissions.forEach(item => renderSubmission(item));\n        setStatus(submissions.length + \" pending submission(s) loaded.\");\n        refreshButton.classList.remove(\"hidden\");\n      } catch (error) {\n        setStatus(error.message, true);\n        if (responseUnauthorized(error)) {\n          adminKey = \"\";\n          document.getElementById(\"adminKey\").value = \"\";\n        }\n      } finally {\n        refreshButton.disabled = false;\n      }\n    }\n\n    function responseUnauthorized(error) {\n      return /key is missing or incorrect/i.test(error.message);\n    }\n\n    function renderSubmission(item) {\n      const card = node(\"article\", \"rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\");\n      const top = node(\"div\", \"flex flex-wrap items-start justify-between gap-3\");\n      const details = node(\"div\", \"min-w-0\");\n      details.append(\n        node(\"h3\", \"text-lg font-bold\", item.survey_title || \"Survey\"),\n        node(\"p\", \"mt-1 text-sm text-slate-400\", (item.full_name || \"User\") + \" · \" + (item.email || \"No email\")),\n        node(\"p\", \"mt-1 text-xs text-slate-500\", \"Submitted: \" + (item.submitted_at || \"Unknown\"))\n      );\n      top.append(details, node(\"span\", \"rounded-full bg-emerald-500/10 px-3 py-1 text-sm font-semibold text-emerald-300\", Number(item.reward_ugx || 0).toLocaleString() + \" UGX potential reward\"));\n      card.append(top);\n\n      let questions = [];\n      let answers = [];\n      try { questions = JSON.parse(item.questions_json || \"[]\"); } catch {}\n      try { answers = JSON.parse(item.answers_json || \"[]\"); } catch {}\n      const answerBlock = node(\"div\", \"mt-5 space-y-4\");\n      questions.forEach((question, index) => {\n        const answer = answers.find(entry => entry.question === index);\n        const chosen = answer?.choice;\n        const chosenText = chosen === \"A\" ? question.a : chosen === \"B\" ? question.b : chosen === \"TIE\" ? \"Tie selected\" : \"No valid answer recorded\";\n        const section = node(\"div\", \"rounded-xl border border-slate-800 bg-slate-950 p-4\");\n        section.append(\n          node(\"p\", \"text-sm font-semibold text-slate-200\", (index + 1) + \". \" + (question.q || \"Question\")),\n          node(\"p\", \"mt-2 text-sm leading-6 text-sky-200\", \"Selected \" + (chosen || \"—\") + \": \" + chosenText)\n        );\n        answerBlock.append(section);\n      });\n      card.append(answerBlock);\n\n      const actions = node(\"div\", \"mt-5 flex flex-wrap gap-3\");\n      const approve = node(\"button\", \"rounded-xl bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-400 disabled:opacity-50\", \"Approve and credit reward\");\n      const reject = node(\"button\", \"rounded-xl border border-rose-500/40 px-5 py-3 text-sm font-semibold text-rose-300 hover:bg-rose-500/10 disabled:opacity-50\", \"Reject\");\n      approve.type = reject.type = \"button\";\n      approve.addEventListener(\"click\", () => review(item.id, \"approve\", approve, reject));\n      reject.addEventListener(\"click\", () => review(item.id, \"reject\", approve, reject));\n      actions.append(approve, reject);\n      card.append(actions);\n      list.append(card);\n    }\n\n    async function review(responseId, decision, approveButton, rejectButton) {\n      const promptText = decision === \"approve\"\n        ? \"Approve this submission and credit its survey reward?\"\n        : \"Reject this submission? No reward will be credited.\";\n      if (!window.confirm(promptText)) return;\n      approveButton.disabled = rejectButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/review\", {\n          method: \"POST\",\n          headers: { \"Content-Type\": \"application/json\", \"Authorization\": \"Bearer \" + adminKey },\n          body: JSON.stringify({ responseId, decision })\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Review failed.\");\n        setStatus(data.message || \"Review completed.\");\n        await loadSubmissions();\n      } catch (error) {\n        setStatus(error.message, true);\n        approveButton.disabled = rejectButton.disabled = false;\n      }\n    }\n\n    document.getElementById(\"authForm\").addEventListener(\"submit\", event => {\n      event.preventDefault();\n      adminKey = document.getElementById(\"adminKey\").value.trim();\n      loadSubmissions();\n    });\n    refreshButton.addEventListener(\"click\", loadSubmissions);\n  </script>\n</body>\n</html>\n","admin-withdrawals.html":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#0b1220\" />\n  <title>Withdrawal Review — TrainAI Uganda</title>\n  <script src=\"https://cdn.tailwindcss.com\"></script>\n</head>\n<body class=\"min-h-screen bg-slate-950 text-slate-100\">\n  <header class=\"border-b border-slate-800 bg-slate-900\">\n    <div class=\"mx-auto flex max-w-5xl items-center justify-between px-5 py-4\">\n      <a href=\"/admin.html\" class=\"font-bold text-sky-400\">TrainAI<span class=\"text-white\">.ug</span></a>\n      <span class=\"text-xs font-semibold uppercase tracking-wider text-slate-400\">Withdrawal administration</span>\n    </div>\n  </header>\n\n  <main class=\"mx-auto max-w-5xl px-4 py-8 sm:px-6\">\n    <section class=\"mb-7 rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\">\n      <h1 class=\"text-2xl font-bold\">Withdrawal requests</h1>\n      <p class=\"mt-2 text-sm leading-6 text-slate-400\">\n        Enter the private administrator key. This page does not save it in your browser.\n        Verify each transfer in your Mobile Money account before marking it paid.\n      </p>\n      <form id=\"authForm\" class=\"mt-5 flex flex-col gap-3 sm:flex-row\">\n        <input id=\"adminKey\" type=\"password\" autocomplete=\"off\" required placeholder=\"Admin API key\"\n          class=\"min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-sky-400\" />\n        <button class=\"rounded-xl bg-sky-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-sky-400\" type=\"submit\">Load requests</button>\n      </form>\n      <p id=\"status\" role=\"status\" class=\"mt-3 text-sm text-slate-400\">Admin access is required.</p>\n    </section>\n\n    <div class=\"mb-4 flex items-center justify-between gap-3\">\n      <h2 class=\"text-lg font-bold\">Pending withdrawals</h2>\n      <button id=\"refreshButton\" type=\"button\" class=\"hidden rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-sky-400\">Refresh</button>\n    </div>\n    <section id=\"withdrawalList\" class=\"space-y-4\"></section>\n    <p class=\"mt-8 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-amber-200\">\n      Important: marking a request as paid only updates your app records. It does not send Mobile Money.\n      Send the payment manually through the correct MTN or Airtel channel, confirm success, then mark it paid.\n      Rejecting a request automatically refunds the amount to the user's available wallet balance.\n    </p>\n  </main>\n\n  <script>\n    let adminKey = \"\";\n    const list = document.getElementById(\"withdrawalList\");\n    const statusLine = document.getElementById(\"status\");\n    const refreshButton = document.getElementById(\"refreshButton\");\n\n    function node(tag, className, text) {\n      const element = document.createElement(tag);\n      if (className) element.className = className;\n      if (text !== undefined) element.textContent = text;\n      return element;\n    }\n\n    function setStatus(message, error = false) {\n      statusLine.textContent = message;\n      statusLine.className = \"mt-3 text-sm \" + (error ? \"text-rose-300\" : \"text-slate-400\");\n    }\n\n    async function loadWithdrawals() {\n      if (!adminKey) return;\n      setStatus(\"Loading pending withdrawals…\");\n      refreshButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/withdrawals\", {\n          headers: { \"Authorization\": \"Bearer \" + adminKey },\n          cache: \"no-store\"\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not load withdrawals.\");\n        list.replaceChildren();\n        const withdrawals = data.withdrawals || [];\n        if (!withdrawals.length) {\n          list.append(node(\"div\", \"rounded-2xl border border-slate-800 bg-slate-900 p-6 text-sm text-slate-400\", \"There are no pending withdrawal requests.\"));\n        }\n        withdrawals.forEach(renderWithdrawal);\n        setStatus(withdrawals.length + \" pending withdrawal(s) loaded.\");\n        refreshButton.classList.remove(\"hidden\");\n      } catch (error) {\n        setStatus(error.message, true);\n        if (/key is missing or incorrect/i.test(error.message)) {\n          adminKey = \"\";\n          document.getElementById(\"adminKey\").value = \"\";\n        }\n      } finally {\n        refreshButton.disabled = false;\n      }\n    }\n\n    function renderWithdrawal(item) {\n      const card = node(\"article\", \"rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-6\");\n      const top = node(\"div\", \"flex flex-wrap items-start justify-between gap-3\");\n      const info = node(\"div\", \"min-w-0\");\n      info.append(\n        node(\"h3\", \"text-lg font-bold\", (item.full_name || \"User\") + \" · \" + (item.email || \"No email\")),\n        node(\"p\", \"mt-1 text-sm text-slate-400\", \"Requested: \" + (item.created_at || \"Unknown\")),\n        node(\"p\", \"mt-1 text-xs text-slate-500 break-all\", \"Request ID: \" + item.id)\n      );\n      top.append(\n        info,\n        node(\"span\", \"rounded-full bg-amber-500/10 px-3 py-1 text-sm font-bold text-amber-300\",\n          Number(item.amount_ugx || 0).toLocaleString() + \" UGX\")\n      );\n      card.append(top);\n\n      const destination = node(\"div\", \"mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4\");\n      destination.append(\n        node(\"p\", \"text-xs uppercase tracking-wider text-slate-500\", \"Payment destination\"),\n        node(\"p\", \"mt-1 text-base font-bold\", item.mobile_money_network + \" Money\"),\n        node(\"p\", \"mt-1 text-lg font-semibold text-sky-200\", item.mobile_money_number)\n      );\n      card.append(destination);\n\n      const actions = node(\"div\", \"mt-5 flex flex-wrap gap-3\");\n      const paid = node(\"button\", \"rounded-xl bg-emerald-500 px-5 py-3 text-sm font-bold text-slate-950 hover:bg-emerald-400 disabled:opacity-50\", \"Mark paid\");\n      const reject = node(\"button\", \"rounded-xl border border-rose-500/40 px-5 py-3 text-sm font-semibold text-rose-300 hover:bg-rose-500/10 disabled:opacity-50\", \"Reject and refund\");\n      paid.type = reject.type = \"button\";\n      paid.addEventListener(\"click\", () => processWithdrawal(item, \"paid\", paid, reject));\n      reject.addEventListener(\"click\", () => processWithdrawal(item, \"reject\", paid, reject));\n      actions.append(paid, reject);\n      card.append(actions);\n      list.append(card);\n    }\n\n    async function processWithdrawal(item, decision, paidButton, rejectButton) {\n      const message = decision === \"paid\"\n        ? \"Only continue if you have already sent and confirmed \" + Number(item.amount_ugx).toLocaleString() + \" UGX to \" + item.mobile_money_network + \" number \" + item.mobile_money_number + \". Mark this request as paid?\"\n        : \"Reject this withdrawal? \" + Number(item.amount_ugx).toLocaleString() + \" UGX will be refunded to the user's available wallet balance.\";\n      if (!window.confirm(message)) return;\n\n      paidButton.disabled = rejectButton.disabled = true;\n      try {\n        const response = await fetch(\"/api/admin/withdrawals\", {\n          method: \"POST\",\n          headers: {\n            \"Content-Type\": \"application/json\",\n            \"Authorization\": \"Bearer \" + adminKey\n          },\n          body: JSON.stringify({ withdrawalId: item.id, decision })\n        });\n        const data = await response.json();\n        if (!response.ok || !data.success) throw new Error(data.error || \"Could not process withdrawal.\");\n        setStatus(data.message || \"Withdrawal processed.\");\n        await loadWithdrawals();\n      } catch (error) {\n        setStatus(error.message, true);\n        paidButton.disabled = rejectButton.disabled = false;\n      }\n    }\n\n    document.getElementById(\"authForm\").addEventListener(\"submit\", event => {\n      event.preventDefault();\n      adminKey = document.getElementById(\"adminKey\").value.trim();\n      loadWithdrawals();\n    });\n    refreshButton.addEventListener(\"click\", loadWithdrawals);\n  </script>\n</body>\n</html>\n"};
const APP_SHELL = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<meta name=\"theme-color\" content=\"#131314\">\n<meta name=\"description\" content=\"TrainAI Uganda — review AI responses, complete language tasks and track approved rewards in UGX.\">\n<title>TrainAI.ug — AI contributor workspace</title>\n<style>\n:root{color-scheme:dark;--bg:#131314;--surface:#1e1f20;--surface2:#282a2c;--line:#333537;--muted:#a1a1aa;--text:#e3e3e3;--blue:#a8c7fa;--green:#81c995;--amber:#fdd663;--red:#f28b82;--grad:linear-gradient(135deg,#4285f4,#9b72cb,#d96570)}\n*{box-sizing:border-box}html{background:var(--bg);scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}a{color:inherit;text-decoration:none}button,input,textarea,select{font:inherit}button,a,input,textarea,select{outline-offset:3px}button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--blue)}button{cursor:pointer}.hidden{display:none!important}.muted{color:var(--muted)}.small{font-size:12px}.tiny{font-size:10px}.wrap{max-width:1200px;margin:auto;padding:28px 32px}.shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:248px;background:#131314;border-right:1px solid var(--line);padding:24px 16px;display:flex;flex-direction:column;z-index:30}.brand{font-size:22px;font-weight:800;letter-spacing:-.7px;padding:0 12px 30px}.brand b{color:var(--blue)}.nav-label{padding:0 12px 10px;color:#777;font-size:10px;letter-spacing:1.8px;font-weight:800;text-transform:uppercase}.nav-list{display:grid;gap:5px}.nav-link{display:flex;align-items:center;gap:13px;padding:11px 13px;border-radius:13px;color:#c2c5c9;font-size:13px;font-weight:600;transition:.18s}.nav-link:hover,.nav-link.active{background:var(--surface2);color:var(--blue)}.nav-icon{width:20px;text-align:center;font-size:17px}.sidebar-foot{margin-top:auto;border:1px solid var(--line);background:var(--surface);border-radius:17px;padding:15px}.ai-badge{display:inline-flex;align-items:center;gap:7px;border:1px solid #a8c7fa40;background:linear-gradient(110deg,#4285f420,#9b72cb20,#d9657020);color:var(--blue);border-radius:99px;padding:6px 11px;font-size:10px;font-weight:800;letter-spacing:.5px}.main{margin-left:248px;min-height:100vh}.topbar{height:70px;position:sticky;top:0;z-index:20;background:#131314ed;backdrop-filter:blur(18px);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 32px}.top-brand{display:none;font-weight:800;color:var(--blue)}.balance-pill{display:inline-flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--line);padding:8px 13px;border-radius:99px;font-size:12px;font-weight:700}.balance-pill strong{color:var(--green);font-variant-numeric:tabular-nums}.user-menu{display:flex;align-items:center;gap:12px}.avatar{width:32px;height:32px;border-radius:50%;background:#30343a;color:var(--blue);display:grid;place-items:center;font-size:12px;font-weight:800}.mobile-nav{display:none}.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:5px 0 26px}.eyebrow{font-size:10px;font-weight:800;letter-spacing:1.7px;text-transform:uppercase;color:var(--blue)}h1{font-size:31px;line-height:1.15;letter-spacing:-1.1px;margin:8px 0 8px}h2{font-size:18px;letter-spacing:-.3px;margin:0 0 14px}h3{font-size:15px;margin:0 0 7px}.lead{color:var(--muted);max-width:690px;font-size:14px}.surface{background:var(--surface);border:1px solid var(--line);border-radius:22px}.surface-pad{padding:22px}.grid{display:grid;gap:16px}.grid.two{grid-template-columns:1.2fr .8fr}.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}.metric{padding:22px}.metric-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px}.metric-value{font-size:29px;font-weight:800;letter-spacing:-1px;margin:8px 0 4px;font-variant-numeric:tabular-nums}.green{color:var(--green)}.amber{color:var(--amber)}.blue{color:var(--blue)}.muted-line{border-top:1px solid var(--line);margin:18px 0}.btn{border:0;border-radius:999px;padding:11px 17px;font-weight:750;font-size:12px;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.18s}.btn-primary{background:var(--blue);color:#111820}.btn-primary:hover{background:#c5d8fa;transform:translateY(-1px)}.btn-secondary{background:var(--surface2);border:1px solid var(--line);color:var(--text)}.btn-secondary:hover{border-color:#69717a}.btn-quiet{background:transparent;color:var(--blue);padding:8px 10px}.btn:disabled{opacity:.42;cursor:not-allowed;transform:none}.progress{height:8px;border-radius:20px;background:#3b3d40;overflow:hidden}.progress>span{display:block;height:100%;background:var(--green);border-radius:20px;transition:width .35s}.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:13px}.step{background:var(--surface);border:1px solid var(--line);border-radius:19px;padding:19px}.step-num{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:#a8c7fa1a;color:var(--blue);font-weight:800;font-size:12px;margin-bottom:13px}.hero{padding:42px;border-radius:28px;border:1px solid #a8c7fa30;background:radial-gradient(ellipse at 90% 0%,#4285f426,transparent 44%),radial-gradient(ellipse at 10% 100%,#9b72cb18,transparent 45%),var(--surface)}.hero h1{font-size:clamp(34px,5vw,54px);max-width:750px;line-height:1.08;margin:20px 0 14px}.gradient-text{background:var(--grad);background-clip:text;color:transparent}.hero .lead{font-size:16px;line-height:1.7}.trust-row{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:18px}.trust{border:1px solid var(--line);border-radius:16px;padding:15px;background:#1a1b1c}.trust strong{display:block;font-size:15px;margin-bottom:3px}.trust span{font-size:11px;color:var(--muted)}.faq details{border-bottom:1px solid var(--line);padding:15px 0}.faq summary{cursor:pointer;font-weight:700;font-size:13px;list-style:none}.faq summary::-webkit-details-marker{display:none}.faq details p{font-size:12px;color:var(--muted);line-height:1.7;margin:10px 0 0}.tag{display:inline-flex;align-items:center;border-radius:99px;padding:5px 9px;font-size:10px;font-weight:750;background:#282a2c;color:#c9cdd2;border:1px solid #3a3d40}.tag.green{background:#81c99515;color:var(--green);border-color:#81c99530}.tag.amber{background:#fdd66315;color:var(--amber);border-color:#fdd66330}.tag.blue{background:#a8c7fa15;color:var(--blue);border-color:#a8c7fa30}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}.filter{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:99px;padding:8px 13px;font-size:11px;font-weight:700}.filter.active{color:var(--blue);border-color:#a8c7fa55;background:#a8c7fa12}.task-card{padding:19px}.task-meta{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0 15px}.response{background:#18191a;border:1px solid #3b3e41;border-radius:17px;padding:17px;margin-top:12px}.response p{font-size:13px;color:#c9cdd1;white-space:pre-wrap}.choice-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px}.choice{background:var(--surface2);border:1px solid var(--line);color:#d5d9de;border-radius:12px;padding:10px 8px;font-size:11px;font-weight:700}.choice.selected{border-color:var(--blue);background:#a8c7fa17;color:var(--blue)}.field{display:grid;gap:7px;margin:13px 0}.field label{font-size:11px;color:#c3c7cb;font-weight:700}.field input,.field textarea,.field select{width:100%;border:1px solid var(--line);background:#18191a;border-radius:12px;color:var(--text);padding:12px 13px;font-size:13px}.field textarea{min-height:115px;resize:vertical}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 13px}.table-wrap{overflow:auto}.ledger{width:100%;border-collapse:collapse;min-width:590px}.ledger th,.ledger td{text-align:left;border-bottom:1px solid var(--line);padding:13px 12px;font-size:11px}.ledger th{color:#92979d;font-size:10px;text-transform:uppercase;letter-spacing:.8px}.ledger td strong{font-size:12px}.empty{padding:35px 15px;text-align:center;color:var(--muted);font-size:13px}.toast{position:fixed;right:22px;bottom:22px;z-index:80;background:#242629;border:1px solid #a8c7fa55;border-radius:16px;padding:14px 17px;box-shadow:0 14px 50px #0008;font-size:12px;max-width:330px}.modal-backdrop{position:fixed;inset:0;background:#0009;z-index:70;display:grid;place-items:center;padding:18px}.modal{width:min(480px,100%);background:var(--surface);border:1px solid var(--line);border-radius:23px;padding:23px;max-height:90vh;overflow:auto}.skeleton{background:linear-gradient(90deg,#242628 25%,#303336 45%,#242628 65%);background-size:220% 100%;animation:shimmer 1.2s infinite;border-radius:12px}@keyframes shimmer{to{background-position:-220% 0}}.loading-line{height:16px;margin:10px 0}.chat-fab{position:fixed;right:22px;bottom:24px;z-index:50;border:1px solid #a8c7fa66;background:#25282c;color:var(--blue);border-radius:99px;padding:12px 17px;font-weight:800;font-size:12px;box-shadow:0 8px 35px #0008}.chat-drawer{position:fixed;right:20px;bottom:82px;width:min(370px,calc(100vw - 30px));max-height:72vh;overflow:auto;z-index:60;background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:18px;box-shadow:0 18px 60px #0009}.quick-reply{display:block;width:100%;text-align:left;border:1px solid var(--line);background:#252729;color:#d8dce0;border-radius:12px;padding:10px;margin:7px 0;font-size:11px}.notice{padding:13px 15px;border:1px solid #fdd66340;background:#fdd6630b;color:#e9d58b;border-radius:14px;font-size:11px;line-height:1.6}.notice.success{border-color:#81c99540;background:#81c9950b;color:var(--green)}.auth-wrap{min-height:calc(100vh - 70px);display:grid;place-items:center;padding:25px}.auth-card{width:min(450px,100%);padding:26px}.brand-mark{height:42px;width:42px;border-radius:14px;background:var(--blue);color:#111820;display:grid;place-items:center;font-size:20px;font-weight:900}.right{margin-left:auto}.footer-note{color:#767b81;font-size:10px;line-height:1.6;margin-top:25px}\n@media(max-width:900px){.sidebar{width:218px}.main{margin-left:218px}.grid.two{grid-template-columns:1fr}.wrap{padding:25px 22px}.topbar{padding:0 22px}}\n@media(max-width:639px){body{padding-bottom:calc(72px + env(safe-area-inset-bottom))}.sidebar{display:none}.main{margin:0}.topbar{height:60px;padding:0 16px}.top-brand{display:block}.topbar .top-context{display:none}.wrap{padding:22px 16px}.page-head{align-items:flex-start;flex-direction:column;margin-bottom:20px}h1{font-size:27px}.hero{padding:25px 20px;border-radius:23px}.hero h1{font-size:35px}.steps{grid-template-columns:1fr}.trust-row{grid-template-columns:1fr}.grid.three{grid-template-columns:1fr 1fr}.metric{padding:17px}.metric-value{font-size:23px}.mobile-nav{position:fixed;display:grid;grid-template-columns:repeat(4,1fr);left:0;right:0;bottom:0;padding:8px 5px calc(8px + env(safe-area-inset-bottom));background:#171819f5;border-top:1px solid var(--line);backdrop-filter:blur(20px);z-index:40}.mobile-nav a{display:grid;justify-items:center;gap:3px;padding:6px 2px;border-radius:12px;color:#999da3;font-size:9px;font-weight:700}.mobile-nav a.active{color:var(--blue);background:#a8c7fa10}.mobile-nav i{font-style:normal;font-size:17px}.chat-fab{right:12px;bottom:calc(82px + env(safe-area-inset-bottom));padding:10px 13px}.chat-drawer{right:10px;bottom:calc(137px + env(safe-area-inset-bottom))}.toast{right:10px;left:10px;bottom:calc(80px + env(safe-area-inset-bottom));max-width:none}.choice-row{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.auth-wrap{min-height:calc(100vh - 130px);padding:15px}.auth-card{padding:21px}}\n@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}\n</style>\n</head>\n<body>\n<div class=\"shell\">\n<aside class=\"sidebar\" id=\"sidebar\">\n<a class=\"brand\" href=\"/\">TrainAI<b>.ug</b></a>\n<div class=\"nav-label\">Workspace</div>\n<nav class=\"nav-list\" id=\"sideNav\">\n<a class=\"nav-link\" data-route=\"/\" href=\"/\"><span class=\"nav-icon\">⌂</span>Home</a>\n<a class=\"nav-link\" data-route=\"/dashboard\" href=\"/dashboard\"><span class=\"nav-icon\">▦</span>Dashboard</a>\n<a class=\"nav-link\" data-route=\"/tasks\" href=\"/tasks\"><span class=\"nav-icon\">✧</span>AI Tasks <span class=\"tag blue\" id=\"taskBadge\">—</span></a>\n<a class=\"nav-link\" data-route=\"/statements\" href=\"/statements\"><span class=\"nav-icon\">▤</span>Statements</a>\n<a class=\"nav-link\" data-route=\"/referrals\" href=\"/referrals\"><span class=\"nav-icon\">♧</span>Referrals</a>\n<a class=\"nav-link\" data-route=\"/support\" href=\"/support\"><span class=\"nav-icon\">◌</span>Support</a>\n<a class=\"nav-link\" data-route=\"/profile\" href=\"/profile\"><span class=\"nav-icon\">⚙</span>Settings & account</a>\n</nav>\n<div class=\"sidebar-foot\"><span class=\"ai-badge\">✦ AI CONTRIBUTOR</span><p style=\"font-size:13px;font-weight:750;margin:12px 0 3px\">Your work matters.</p><p class=\"muted small\" style=\"margin:0\">Thoughtful human feedback helps improve AI systems.</p></div>\n</aside>\n<div class=\"main\">\n<header class=\"topbar\">\n<a class=\"top-brand\" href=\"/\">TrainAI.ug</a>\n<div class=\"top-context muted small\">Contributor workspace</div>\n<div class=\"user-menu\">\n<a class=\"balance-pill\" href=\"/statements\"><span class=\"muted\">Available</span><strong id=\"topBalance\">— UGX</strong></a>\n<a class=\"avatar\" href=\"/profile\" id=\"userAvatar\" aria-label=\"My account\">TA</a>\n</div>\n</header>\n<main class=\"wrap\" id=\"view\"><div class=\"surface surface-pad\"><div class=\"skeleton loading-line\" style=\"width:40%\"></div><div class=\"skeleton loading-line\" style=\"width:80%;height:30px\"></div><div class=\"skeleton loading-line\" style=\"width:65%\"></div></div></main>\n</div>\n<nav class=\"mobile-nav\" id=\"mobileNav\">\n<a data-route=\"/dashboard\" href=\"/dashboard\"><i>⌂</i>Dashboard</a>\n<a data-route=\"/tasks\" href=\"/tasks\"><i>✧</i>Tasks</a>\n<a data-route=\"/statements\" href=\"/statements\"><i>▤</i>Statements</a>\n<a data-route=\"/support\" href=\"/support\"><i>◌</i>Support</a>\n</nav>\n</div>\n<button class=\"chat-fab\" id=\"chatFab\" type=\"button\">✦ Help</button>\n<div class=\"chat-drawer hidden\" id=\"chatDrawer\">\n<div style=\"display:flex;align-items:center;justify-content:space-between\"><strong>TrainAI Help</strong><button class=\"btn btn-quiet\" id=\"chatClose\" type=\"button\">Close ×</button></div>\n<p class=\"muted small\">Quick answers and support for your account.</p>\n<button class=\"quick-reply\" data-help=\"Check my payout status\">Check my payout status</button>\n<button class=\"quick-reply\" data-help=\"Why is my task still in review?\">Why is my task still in review?</button>\n<button class=\"quick-reply\" data-help=\"How to unlock 5,000 UGX bonus\">How to unlock 5,000 UGX bonus</button>\n<div id=\"chatAnswer\" class=\"muted small\" style=\"line-height:1.7;margin:12px 0\"></div>\n<a class=\"btn btn-secondary\" href=\"/support\" style=\"width:100%\">Create a support ticket</a>\n</div>\n<div id=\"modalRoot\"></div><div id=\"toastRoot\" aria-live=\"polite\"></div>\n<script>\n(function(){\n\"use strict\";\nconst MIN_PAYOUT=25000, BONUS=5000;\nconst state={user:null,surveys:[],completedIds:[],ledger:[],tickets:[],route:location.pathname,task:null,attemptId:null,taskStartedAt:0,answers:{},filter:\"All\",ledgerFilter:\"All\",authenticated:false};\nconst view=document.getElementById(\"view\");\nconst fmt=n=>Number(n||0).toLocaleString(\"en-UG\")+\" UGX\";\nconst esc=s=>String(s??\"\").replace(/[&<>\"']/g,c=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#39;\"}[c]));\nconst json=async(url,options={})=>{const r=await fetch(url,{credentials:\"same-origin\",cache:\"no-store\",...options,headers:{\"Content-Type\":\"application/json\",...(options.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok||d.success===false)throw new Error(d.error||\"Request failed. Please try again.\");return d};\nconst post=(url,body)=>json(url,{method:\"POST\",body:JSON.stringify(body)});\nfunction toast(message){const root=document.getElementById(\"toastRoot\");root.innerHTML='<div class=\"toast\">✦ '+esc(message)+'</div>';setTimeout(()=>{root.innerHTML=\"\"},3800)}\nfunction activeRoute(){const p=location.pathname.replace(/\\/+$/,\"\")||\"/\";const aliases={\"/index.html\":\"/\",\"/dashboard.html\":\"/dashboard\",\"/survey.html\":\"/tasks\",\"/wallet.html\":\"/statements\",\"/register.html\":\"/auth\"};return aliases[p]||p}\nfunction updateNav(){const route=activeRoute();document.querySelectorAll(\"[data-route]\").forEach(a=>a.classList.toggle(\"active\",a.dataset.route===route));}\nfunction setBalance(){const amount=state.user?.available_balance_ugx;document.getElementById(\"topBalance\").textContent=state.user?fmt(amount):\"Sign in\";document.getElementById(\"userAvatar\").textContent=state.user?.full_name?state.user.full_name.split(/\\s+/).map(x=>x[0]).join(\"\").slice(0,2).toUpperCase():\"TA\";document.getElementById(\"taskBadge\").textContent=state.surveys.filter(s=>!state.completedIds.includes(s.id)).length||\"0\";}\nasync function loadData(){try{const d=await json(\"/api/user\");state.user=d.user;state.surveys=d.surveys||[];state.completedIds=d.completedIds||[];state.ledger=d.ledger||[];state.authenticated=true;setBalance();return true}catch(e){state.user=null;state.authenticated=false;setBalance();return false}}\nfunction shellHead(kicker,title,sub,action){return '<div class=\"page-head\"><div><div class=\"eyebrow\">'+kicker+'</div><h1>'+title+'</h1><div class=\"lead\">'+sub+'</div></div>'+(action||\"\")+'</div>'}\nfunction statusTag(s){const x=String(s||\"pending\").toLowerCase();const cls=[\"approved\",\"completed\",\"paid\"].includes(x)?\"green\":[\"pending\",\"in_review\",\"processing\"].includes(x)?\"amber\":\"blue\";return '<span class=\"tag '+cls+'\">'+esc(x.replace(/_/g,\" \"))+'</span>'}\nfunction renderHome(){view.innerHTML='<section class=\"hero\"><span class=\"ai-badge\">✦ 5,000 UGX STARTER BONUS RESERVED</span><h1>Help make AI <span class=\"gradient-text\">more useful for everyone.</span></h1><p class=\"lead\">Review AI responses, check local-language translations and complete short feedback tasks. Track every approved reward in your UGX wallet.</p><div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:23px\"><a class=\"btn btn-primary\" href=\"/auth\">Create free account →</a><a class=\"btn btn-secondary\" href=\"#how\">How it works</a></div><p class=\"muted small\" style=\"margin-top:17px\">Complete 3 approved tasks to unlock your reserved 5,000 UGX welcome bonus.</p></section><section style=\"margin-top:30px\" id=\"how\"><h2>Three simple steps</h2><div class=\"steps\"><article class=\"step\"><div class=\"step-num\">1</div><h3>Create a free account</h3><p class=\"muted small\">Register with your details and secure your account.</p></article><article class=\"step\"><div class=\"step-num\">2</div><h3>Review AI responses</h3><p class=\"muted small\">Compare answers, check translations and submit thoughtful feedback.</p></article><article class=\"step\"><div class=\"step-num\">3</div><h3>Request your payout</h3><p class=\"muted small\">Build at least 25,000 UGX in approved available rewards, then request a manual Mobile Money payout.</p></article></div></section><section style=\"margin-top:28px\"><h2>Clear payout information</h2><div class=\"trust-row\"><div class=\"trust\"><strong>MTN MoMo</strong><span>Manual payout requests supported</span></div><div class=\"trust\"><strong>Airtel Money</strong><span>Manual payout requests supported</span></div><div class=\"trust\"><strong>25,000 UGX</strong><span>Minimum withdrawal request</span></div></div><p class=\"notice\" style=\"margin-top:13px\">Payout requests are reviewed and processed manually. TrainAI does not currently send automatic Mobile Money transfers. No payout is marked paid until a transfer is confirmed.</p></section><section class=\"surface surface-pad faq\" style=\"margin-top:28px\"><h2>Frequently asked questions</h2><details><summary>How does my 5,000 UGX welcome bonus unlock?</summary><p>Your bonus starts locked. After 3 of your submitted tasks have been approved, the system moves the 5,000 UGX into your available wallet automatically. Pending or rejected tasks do not count.</p></details><details><summary>Why is the minimum withdrawal 25,000 UGX?</summary><p>Requests can be submitted once your approved available balance reaches 25,000 UGX. You must save and lock a correct Mobile Money destination first.</p></details><details><summary>How are my AI ratings reviewed?</summary><p>Submissions are checked by an administrator. Only approved submissions receive the displayed task reward. Rejected submissions do not earn a reward.</p></details><details><summary>Does TrainAI send money automatically?</summary><p>No. The current process queues requests for manual processing. The website records a payment as paid only after an administrator confirms the transfer.</p></details></section><p class=\"footer-note\">Rewards are conditional on valid work and review. The welcome bonus is promotional, locked until eligibility is met, and is not guaranteed income.</p>';}\nfunction renderAuth(){view.innerHTML='<div class=\"auth-wrap\"><section class=\"surface auth-card\"><div class=\"brand-mark\">T</div><div class=\"eyebrow\" style=\"margin-top:17px\">WELCOME TO TRAINAI.UG</div><h1 style=\"font-size:27px\">Your AI contributor account</h1><p class=\"muted small\">Sign in or create a free account to continue.</p><div class=\"filters\"><button class=\"filter active\" id=\"tabLogin\" type=\"button\">Sign in</button><button class=\"filter\" id=\"tabRegister\" type=\"button\">Create account</button></div><form id=\"authForm\"><div id=\"nameField\" class=\"field hidden\"><label for=\"fullName\">Full name</label><input id=\"fullName\" maxlength=\"100\" autocomplete=\"name\" placeholder=\"Your full name\"></div><div id=\"phoneField\" class=\"field hidden\"><label for=\"phone\">Ugandan Mobile Money number</label><input id=\"phone\" inputmode=\"tel\" autocomplete=\"tel\" placeholder=\"077… or +256 77…\"><span class=\"muted tiny\" id=\"networkHint\">MTN or Airtel number</span></div><div class=\"field\"><label for=\"email\">Email address</label><input id=\"email\" type=\"email\" required maxlength=\"254\" autocomplete=\"email\" placeholder=\"you@example.com\"></div><div class=\"field\"><label for=\"password\">Password</label><input id=\"password\" type=\"password\" required minlength=\"10\" maxlength=\"128\" autocomplete=\"current-password\" placeholder=\"At least 10 characters\"></div><div id=\"referralField\" class=\"field hidden\"><label for=\"referral\">Referral code (optional)</label><input id=\"referral\" maxlength=\"20\" placeholder=\"TAI-XXXXXXXX\"></div><p id=\"authError\" class=\"small\" style=\"color:var(--red)\" role=\"alert\"></p><button class=\"btn btn-primary\" id=\"authSubmit\" type=\"submit\" style=\"width:100%\">Sign in</button></form><p class=\"footer-note\">Use a password you do not use on another website. TrainAI will never ask you to pay an activation fee to register.</p></section></div>';\nlet mode=\"login\";const form=document.getElementById(\"authForm\");document.getElementById(\"referral\").value=new URLSearchParams(location.search).get(\"ref\")||\"\";const toggle=m=>{mode=m;document.getElementById(\"tabLogin\").classList.toggle(\"active\",m===\"login\");document.getElementById(\"tabRegister\").classList.toggle(\"active\",m===\"register\");[\"nameField\",\"phoneField\",\"referralField\"].forEach(id=>document.getElementById(id).classList.toggle(\"hidden\",m!==\"register\"));document.getElementById(\"authSubmit\").textContent=m===\"login\"?\"Sign in\":\"Create free account\";document.getElementById(\"password\").autocomplete=m===\"login\"?\"current-password\":\"new-password\";};document.getElementById(\"tabLogin\").onclick=()=>toggle(\"login\");document.getElementById(\"tabRegister\").onclick=()=>toggle(\"register\");document.getElementById(\"phone\").addEventListener(\"input\",e=>{const d=e.target.value.replace(/\\D/g,\"\");let n=\"Mobile Money\";if(/^(077|078|076|039|25677|25678|25676|25639)/.test(d))n=\"MTN detected\";if(/^(070|075|074|25670|25675|25674)/.test(d))n=\"Airtel detected\";document.getElementById(\"networkHint\").textContent=n;});form.onsubmit=async e=>{e.preventDefault();const btn=document.getElementById(\"authSubmit\"),err=document.getElementById(\"authError\");err.textContent=\"\";btn.disabled=true;try{if(mode===\"register\"){const p=document.getElementById(\"phone\").value.trim();if(!/^(?:\\+?256|0)(?:70|74|75|76|77|78|39)\\d{7}$/.test(p.replace(/[\\s()-]/g,\"\")))throw new Error(\"Enter a valid Ugandan MTN or Airtel number.\");await post(\"/api/register\",{full_name:document.getElementById(\"fullName\").value.trim(),phone_number:p,email:document.getElementById(\"email\").value.trim(),password:document.getElementById(\"password\").value,referral_code:document.getElementById(\"referral\").value.trim()});toast(\"Account created. Your 5,000 UGX bonus is locked until 3 tasks are approved.\");}else{await post(\"/api/login\",{email:document.getElementById(\"email\").value.trim(),password:document.getElementById(\"password\").value});toast(\"Welcome back.\");}await loadData();navigate(\"/dashboard\");}catch(x){err.textContent=x.message||\"Could not complete this request.\";}finally{btn.disabled=false;}};}\nfunction renderDashboard(){const u=state.user||{},bal=Number(u.available_balance_ugx||0),locked=Number(u.locked_bonus_ugx||0),done=Number(u.approved_task_count||0),pct=Math.min(100,Math.round(bal/MIN_PAYOUT*100)),remaining=Math.max(0,MIN_PAYOUT-bal),bonusDone=Math.min(3,done),quality=u.quality_score==null?\"—\":u.quality_score+\"%\";view.innerHTML=shellHead(\"YOUR WORKSPACE\",\"Welcome back, \"+esc((u.full_name||\"Contributor\").split(\" \")[0]),\"Review available tasks and keep track of approved rewards.\",'<a class=\"btn btn-primary\" href=\"/tasks\">Find an AI task ↗</a>')+'<div class=\"grid two\"><section class=\"surface metric\"><div style=\"display:flex;justify-content:space-between;gap:12px\"><div class=\"metric-label\">Available UGX</div><span class=\"tag green\">Approved balance</span></div><div class=\"metric-value green\">'+fmt(bal)+'</div><div class=\"muted small\">Minimum payout: '+fmt(MIN_PAYOUT)+'</div><div class=\"progress\" style=\"margin:17px 0 10px\"><span style=\"width:'+pct+'%\"></span></div><div class=\"muted small\">'+(remaining?fmt(remaining)+\" away from cashout\":\"You have reached the withdrawal threshold.\")+'</div><div style=\"margin-top:18px\"><button class=\"btn btn-primary\" id=\"withdrawOpen\" '+(bal<MIN_PAYOUT?'disabled':'')+'>Withdraw via Mobile Money</button></div></section><section class=\"surface metric\"><div class=\"metric-label\">Reserved welcome bonus</div><div class=\"metric-value amber\">'+fmt(locked)+'</div><div class=\"muted small\">Complete 3 approved tasks to unlock 5,000 UGX.</div><div class=\"grid three\" style=\"gap:8px;margin-top:20px\">'+[0,1,2].map(i=>'<div style=\"height:7px;border-radius:20px;background:'+(i<bonusDone?'var(--green)':'#414448')+'\"></div>').join(\"\")+'</div><div class=\"muted small\" style=\"margin-top:10px\">'+bonusDone+'/3 approved tasks completed</div></section></div><div class=\"grid three\" style=\"margin-top:16px\"><section class=\"surface metric\"><div class=\"metric-label\">Approved tasks</div><div class=\"metric-value\">'+done+'</div><div class=\"muted tiny\">Counted toward bonus</div></section><section class=\"surface metric\"><div class=\"metric-label\">Approval accuracy</div><div class=\"metric-value blue\">'+quality+'</div><div class=\"muted tiny\">Approved ÷ reviewed tasks</div></section><section class=\"surface metric\"><div class=\"metric-label\">Current streak</div><div class=\"metric-value amber\">'+(u.current_streak||0)+' days</div><div class=\"muted tiny\">Based on approved activity</div></section></div><section style=\"margin-top:28px\"><div style=\"display:flex;align-items:center;justify-content:space-between;gap:10px\"><h2>Available AI tasks</h2><a class=\"btn btn-quiet\" href=\"/tasks\">View all →</a></div><div class=\"grid two\" id=\"dashboardTasks\">'+taskCards(state.surveys.filter(s=>!state.completedIds.includes(s.id)).slice(0,4))+'</div></section><section class=\"surface surface-pad\" style=\"margin-top:22px\"><h2>Recent activity</h2>'+ledgerRows(state.ledger.slice(0,4))+'</section>';document.getElementById(\"withdrawOpen\").onclick=openWithdraw;}\nfunction taskCategory(s){const c=(String(s.category||\"\")+\" \"+String(s.title||\"\")).toLowerCase();if(c.includes(\"language\")||c.includes(\"luganda\")||c.includes(\"translation\"))return \"Luganda Translation\";if(c.includes(\"factual\")||c.includes(\"fact check\"))return \"Factual Check\";return \"Response Comparison\";}\nfunction taskCards(tasks){if(!tasks.length)return '<div class=\"surface empty\">No new tasks are available right now. Check again later.</div>';return tasks.map(s=>'<article class=\"surface task-card\"><div class=\"eyebrow\">'+esc(s.category||\"AI task\")+'</div><h3>'+esc(s.title)+'</h3><p class=\"muted small\">'+esc(s.description||\"Compare AI responses and submit careful feedback.\")+'</p><div class=\"task-meta\"><span class=\"tag\">~2 mins</span><span class=\"tag green\">+'+fmt(s.reward_ugx)+'</span><span class=\"tag\">Easy</span></div><a class=\"btn btn-secondary\" href=\"/tasks?task='+encodeURIComponent(s.id)+'\">Open task →</a></article>').join(\"\");}\nfunction renderTasks(){const cats=[\"All\",\"Luganda Translation\",\"Response Comparison\",\"Factual Check\"];const filtered=state.surveys.filter(s=>state.filter===\"All\"||taskCategory(s)===state.filter).filter(s=>!state.completedIds.includes(s.id));view.innerHTML=shellHead(\"CONTRIBUTE TO AI\",\"AI task workspace\",\"Choose a task, compare the responses carefully and submit your feedback.\")+'<div class=\"filters\">'+cats.map(c=>'<button class=\"filter '+(state.filter===c?'active':'')+'\" data-filter=\"'+esc(c)+'\">'+esc(c)+'</button>').join(\"\")+'</div><div class=\"grid two\">'+taskCards(filtered)+'</div>';document.querySelectorAll(\"[data-filter]\").forEach(b=>b.onclick=()=>{state.filter=b.dataset.filter;renderTasks()});const wanted=new URLSearchParams(location.search).get(\"task\");if(wanted){const task=state.surveys.find(s=>s.id===wanted);if(task&&!state.completedIds.includes(task.id))startTask(task);}}\nasync function startTask(task){try{const d=await post(\"/api/tasks/start\",{surveyId:task.id});state.task=task;state.attemptId=d.attemptId;state.taskStartedAt=Date.now();state.answers={};renderTaskDetail();}catch(e){toast(e.message)}}\nfunction renderTaskDetail(){const t=state.task;let qs=[];try{qs=JSON.parse(t.questions_json||\"[]\")}catch{};view.innerHTML='<div class=\"page-head\"><div><div class=\"eyebrow\">'+esc(t.category||\"AI TASK\")+'</div><h1>'+esc(t.title)+'</h1><p class=\"lead\">'+esc(t.description||\"Read the prompt and compare both responses.\")+'</p></div><button class=\"btn btn-secondary\" id=\"backTasks\">← All tasks</button></div><div class=\"notice\">Your submission is reviewed before any reward is credited. Choose carefully. Do not include personal or payment details in your answers.</div><section class=\"surface surface-pad\" style=\"margin-top:16px\"><div class=\"metric-label\">Potential task reward</div><div class=\"metric-value green\">'+fmt(t.reward_ugx)+'</div><div class=\"muted tiny\">10-second minimum review time applies.</div></section><div id=\"questionList\">'+qs.map((q,i)=>'<section class=\"surface surface-pad\" style=\"margin-top:15px\"><div class=\"eyebrow\">QUESTION '+(i+1)+'</div><h3 style=\"margin-top:8px\">'+esc(q.q||q.prompt||\"Compare these responses\")+'</h3><div class=\"response\"><span class=\"tag blue\">RESPONSE A</span><p>'+esc(q.a||q.response_a||\"\")+'</p></div><div class=\"response\"><span class=\"tag\">RESPONSE B</span><p>'+esc(q.b||q.response_b||\"\")+'</p></div><div class=\"choice-row\">'+[['A','Response A is much better'],['TIE','Tie'],['B','Response B is much better']].map(x=>'<button class=\"choice\" data-q=\"'+i+'\" data-choice=\"'+x[0]+'\">'+x[1]+'</button>').join(\"\")+'</div><div class=\"filters\" style=\"margin:10px 0 0\"><span class=\"muted tiny\" style=\"align-self:center\">Quick feedback:</span>'+[\"Accurate\",\"Natural Luganda\",\"Hallucination\"].map(tag=>'<button class=\"filter\" data-feedback=\"'+i+'\" data-tag=\"'+tag+'\">'+tag+'</button>').join(\"\")+'</div></section>').join(\"\")+'</div><div style=\"display:flex;justify-content:flex-end;margin-top:18px\"><button class=\"btn btn-primary\" id=\"submitTask\">Submit for review →</button></div>';document.getElementById(\"backTasks\").onclick=()=>{state.task=null;history.replaceState({},\"\",\"/tasks\");renderTasks()};document.querySelectorAll(\"[data-choice]\").forEach(b=>b.onclick=()=>{state.answers[b.dataset.q]=state.answers[b.dataset.q]||{};state.answers[b.dataset.q].choice=b.dataset.choice;document.querySelectorAll('[data-q=\"'+b.dataset.q+'\"]').forEach(x=>x.classList.toggle(\"selected\",x===b))});document.querySelectorAll(\"[data-tag]\").forEach(b=>b.onclick=()=>{state.answers[b.dataset.feedback]=state.answers[b.dataset.feedback]||{};state.answers[b.dataset.feedback].feedback=b.dataset.tag;b.classList.toggle(\"active\")});document.getElementById(\"submitTask\").onclick=submitTask;}\nasync function submitTask(){const t=state.task;let qs=[];try{qs=JSON.parse(t.questions_json||\"[]\")}catch{};const answers=qs.map((q,i)=>({question:i,choice:state.answers[i]?.choice,feedback:state.answers[i]?.feedback||null}));if(answers.some(a=>![\"A\",\"B\",\"TIE\"].includes(a.choice))){toast(\"Please answer every comparison.\");return}const btn=document.getElementById(\"submitTask\");btn.disabled=true;try{await post(\"/api/submissions\",{surveyId:t.id,answers,attemptId:state.attemptId});toast(\"✦ \"+fmt(t.reward_ugx)+\" submitted for review — not yet earned.\");state.task=null;state.attemptId=null;history.replaceState({},\"\",\"/tasks\");await loadData();renderTasks();}catch(e){toast(e.message);btn.disabled=false;}}\nfunction ledgerRows(rows){if(!rows.length)return '<div class=\"empty\">No transactions yet. Approved rewards will appear here.</div>';return '<div class=\"table-wrap\"><table class=\"ledger\"><thead><tr><th>Date</th><th>Activity</th><th>Reference</th><th>Amount</th><th>Status</th></tr></thead><tbody>'+rows.map((x,i)=>'<tr '+(String(x.type||\"\").toLowerCase()===\"withdrawal\"?'data-receipt=\"'+i+'\" style=\"cursor:pointer\"':\"\")+'><td>'+esc(x.created_at?new Date(x.created_at).toLocaleString():\"—\")+'</td><td><strong>'+esc(String(x.type||x.transaction_type||\"Activity\").replace(/_/g,\" \"))+'</strong><div class=\"muted tiny\">'+esc(x.details||\"\")+'</div></td><td class=\"muted\">'+esc(x.reference||\"—\")+'</td><td style=\"font-weight:800;color:'+(x.type===\"withdrawal\"?\"var(--text)\":\"var(--green)\")+'\">'+(x.type===\"withdrawal\"?\"−\":\"+\")+fmt(x.amount_ugx)+'</td><td>'+statusTag(x.status)+'</td></tr>').join(\"\")+'</tbody></table></div>';}\nfunction showReceipt(item){const root=document.getElementById(\"modalRoot\");root.innerHTML='<div class=\"modal-backdrop\" id=\"receiptBackdrop\"><section class=\"modal\"><div style=\"display:flex;justify-content:space-between;align-items:center\"><h2>Withdrawal receipt</h2><button class=\"btn btn-quiet\" id=\"receiptClose\">×</button></div><div class=\"metric-value\">'+fmt(item.amount_ugx)+'</div><p class=\"muted small\">Reference: '+esc(item.reference||\"Not assigned\")+'</p><p class=\"small\">Status: '+esc(item.status||\"pending\")+'</p><p class=\"small\">Date: '+esc(item.created_at||\"—\")+'</p><p class=\"muted small\">'+esc(item.details||\"Manual Mobile Money payout request\")+'</p><div class=\"notice\">This receipt records your request. It is not proof of a completed Mobile Money transfer.</div></section></div>';document.getElementById(\"receiptClose\").onclick=()=>root.innerHTML=\"\";document.getElementById(\"receiptBackdrop\").onclick=e=>{if(e.target.id===\"receiptBackdrop\")root.innerHTML=\"\"};}\nfunction renderStatements(){const opts=[\"All\",\"Approved\",\"In Review\",\"Bonus Unlocks\",\"Withdrawals\"];let rows=state.ledger.filter(x=>{const t=String(x.type||\"\").toLowerCase(),s=String(x.status||\"\").toLowerCase();if(state.ledgerFilter===\"Approved\")return s===\"completed\"||s===\"approved\";if(state.ledgerFilter===\"In Review\")return s===\"pending\"||s===\"processing\";if(state.ledgerFilter===\"Bonus Unlocks\")return t.includes(\"bonus\");if(state.ledgerFilter===\"Withdrawals\")return t===\"withdrawal\";return true});view.innerHTML=shellHead(\"ACCOUNT ACTIVITY\",\"Statements & ledger\",\"A clear record of submitted rewards, approved credits and withdrawal requests.\")+'<div class=\"filters\">'+opts.map(o=>'<button class=\"filter '+(state.ledgerFilter===o?'active':'')+'\" data-ledger=\"'+o+'\">'+o+'</button>').join(\"\")+'</div><section class=\"surface surface-pad\">'+ledgerRows(rows)+'</section><p class=\"footer-note\">Transaction references are generated by TrainAI. A withdrawal marked pending or processing is not a completed Mobile Money transfer.</p>';document.querySelectorAll(\"[data-ledger]\").forEach(b=>b.onclick=()=>{state.ledgerFilter=b.dataset.ledger;renderStatements()});document.querySelectorAll(\"[data-receipt]\").forEach(row=>row.onclick=()=>showReceipt(rows[Number(row.dataset.receipt)]));}\nasync function renderSupport(){view.innerHTML=shellHead(\"HELP CENTER\",\"How can we help?\",\"Ask about your account, task reviews, bonus eligibility or withdrawal requests.\")+'<section class=\"grid two\"><div class=\"surface surface-pad\"><h2>Create a support ticket</h2><form id=\"ticketForm\"><div class=\"field\"><label>Subject</label><input id=\"ticketSubject\" required minlength=\"4\" maxlength=\"120\" placeholder=\"What do you need help with?\"></div><div class=\"field\"><label>Message</label><textarea id=\"ticketMessage\" required minlength=\"10\" maxlength=\"3000\" placeholder=\"Explain what happened. Do not include your password or PIN.\"></textarea></div><button class=\"btn btn-primary\" type=\"submit\">Send ticket</button></form></div><div class=\"surface surface-pad\"><h2>Common questions</h2><div class=\"faq\"><details><summary>Why is my task in review?</summary><p>Every submission is checked before a reward is credited. Pending submissions do not count toward the bonus.</p></details><details><summary>How do I check a payout?</summary><p>Open Statements to view the latest status and reference. A pending request is not a transfer confirmation.</p></details><details><summary>How do I unlock my bonus?</summary><p>Complete three tasks that are approved by the review team.</p></details></div></div></section><section class=\"surface surface-pad\" style=\"margin-top:18px\"><h2>Your support tickets</h2><div id=\"ticketList\" class=\"muted small\">Loading…</div></section>';document.getElementById(\"ticketForm\").onsubmit=async e=>{e.preventDefault();try{await post(\"/api/support\",{subject:document.getElementById(\"ticketSubject\").value.trim(),message:document.getElementById(\"ticketMessage\").value.trim()});toast(\"Support ticket submitted.\");document.getElementById(\"ticketForm\").reset();await loadTickets()}catch(x){toast(x.message)}};await loadTickets();}\nasync function loadTickets(){const el=document.getElementById(\"ticketList\");if(!el)return;try{const d=await json(\"/api/support\");const rows=d.tickets||[];el.innerHTML=rows.length?rows.map(t=>'<div style=\"padding:12px 0;border-bottom:1px solid var(--line)\"><strong>'+esc(t.subject)+'</strong><span class=\"right\">'+statusTag(t.ticket_status)+'</span><p class=\"muted tiny\">'+esc(t.created_at)+'</p><p class=\"small\">'+esc(t.message)+'</p></div>').join(\"\"):'No support tickets yet.'}catch(e){el.textContent=e.message}}\nasync function renderProfile(){const u=state.user||{};view.innerHTML=shellHead(\"ACCOUNT SETTINGS\",\"Your account\",\"Manage your profile and secure the Mobile Money destination for withdrawals.\")+'<div class=\"grid two\"><section class=\"surface surface-pad\"><h2>Profile details</h2><div class=\"field\"><label>Full name</label><input value=\"'+esc(u.full_name||\"\")+'\" disabled></div><div class=\"field\"><label>Email address</label><input value=\"'+esc(u.email||\"\")+'\" disabled></div><div class=\"field\"><label>Registration phone</label><input value=\"'+esc(u.phone_number||\"\")+'\" disabled></div><button class=\"btn btn-secondary\" id=\"logoutButton\">Sign out</button></section><section class=\"surface surface-pad\"><h2>Mobile Money payout account</h2><p class=\"muted small\">Check the registered account name and number carefully. Locking prevents accidental changes before a withdrawal.</p><form id=\"payoutForm\"><div class=\"field\"><label>Account holder name</label><input id=\"payoutName\" required maxlength=\"120\" value=\"'+esc(u.payout_name||\"\")+'\" '+(u.payout_locked?'disabled':'')+'></div><div class=\"field\"><label>Network</label><select id=\"payoutNetwork\" '+(u.payout_locked?'disabled':'')+'><option value=\"\">Choose network</option><option value=\"MTN\" '+(u.payout_network===\"MTN\"?\"selected\":\"\")+'>MTN MoMo</option><option value=\"AIRTEL\" '+(u.payout_network===\"AIRTEL\"?\"selected\":\"\")+'>Airtel Money</option></select></div><div class=\"field\"><label>Mobile Money number</label><input id=\"payoutNumber\" required inputmode=\"tel\" placeholder=\"+256 7…\" value=\"'+esc(u.payout_number||\"\")+'\" '+(u.payout_locked?'disabled':'')+'></div>'+(u.payout_locked?'<div class=\"notice success\">✓ Your payout account is locked. Contact support if your registered details need correction.</div>':'<div class=\"notice\">Once locked, these payout details cannot be edited from this page. Verify them before continuing.</div><button class=\"btn btn-primary\" type=\"submit\" style=\"margin-top:14px\">Verify & lock payout account</button>')+'</form></section></div><p class=\"footer-note\">TrainAI does not request your Mobile Money PIN or one-time password. Never share these with anyone.</p>';document.getElementById(\"logoutButton\").onclick=logout;const form=document.getElementById(\"payoutForm\");if(!u.payout_locked)form.onsubmit=async e=>{e.preventDefault();if(!confirm(\"Lock this payout name, network and number? You will need support to change them later.\"))return;try{await post(\"/api/profile\",{payout_name:document.getElementById(\"payoutName\").value.trim(),payout_network:document.getElementById(\"payoutNetwork\").value,payout_number:document.getElementById(\"payoutNumber\").value.trim()});await loadData();toast(\"Payout account locked.\");renderProfile()}catch(x){toast(x.message)}};}\nasync function renderReferrals(){const d=await json(\"/api/referrals\");const link=location.origin+\"/auth?ref=\"+encodeURIComponent(d.referral_code||\"\");view.innerHTML=shellHead(\"INVITE OTHERS\",\"Your referral link\",\"Share TrainAI with people who may enjoy helping improve AI.\")+'<section class=\"surface surface-pad\" style=\"max-width:680px\"><div class=\"metric-label\">Your referral code</div><div class=\"metric-value blue\">'+esc(d.referral_code||\"Not available\")+'</div><div class=\"field\"><label>Share link</label><input id=\"refLink\" readonly value=\"'+esc(link)+'\"></div><button class=\"btn btn-primary\" id=\"copyRef\">Copy referral link</button><div class=\"muted-line\"></div><div class=\"metric-label\">Registered referrals</div><div class=\"metric-value\">'+Number(d.referral_count||0)+'</div><p class=\"muted small\">Referral tracking is informational. No referral reward is promised or credited at this time.</p></section>';document.getElementById(\"copyRef\").onclick=()=>{navigator.clipboard?.writeText(link).then(()=>toast(\"Referral link copied.\")).catch(()=>toast(\"Select and copy the link.\"))};}\nfunction openWithdraw(){const u=state.user||{},bal=Number(u.available_balance_ugx||0);if(bal<MIN_PAYOUT)return;const root=document.getElementById(\"modalRoot\");root.innerHTML='<div class=\"modal-backdrop\" id=\"withdrawBackdrop\"><section class=\"modal\"><div style=\"display:flex;justify-content:space-between;align-items:center\"><h2>Request a withdrawal</h2><button class=\"btn btn-quiet\" id=\"withdrawClose\">×</button></div><p class=\"muted small\">Review the amount and locked Mobile Money destination before submitting.</p><div class=\"notice\">Manual processing: submitting creates a request for review. It does not send money automatically.</div><form id=\"withdrawForm\"><div class=\"field\"><label>Available balance</label><input value=\"'+fmt(bal)+'\" disabled></div><div class=\"field\"><label>Amount (UGX)</label><input id=\"withdrawAmount\" type=\"number\" min=\"25000\" max=\"'+bal+'\" step=\"1\" value=\"25000\" required></div><div class=\"field\"><label>Destination</label><input value=\"'+esc((u.payout_network||\"\")+\" · \"+(u.payout_number||\"Not locked\"))+'\" disabled></div><div class=\"field\"><label>Platform fee</label><input value=\"0 UGX\" disabled></div><div id=\"withdrawSummary\" class=\"notice\">You will request 25,000 UGX. No transfer has been sent.</div><button class=\"btn btn-primary\" type=\"submit\" style=\"width:100%;margin-top:12px\" '+(!u.payout_locked?'disabled':'')+'>Continue to confirmation</button></form></section></div>';document.getElementById(\"withdrawClose\").onclick=()=>root.innerHTML=\"\";document.getElementById(\"withdrawBackdrop\").onclick=e=>{if(e.target.id===\"withdrawBackdrop\")root.innerHTML=\"\"};const amount=document.getElementById(\"withdrawAmount\");amount.oninput=()=>{document.getElementById(\"withdrawSummary\").textContent=\"You will request \"+fmt(amount.value)+\". Platform fee: 0 UGX. No transfer has been sent.\";};document.getElementById(\"withdrawForm\").onsubmit=async e=>{e.preventDefault();const value=Number(amount.value);if(!Number.isSafeInteger(value)||value<MIN_PAYOUT||value>bal){toast(\"Enter an amount from 25,000 UGX up to your available balance.\");return}if(!confirm(\"Confirm withdrawal request for \"+fmt(value)+\" to \"+u.payout_network+\" \"+u.payout_number+\"? This only queues a manual payout request.\"))return;try{await post(\"/api/withdraw\",{amount:value,network:u.payout_network,phone:u.payout_number});root.innerHTML=\"\";await loadData();toast(\"Withdrawal request queued for review.\");renderStatements()}catch(x){toast(x.message)}};}\nasync function logout(){try{await post(\"/api/logout\",{})}catch{}state.user=null;state.authenticated=false;navigate(\"/\");}\nasync function render(){const route=activeRoute();state.route=route;updateNav();if(route===\"/\"||route===\"/index.html\"){renderHome();return}if(route===\"/auth\"||route===\"/register\"||route===\"/login\"){if(state.authenticated){navigate(\"/dashboard\");return}renderAuth();return}if(!state.authenticated){navigate(\"/auth\");return}if(route===\"/dashboard\"){renderDashboard();return}if(route===\"/tasks\"||route===\"/survey\"){renderTasks();return}if(route===\"/statements\"||route===\"/wallet\"){renderStatements();return}if(route===\"/support\"){await renderSupport();return}if(route===\"/profile\"||route===\"/settings\"){renderProfile();return}if(route===\"/referrals\"){await renderReferrals();return}renderDashboard();}\nfunction navigate(path){history.pushState({},\"\",path);render();window.scrollTo(0,0)}\ndocument.addEventListener(\"click\",e=>{const a=e.target.closest(\"a[href^='/']\");if(!a||a.target||e.metaKey||e.ctrlKey||e.shiftKey)return;const href=a.getAttribute(\"href\");if(href.startsWith(\"/#\"))return;e.preventDefault();const url=new URL(href,location.origin);history.pushState({},\"\",url.pathname+url.search+url.hash);render();window.scrollTo(0,0)});\nwindow.addEventListener(\"popstate\",render);\ndocument.getElementById(\"chatFab\").onclick=()=>document.getElementById(\"chatDrawer\").classList.toggle(\"hidden\");document.getElementById(\"chatClose\").onclick=()=>document.getElementById(\"chatDrawer\").classList.add(\"hidden\");document.querySelectorAll(\"[data-help]\").forEach(b=>b.onclick=()=>{const q=b.dataset.help;const answers={\"Check my payout status\":\"Open Statements to view the latest request status. Pending means queued for manual review; Paid is shown only after a transfer is confirmed.\",\"Why is my task still in review?\":\"Every task is checked before its reward is credited. Pending tasks do not count toward your 3-task bonus unlock.\",\"How to unlock 5,000 UGX bonus\":\"Complete 3 tasks that are approved. The 5,000 UGX bonus then moves from locked to available automatically.\"};document.getElementById(\"chatAnswer\").textContent=answers[q]||\"Please create a support ticket for help.\"});\nasync function boot(){const ok=await loadData();const route=activeRoute();if(!ok&&route!==\"/\"&&route!==\"/auth\"&&route!==\"/register\"&&route!==\"/login\"){history.replaceState({},\"\",\"/auth\")}render();}\nboot();\n})();\n</script>\n</body>\n</html>\n";
const sec={"X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","X-Frame-Options":"DENY","Cache-Control":"no-store"};
export default {async fetch(request,env){const url=new URL(request.url),path=url.pathname;const routes={"/api/register":registerHandler,"/api/login":loginHandler,"/api/auth":authHandler,"/api/logout":logoutHandler,"/api/user":userHandler,"/api/dashboard":userHandler,"/api/tasks":userHandler,"/api/tasks/start":tasksStartHandler,"/api/submit":submissionHandler,"/api/submissions":submissionHandler,"/api/withdraw":withdrawHandler,"/api/withdrawals":withdrawHandler,"/api/profile":profileHandler,"/api/referrals":referralsHandler,"/api/support":supportHandler,"/api/admin/review":adminReviewHandler,"/api/admin/withdrawals":adminWithdrawalsHandler};if(routes[path]){try{const r=await routes[path]({request,env});const h=new Headers(r.headers);h.set("X-Content-Type-Options","nosniff");h.set("Referrer-Policy","strict-origin-when-cross-origin");return new Response(r.body,{status:r.status,statusText:r.statusText,headers:h});}catch(e){return Response.json({success:false,error:"The request could not be completed."},{status:500,headers:sec});}}if(path.startsWith("/api/"))return Response.json({success:false,error:"API route not found."},{status:404,headers:sec});const contributorRoutes=new Set(["/","/index.html","/dashboard","/dashboard.html","/tasks","/survey","/survey.html","/statements","/wallet","/wallet.html","/support","/profile","/settings","/auth","/register","/register.html","/login","/referrals"]);const key=path.slice(1);const html=contributorRoutes.has(path)?APP_SHELL:PAGES[key];if(!html)return new Response("Not found",{status:404,headers:sec});return new Response(html,{headers:{...sec,"Content-Type":"text/html; charset=utf-8"}});}};