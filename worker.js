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
  if (request.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);
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
    if (!user.payout_locked || !user.payout_name || !user.payout_number || !user.payout_network) {
      return json({ success: false, error: "Verify and lock your Mobile Money payout account in Settings first." }, 409);
    }
    const prefix = phone.slice(4, 6);
    const detectedNetwork = ["77", "78", "76", "39"].includes(prefix)
      ? "MTN"
      : ["70", "74", "75"].includes(prefix) ? "AIRTEL" : null;
    if (!detectedNetwork || detectedNetwork !== network || network !== user.payout_network || phone !== user.payout_number) {
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

    const savedRequest = await env.DB.prepare(
      "SELECT created_at FROM withdrawal_requests WHERE id = ? AND user_id = ?"
    ).bind(withdrawalId, user.id).first();
    return json({
      success: true,
      status: "pending",
      withdrawalId,
      reference: "WDL-" + withdrawalId.toUpperCase(),
      createdAt: savedRequest?.created_at || new Date().toISOString(),
      amountUGX: amount,
      payoutName: user.payout_name,
      network,
      phone,
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
const adminClubHandler=(()=>{const j=(b,n=200)=>new Response(JSON.stringify(b),{status:n,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}});const auth=(r,e)=>{const k=e.ADMIN_API_KEY||"",v=r.headers.get("Authorization")||"";if(!k||!v.startsWith("Bearer "))return false;const a=v.slice(7);if(a.length!==k.length)return false;let d=0;for(let i=0;i<k.length;i++)d|=a.charCodeAt(i)^k.charCodeAt(i);return d===0};function valid(v){let q;try{q=typeof v==="string"?JSON.parse(v):v}catch{return {error:"Questions must be valid JSON."}}if(!Array.isArray(q)||q.length<1||q.length>50)return {error:"Add 1–50 questions."};for(let i=0;i<q.length;i++){const x=q[i],t=x?.type||"opinion";if(!x||typeof x.question!=="string"||x.question.trim().length<8||!x.options||["A","B","C","D"].some(k=>typeof x.options[k]!=="string"||!x.options[k].trim()))return {error:"Question "+(i+1)+" needs a prompt and four A–D options."};if(!["opinion","experience","knowledge_check"].includes(t))return {error:"Invalid question type at question "+(i+1)};if(t==="knowledge_check"&&!["A","B","C","D"].includes(x.correct_answer))return {error:"Knowledge check "+(i+1)+" needs a correct A–D answer."};if(t!=="knowledge_check"&&x.correct_answer)return {error:"Only knowledge checks may have a correct answer."}}return {questions:q}}async function onRequest({request:r,env:e}){if(!e.DB)return j({success:false,error:"Database is not configured."},500);if(!auth(r,e))return j({success:false,error:"Admin key is missing or incorrect."},401);const origin=r.headers.get("Origin");if(origin&&origin!==new URL(r.url).origin)return j({success:false,error:"Invalid request origin."},403);if(r.method==="GET"){try{const x=await e.DB.prepare("SELECT id,title,topic,country_code,questions_json,status,created_at,scheduled_for,published_at FROM club_question_sets ORDER BY created_at DESC LIMIT 100").all();return j({success:true,questionSets:x.results||[]})}catch{return j({success:false,error:"Could not load sets. Apply migration 0002 first."},500)}}if(!["POST","PUT","PATCH"].includes(r.method))return j({success:false,error:"Method not allowed."},405);let b;try{const raw=await r.text();if(raw.length>120000)return j({success:false,error:"Request too large."},413);b=JSON.parse(raw)}catch{return j({success:false,error:"Invalid request body."},400)}try{if(r.method==="POST"||r.method==="PUT"){const title=String(b.title||"").trim(),topic=String(b.topic||"").trim(),v=valid(b.questions);if(title.length<3||title.length>160||topic.length<2||topic.length>120)return j({success:false,error:"Enter a valid title and topic."},400);if(v.error)return j({success:false,error:v.error},400);if(r.method==="POST"){const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO club_question_sets (id,title,topic,country_code,question_format,questions_json,status,created_by) VALUES (?,?,?,'UG','multiple_choice',?,'draft','admin')").bind(id,title,topic,JSON.stringify(v.questions)).run();return j({success:true,id,message:"Draft saved."},201)}const id=String(b.id||"");if(!/^[0-9a-f-]{36}$/i.test(id))return j({success:false,error:"Invalid set ID."},400);const x=await e.DB.prepare("UPDATE club_question_sets SET title=?,topic=?,questions_json=? WHERE id=? AND status IN ('draft','scheduled')").bind(title,topic,JSON.stringify(v.questions),id).run();if(!x.meta||x.meta.changes!==1)return j({success:false,error:"Only draft or scheduled sets can be edited."},409);return j({success:true,message:"Question set updated."})}const id=String(b.id||""),action=String(b.action||"");if(!/^[0-9a-f-]{36}$/i.test(id))return j({success:false,error:"Invalid set ID."},400);if(action==="schedule"){const ms=Date.parse(String(b.scheduled_for||""));if(!Number.isFinite(ms)||ms<=Date.now())return j({success:false,error:"Choose a future date and time."},400);const x=await e.DB.prepare("UPDATE club_question_sets SET status='scheduled',scheduled_for=? WHERE id=? AND status IN ('draft','scheduled')").bind(new Date(ms).toISOString(),id).run();if(!x.meta||x.meta.changes!==1)return j({success:false,error:"This set cannot be scheduled."},409);return j({success:true,message:"Scheduled; not yet visible to contributors."})}if(action==="publish"){if(b.confirm_publish!==true)return j({success:false,error:"Explicit confirmation required."},400);const x=await e.DB.prepare("UPDATE club_question_sets SET status='published',published_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),scheduled_for=NULL WHERE id=? AND status IN ('draft','scheduled')").bind(id).run();if(!x.meta||x.meta.changes!==1)return j({success:false,error:"Only draft or scheduled sets can be published."},409);return j({success:true,message:"Published to Answer CLUB records only. No survey or reward was created."})}if(action==="archive"){const x=await e.DB.prepare("UPDATE club_question_sets SET status='archived',scheduled_for=NULL WHERE id=? AND status IN ('draft','scheduled','published')").bind(id).run();if(!x.meta||x.meta.changes!==1)return j({success:false,error:"This set cannot be archived."},409);return j({success:true,message:"Archived."})}return j({success:false,error:"Unknown action."},400)}catch{return j({success:false,error:"Action failed. Confirm migration 0002 is applied."},500)}}return onRequest})();
const ANSWER_CLUB_ADMIN = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Answer CLUB Admin · TrainAI.ug</title><style>\n:root{color-scheme:dark;--bg:#0e1013;--panel:#191e27;--line:#303947;--text:#f1f3f4;--muted:#9aa0a6;--blue:#a8c7fa;--green:#81c995;--red:#f28b82}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0,#24334a,transparent 40%),var(--bg);color:var(--text);font:14px/1.55 system-ui,sans-serif}.wrap{max-width:1100px;margin:auto;padding:24px 16px 60px}header,.row,.item{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.panel{background:rgba(25,30,39,.9);border:1px solid #354154;border-radius:18px;padding:18px;margin:16px 0}.muted,.note{color:var(--muted)}.note{font-size:12px}.brand{font-size:20px;font-weight:800}.brand b,a{color:var(--blue)}h1,h2{font-family:Georgia,serif;font-weight:500}h1{font-size:30px;margin:14px 0 4px}h2{font-size:22px;margin:0 0 10px}.grow{flex:1;min-width:220px}label{display:block;font-size:12px;font-weight:700}input,textarea{width:100%;background:#0d1118;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:11px;margin:6px 0 13px}textarea{min-height:320px;font:12px/1.5 monospace}button{background:#252e3b;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:10px 14px;font-weight:700;cursor:pointer}button.primary{background:var(--blue);color:#062e6f}.danger{color:var(--red)}.status{min-height:22px;color:var(--muted)}.error{color:var(--red)}.list{display:grid;gap:8px}.item{padding:12px;border:1px solid var(--line);border-radius:12px;background:#11161e}.pill{font-size:11px;padding:4px 9px;border-radius:30px;background:#29313c}.published{color:var(--green)}.grid{display:grid;grid-template-columns:1fr 1.5fr;gap:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}.panel{padding:14px}h1{font-size:26px}}\n</style></head><body><main class=\"wrap\"><header><div class=\"brand\">TrainAI<b>.ug</b> / Answer CLUB</div><nav><a href=\"/admin.html\">Survey review</a> · <a href=\"/admin-withdrawals.html\">Withdrawals</a></nav></header><p class=\"muted\">ADMINISTRATION · UGANDA QUESTION SETS</p><h1>Question set manager</h1><p class=\"muted\">Create, review, edit, schedule and publish sets. Publishing here does not create a client-funded survey or attach rewards.</p>\n<section class=\"panel\"><h2>Admin access</h2><p class=\"note\">Enter the Cloudflare ADMIN_API_KEY secret. It is held in memory only, never browser storage.</p><form id=\"auth\" class=\"row\"><div class=\"grow\"><label>Admin API key</label><input id=\"key\" type=\"password\" autocomplete=\"off\" required></div><button class=\"primary\">Connect</button><button id=\"refresh\" type=\"button\">Refresh</button></form><div id=\"status\" class=\"status\">Admin access required.</div></section>\n<section class=\"panel\"><div class=\"row\"><h2>Question sets</h2><button id=\"new\" type=\"button\">＋ New draft</button></div><div id=\"sets\" class=\"list\">Connect to load sets.</div></section>\n<section class=\"panel\" id=\"editor\"><h2 id=\"heading\">Create question set</h2><div class=\"grid\"><div><label>Set title</label><input id=\"title\" maxlength=\"160\" placeholder=\"Uganda Community & Social Life — Set 03\"><label>Topic</label><input id=\"topic\" maxlength=\"120\" placeholder=\"Culture, community and daily life\"><label>Schedule time (Kampala local)</label><input id=\"when\" type=\"datetime-local\"><p class=\"note\">Scheduling records the date; it does not automatically release the set to contributors.</p></div><div><label>Questions JSON</label><textarea id=\"questions\" spellcheck=\"false\" placeholder='[{\"id\":\"Q1\",\"type\":\"opinion\",\"question\":\"...\",\"options\":{\"A\":\"...\",\"B\":\"...\",\"C\":\"...\",\"D\":\"...\"}}]'></textarea><p class=\"note\">Use opinion, experience or knowledge_check. Every question needs four options. Only knowledge checks can have correct_answer.</p></div></div><div class=\"row\"><button class=\"primary\" id=\"save\">Save draft</button><button id=\"schedule\">Schedule</button><button id=\"publish\">Publish…</button><button class=\"danger\" id=\"archive\">Archive</button><button id=\"clear\">Clear</button></div><div id=\"editorStatus\" class=\"status\"></div></section><p class=\"note\">Client funding, eligibility and reward amounts must be verified and configured separately. No guaranteed earnings are promised.</p></main>\n<script>\nlet adminKey=\"\",selected=null,sets=[];const $=x=>document.getElementById(x);function say(x,e=false){$(\"status\").textContent=x;$(\"status\").className=\"status\"+(e?\" error\":\"\")}function esay(x,e=false){$(\"editorStatus\").textContent=x;$(\"editorStatus\").className=\"status\"+(e?\" error\":\"\")}\nasync function api(method=\"GET\",body){const r=await fetch(\"/api/admin/answer-club\",{method,headers:{\"Authorization\":\"Bearer \"+adminKey,...(body?{\"Content-Type\":\"application/json\"}:{})},body:body?JSON.stringify(body):undefined,cache:\"no-store\"});const d=await r.json().catch(()=>({}));if(!r.ok||!d.success)throw Error(d.error||\"Request failed.\");return d}\nasync function load(){if(!adminKey)return;say(\"Loading…\");try{sets=(await api()).questionSets||[];render();say(sets.length+\" set(s) loaded.\")}catch(e){say(e.message,true);if(/key is missing or incorrect/i.test(e.message))adminKey=\"\"}}\nfunction render(){$(\"sets\").replaceChildren();if(!sets.length){$(\"sets\").textContent=\"No sets found. Apply database migrations 0002 and 0003.\";return}for(const x of sets){const el=document.createElement(\"div\");el.className=\"item\";const t=document.createElement(\"strong\");t.textContent=x.title;const sub=document.createElement(\"span\");sub.className=\"muted\";sub.textContent=x.topic+\" · \"+JSON.parse(x.questions_json||\"[]\").length+\" questions\";const p=document.createElement(\"span\");p.className=\"pill \"+x.status;p.textContent=x.status;const b=document.createElement(\"button\");b.textContent=\"Open\";b.onclick=()=>edit(x.id);el.append(t,sub,p,b);$(\"sets\").append(el)}}\nfunction clear(){selected=null;$(\"heading\").textContent=\"Create question set\";$(\"title\").value=\"\";$(\"topic\").value=\"\";$(\"questions\").value=\"\";$(\"when\").value=\"\";esay(\"\")}\nfunction edit(id){const x=sets.find(y=>y.id===id);if(!x)return;selected=id;$(\"heading\").textContent=\"Edit question set\";$(\"title\").value=x.title;$(\"topic\").value=x.topic;$(\"questions\").value=JSON.stringify(JSON.parse(x.questions_json||\"[]\"),null,2);$(\"when\").value=x.scheduled_for?new Date(x.scheduled_for).toISOString().slice(0,16):\"\";esay(\"Current status: \"+x.status);$(\"editor\").scrollIntoView({behavior:\"smooth\"})}\nfunction payload(){let q;try{q=JSON.parse($(\"questions\").value)}catch{throw Error(\"Questions JSON is invalid.\")}return {id:selected,title:$(\"title\").value.trim(),topic:$(\"topic\").value.trim(),questions:q}}\nasync function save(){const p=payload(),d=await api(selected?\"PUT\":\"POST\",p);if(!selected)selected=d.id;esay(d.message||\"Saved.\");await load()}\n$(\"auth\").onsubmit=async e=>{e.preventDefault();adminKey=$(\"key\").value.trim();await load()};$(\"refresh\").onclick=load;$(\"new\").onclick=clear;$(\"clear\").onclick=clear;$(\"save\").onclick=async()=>{try{await save()}catch(e){esay(e.message,true)}};\n$(\"schedule\").onclick=async()=>{try{await save();if(!$(\"when\").value)throw Error(\"Choose a future date and time.\");const d=await api(\"PATCH\",{id:selected,action:\"schedule\",scheduled_for:new Date($(\"when\").value).toISOString()});esay(d.message);await load()}catch(e){esay(e.message,true)}};\n$(\"publish\").onclick=async()=>{try{await save();if(!confirm(\"Publish this question set to Answer CLUB records? This does not create a funded survey or attach rewards.\"))return;const d=await api(\"PATCH\",{id:selected,action:\"publish\",confirm_publish:true});esay(d.message);await load()}catch(e){esay(e.message,true)}};\n$(\"archive\").onclick=async()=>{try{if(!selected)throw Error(\"Open a saved set first.\");if(!confirm(\"Archive this set?\"))return;const d=await api(\"PATCH\",{id:selected,action:\"archive\"});esay(d.message);await load()}catch(e){esay(e.message,true)}};\n</script></body></html>";
const APP_SHELL = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<meta name=\"theme-color\" content=\"#131314\">\n<meta name=\"description\" content=\"TrainAI Uganda — review AI responses, complete language tasks and track approved rewards in UGX.\">\n<title>TrainAI.ug — AI contributor workspace</title>\n<style>\n:root{color-scheme:dark;--bg:#131314;--surface:#1e1f20;--surface2:#282a2c;--line:#333537;--muted:#a1a1aa;--text:#e3e3e3;--blue:#a8c7fa;--green:#81c995;--amber:#fdd663;--red:#f28b82;--grad:linear-gradient(135deg,#4285f4,#9b72cb,#d96570)}\n*{box-sizing:border-box}html{background:var(--bg);scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}a{color:inherit;text-decoration:none}button,input,textarea,select{font:inherit}button,a,input,textarea,select{outline-offset:3px}button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--blue)}button{cursor:pointer}.hidden{display:none!important}.muted{color:var(--muted)}.small{font-size:12px}.tiny{font-size:10px}.wrap{max-width:1200px;margin:auto;padding:28px 32px}.shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:248px;background:#131314;border-right:1px solid var(--line);padding:24px 16px;display:flex;flex-direction:column;z-index:30}.brand{font-size:22px;font-weight:800;letter-spacing:-.7px;padding:0 12px 30px}.brand b{color:var(--blue)}.nav-label{padding:0 12px 10px;color:#777;font-size:10px;letter-spacing:1.8px;font-weight:800;text-transform:uppercase}.nav-list{display:grid;gap:5px}.nav-link{display:flex;align-items:center;gap:13px;padding:11px 13px;border-radius:13px;color:#c2c5c9;font-size:13px;font-weight:600;transition:.18s}.nav-link:hover,.nav-link.active{background:var(--surface2);color:var(--blue)}.nav-icon{width:20px;text-align:center;font-size:17px}.sidebar-foot{margin-top:auto;border:1px solid var(--line);background:var(--surface);border-radius:17px;padding:15px}.ai-badge{display:inline-flex;align-items:center;gap:7px;border:1px solid #a8c7fa40;background:linear-gradient(110deg,#4285f420,#9b72cb20,#d9657020);color:var(--blue);border-radius:99px;padding:6px 11px;font-size:10px;font-weight:800;letter-spacing:.5px}.main{margin-left:248px;min-height:100vh}.topbar{height:70px;position:sticky;top:0;z-index:20;background:#131314ed;backdrop-filter:blur(18px);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 32px}.top-brand{display:none;font-weight:800;color:var(--blue)}.balance-pill{display:inline-flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--line);padding:8px 13px;border-radius:99px;font-size:12px;font-weight:700}.balance-pill strong{color:var(--green);font-variant-numeric:tabular-nums}.user-menu{display:flex;align-items:center;gap:12px}.avatar{width:32px;height:32px;border-radius:50%;background:#30343a;color:var(--blue);display:grid;place-items:center;font-size:12px;font-weight:800}.mobile-nav{display:none}.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:5px 0 26px}.eyebrow{font-size:10px;font-weight:800;letter-spacing:1.7px;text-transform:uppercase;color:var(--blue)}h1{font-size:31px;line-height:1.15;letter-spacing:-1.1px;margin:8px 0 8px}h2{font-size:18px;letter-spacing:-.3px;margin:0 0 14px}h3{font-size:15px;margin:0 0 7px}.lead{color:var(--muted);max-width:690px;font-size:14px}.surface{background:var(--surface);border:1px solid var(--line);border-radius:22px}.surface-pad{padding:22px}.grid{display:grid;gap:16px}.grid.two{grid-template-columns:1.2fr .8fr}.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}.metric{padding:22px}.metric-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px}.metric-value{font-size:29px;font-weight:800;letter-spacing:-1px;margin:8px 0 4px;font-variant-numeric:tabular-nums}.green{color:var(--green)}.amber{color:var(--amber)}.blue{color:var(--blue)}.muted-line{border-top:1px solid var(--line);margin:18px 0}.btn{border:0;border-radius:999px;padding:11px 17px;font-weight:750;font-size:12px;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.18s}.btn-primary{background:var(--blue);color:#111820}.btn-primary:hover{background:#c5d8fa;transform:translateY(-1px)}.btn-secondary{background:var(--surface2);border:1px solid var(--line);color:var(--text)}.btn-secondary:hover{border-color:#69717a}.btn-quiet{background:transparent;color:var(--blue);padding:8px 10px}.btn:disabled{opacity:.42;cursor:not-allowed;transform:none}.progress{height:8px;border-radius:20px;background:#3b3d40;overflow:hidden}.progress>span{display:block;height:100%;background:var(--green);border-radius:20px;transition:width .35s}.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:13px}.step{background:var(--surface);border:1px solid var(--line);border-radius:19px;padding:19px}.step-num{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:#a8c7fa1a;color:var(--blue);font-weight:800;font-size:12px;margin-bottom:13px}.hero{padding:42px;border-radius:28px;border:1px solid #a8c7fa30;background:radial-gradient(ellipse at 90% 0%,#4285f426,transparent 44%),radial-gradient(ellipse at 10% 100%,#9b72cb18,transparent 45%),var(--surface)}.hero h1{font-size:clamp(34px,5vw,54px);max-width:750px;line-height:1.08;margin:20px 0 14px}.gradient-text{background:var(--grad);background-clip:text;color:transparent}.hero .lead{font-size:16px;line-height:1.7}.trust-row{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:18px}.trust{border:1px solid var(--line);border-radius:16px;padding:15px;background:#1a1b1c}.trust strong{display:block;font-size:15px;margin-bottom:3px}.trust span{font-size:11px;color:var(--muted)}.faq details{border-bottom:1px solid var(--line);padding:15px 0}.faq summary{cursor:pointer;font-weight:700;font-size:13px;list-style:none}.faq summary::-webkit-details-marker{display:none}.faq details p{font-size:12px;color:var(--muted);line-height:1.7;margin:10px 0 0}.tag{display:inline-flex;align-items:center;border-radius:99px;padding:5px 9px;font-size:10px;font-weight:750;background:#282a2c;color:#c9cdd2;border:1px solid #3a3d40}.tag.green{background:#81c99515;color:var(--green);border-color:#81c99530}.tag.amber{background:#fdd66315;color:var(--amber);border-color:#fdd66330}.tag.blue{background:#a8c7fa15;color:var(--blue);border-color:#a8c7fa30}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}.filter{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:99px;padding:8px 13px;font-size:11px;font-weight:700}.filter.active{color:var(--blue);border-color:#a8c7fa55;background:#a8c7fa12}.task-card{padding:19px}.task-meta{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0 15px}.response{background:#18191a;border:1px solid #3b3e41;border-radius:17px;padding:17px;margin-top:12px}.response p{font-size:13px;color:#c9cdd1;white-space:pre-wrap}.choice-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px}.choice{background:var(--surface2);border:1px solid var(--line);color:#d5d9de;border-radius:12px;padding:10px 8px;font-size:11px;font-weight:700}.choice.selected{border-color:var(--blue);background:#a8c7fa17;color:var(--blue)}.field{display:grid;gap:7px;margin:13px 0}.field label{font-size:11px;color:#c3c7cb;font-weight:700}.field input,.field textarea,.field select{width:100%;border:1px solid var(--line);background:#18191a;border-radius:12px;color:var(--text);padding:12px 13px;font-size:13px}.field textarea{min-height:115px;resize:vertical}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 13px}.table-wrap{overflow:auto}.ledger{width:100%;border-collapse:collapse;min-width:590px}.ledger th,.ledger td{text-align:left;border-bottom:1px solid var(--line);padding:13px 12px;font-size:11px}.ledger th{color:#92979d;font-size:10px;text-transform:uppercase;letter-spacing:.8px}.ledger td strong{font-size:12px}.empty{padding:35px 15px;text-align:center;color:var(--muted);font-size:13px}.toast{position:fixed;right:22px;bottom:22px;z-index:80;background:#242629;border:1px solid #a8c7fa55;border-radius:16px;padding:14px 17px;box-shadow:0 14px 50px #0008;font-size:12px;max-width:330px}.modal-backdrop{position:fixed;inset:0;background:#0009;z-index:70;display:grid;place-items:center;padding:18px}.modal{width:min(480px,100%);background:var(--surface);border:1px solid var(--line);border-radius:23px;padding:23px;max-height:90vh;overflow:auto}.skeleton{background:linear-gradient(90deg,#242628 25%,#303336 45%,#242628 65%);background-size:220% 100%;animation:shimmer 1.2s infinite;border-radius:12px}@keyframes shimmer{to{background-position:-220% 0}}.loading-line{height:16px;margin:10px 0}.chat-fab{position:fixed;right:22px;bottom:24px;z-index:50;border:1px solid #a8c7fa66;background:#25282c;color:var(--blue);border-radius:99px;padding:12px 17px;font-weight:800;font-size:12px;box-shadow:0 8px 35px #0008}.chat-drawer{position:fixed;right:20px;bottom:82px;width:min(370px,calc(100vw - 30px));max-height:72vh;overflow:auto;z-index:60;background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:18px;box-shadow:0 18px 60px #0009}.quick-reply{display:block;width:100%;text-align:left;border:1px solid var(--line);background:#252729;color:#d8dce0;border-radius:12px;padding:10px;margin:7px 0;font-size:11px}.notice{padding:13px 15px;border:1px solid #fdd66340;background:#fdd6630b;color:#e9d58b;border-radius:14px;font-size:11px;line-height:1.6}.notice.success{border-color:#81c99540;background:#81c9950b;color:var(--green)}.auth-wrap{min-height:calc(100vh - 70px);display:grid;place-items:center;padding:25px}.auth-card{width:min(450px,100%);padding:26px}.brand-mark{height:42px;width:42px;border-radius:14px;background:var(--blue);color:#111820;display:grid;place-items:center;font-size:20px;font-weight:900}.right{margin-left:auto}.footer-note{color:#767b81;font-size:10px;line-height:1.6;margin-top:25px}\n@media(max-width:900px){.sidebar{width:218px}.main{margin-left:218px}.grid.two{grid-template-columns:1fr}.wrap{padding:25px 22px}.topbar{padding:0 22px}}\n@media(max-width:639px){body{padding-bottom:calc(72px + env(safe-area-inset-bottom))}.sidebar{display:none}.main{margin:0}.topbar{height:60px;padding:0 16px}.top-brand{display:block}.topbar .top-context{display:none}.wrap{padding:22px 16px}.page-head{align-items:flex-start;flex-direction:column;margin-bottom:20px}h1{font-size:27px}.hero{padding:25px 20px;border-radius:23px}.hero h1{font-size:35px}.steps{grid-template-columns:1fr}.trust-row{grid-template-columns:1fr}.grid.three{grid-template-columns:1fr 1fr}.metric{padding:17px}.metric-value{font-size:23px}.mobile-nav{position:fixed;display:grid;grid-template-columns:repeat(4,1fr);left:0;right:0;bottom:0;padding:8px 5px calc(8px + env(safe-area-inset-bottom));background:#171819f5;border-top:1px solid var(--line);backdrop-filter:blur(20px);z-index:40}.mobile-nav a{display:grid;justify-items:center;gap:3px;padding:6px 2px;border-radius:12px;color:#999da3;font-size:9px;font-weight:700}.mobile-nav a.active{color:var(--blue);background:#a8c7fa10}.mobile-nav i{font-style:normal;font-size:17px}.chat-fab{right:12px;bottom:calc(82px + env(safe-area-inset-bottom));padding:10px 13px}.chat-drawer{right:10px;bottom:calc(137px + env(safe-area-inset-bottom))}.toast{right:10px;left:10px;bottom:calc(80px + env(safe-area-inset-bottom));max-width:none}.choice-row{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.auth-wrap{min-height:calc(100vh - 130px);padding:15px}.auth-card{padding:21px}}\n@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}\n .sidebar,.main{transition:width .2s ease,margin-left .2s ease}.sidebar.collapsed{width:76px;padding-left:10px;padding-right:10px}.sidebar.collapsed .brand{font-size:0;text-align:center;padding-left:0;padding-right:0}.sidebar.collapsed .brand::after{content:'T';font-size:22px;color:var(--blue)}.sidebar.collapsed .nav-label,.sidebar.collapsed .sidebar-foot{display:none}.sidebar.collapsed .nav-link{justify-content:center;font-size:0;padding:12px 8px}.sidebar.collapsed .nav-icon{font-size:18px}.sidebar.collapsed .nav-link .tag{display:none}.main.expanded{margin-left:76px}@media(max-width:639px){.main.expanded{margin-left:0}}\n\n/* Mobile Money checkout — Gemini obsidian surfaces */\n.checkout-backdrop{position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.72);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:22px}\n.checkout-sheet{width:min(100%,520px);max-height:min(92dvh,820px);overflow:auto;background:#1e1f20;border:1px solid #333537;border-radius:26px;padding:24px;box-shadow:0 24px 90px rgba(0,0,0,.55);color:#e3e3e3;overscroll-behavior:contain}\n.checkout-top{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px}\n.checkout-kicker{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#a8c7fa;font-weight:750}\n.checkout-title{font-size:22px;line-height:1.2;margin:4px 0 0;font-weight:750}\n.checkout-steps{display:flex;gap:6px;margin:0 0 20px}\n.checkout-steps span{height:4px;flex:1;border-radius:99px;background:#333537}\n.checkout-steps span.active{background:#a8c7fa}\n.checkout-balance{background:linear-gradient(145deg,#282a2c,#202123);border:1px solid #3b3e40;border-radius:18px;padding:16px;margin-bottom:18px}\n.checkout-balance-label{font-size:12px;color:#b8b8bd;display:flex;justify-content:space-between;align-items:center}\n.checkout-balance-value{font-size:26px;font-weight:780;letter-spacing:-.04em;margin-top:5px;color:#81c995}\n.checkout-eye{border:1px solid #45484a;background:#282a2c;color:#e3e3e3;border-radius:99px;padding:5px 10px;cursor:pointer}\n.checkout-field{margin:14px 0}\n.checkout-field label{display:block;font-size:12px;color:#c4c7c5;margin-bottom:7px;font-weight:650}\n.checkout-input{width:100%;background:#131314;border:1px solid #44474a;border-radius:13px;padding:13px 14px;color:#e3e3e3;font-size:16px;min-height:48px}\n.checkout-input:focus{outline:2px solid #a8c7fa;outline-offset:1px;border-color:#a8c7fa}\n.checkout-quick{display:flex;gap:8px;flex-wrap:wrap;margin-top:9px}\n.checkout-chip{border:1px solid #45484a;background:#282a2c;color:#dfe3e8;border-radius:999px;padding:8px 13px;font-size:12px;font-weight:700;cursor:pointer}\n.checkout-chip[aria-pressed=true]{border-color:#a8c7fa;color:#a8c7fa;background:#26313d}\n.checkout-chip:disabled{opacity:.35;cursor:not-allowed}\n.checkout-carrier{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:11px;font-weight:800;border:1px solid}\n.checkout-carrier.mtn{color:#ffcc00;border-color:#a88c22;background:rgba(255,204,0,.08)}\n.checkout-carrier.airtel{color:#ff8585;border-color:#9d4040;background:rgba(230,0,0,.09)}\n.checkout-lock{font-size:10px;color:#81c995;border:1px solid rgba(129,201,149,.45);background:rgba(129,201,149,.08);border-radius:999px;padding:4px 8px;font-weight:750}\n.checkout-destination{border:1px solid #3b3e40;background:#242628;border-radius:16px;padding:14px}\n.checkout-destination-head{display:flex;justify-content:space-between;align-items:center;gap:8px}\n.checkout-destination-name{font-weight:750;margin-top:8px}\n.checkout-destination-number{color:#bfc3c8;font-size:13px}\n.checkout-breakdown{background:#131314;border:1px solid #333537;border-radius:16px;padding:14px;margin:16px 0}\n.checkout-breakdown-row{display:flex;justify-content:space-between;gap:12px;padding:5px 0;font-size:13px;color:#c5c8ca}\n.checkout-breakdown-row.total{border-top:1px solid #333537;margin-top:7px;padding-top:12px;font-weight:800;color:#81c995;font-size:15px}\n.checkout-notice{border:1px solid rgba(253,214,99,.28);background:rgba(253,214,99,.06);color:#e6d9a9;border-radius:13px;padding:11px 12px;font-size:11px;line-height:1.55;margin:14px 0}\n.checkout-error{color:#f28b82;font-size:12px;margin-top:8px;min-height:18px}\n.checkout-actions{display:flex;gap:10px;margin-top:18px}\n.checkout-actions>*{flex:1}\n.checkout-btn{border:1px solid transparent;border-radius:999px;min-height:48px;padding:12px 17px;font-weight:780;cursor:pointer}\n.checkout-btn.primary{background:#a8c7fa;color:#172333}\n.checkout-btn.secondary{background:#282a2c;color:#e3e3e3;border-color:#45484a}\n.checkout-btn:disabled{opacity:.45;cursor:not-allowed}\n.checkout-review{border:1px solid #3b3e40;background:#242628;border-radius:17px;padding:16px;margin:16px 0}\n.checkout-review-row{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #333537;font-size:13px}\n.checkout-review-row:last-child{border:0}\n.checkout-review-row span:first-child{color:#aeb3b7}\n.checkout-review-row strong{text-align:right;overflow-wrap:anywhere}\n.checkout-review-amount{font-size:28px;font-weight:800;color:#81c995;margin:6px 0 12px}\n.checkout-success-mark{width:54px;height:54px;border-radius:50%;display:grid;place-items:center;background:rgba(129,201,149,.13);border:1px solid rgba(129,201,149,.4);color:#81c995;font-size:28px;margin-bottom:14px}\n.checkout-ref{background:#131314;border:1px dashed #4a4e50;border-radius:13px;padding:13px;font:700 12px ui-monospace,monospace;overflow-wrap:anywhere}\n.checkout-spin{display:inline-block;width:15px;height:15px;border:2px solid rgba(23,35,51,.3);border-top-color:#172333;border-radius:50%;animation:checkoutSpin .7s linear infinite;vertical-align:-3px;margin-right:7px}\n@keyframes checkoutSpin{to{transform:rotate(360deg)}}\n@media(max-width:639px){.checkout-backdrop{padding:0;align-items:flex-end}.checkout-sheet{width:100%;max-height:94dvh;border-radius:24px 24px 0 0;padding:21px 18px calc(20px + env(safe-area-inset-bottom));border-bottom:0}.checkout-title{font-size:20px}.checkout-actions{position:sticky;bottom:-1px;background:#1e1f20;padding:10px 0 2px}.checkout-balance-value{font-size:24px}}\n@media(prefers-reduced-motion:reduce){.checkout-spin{animation:none}}\n\n\n/* Uganda-first home experience */\n\n/* Requested typography: Gemini-style sans headings and Georgia body copy */\n.home-light-ui h1,.home-light-ui h2,.home-light-ui h3,.home-light-ui .home-brand{\n font-family:\"Google Sans\",\"Product Sans\",Arial,sans-serif;\n font-size:28px;\n font-weight:700;\n letter-spacing:-.55px;\n line-height:1.2;\n}\n.home-light-ui p,.home-light-ui .home-sub,.home-light-ui .home-task p,\n.home-light-ui .home-card p,.home-light-ui .home-reward p,\n.home-light-ui .home-trust .home-muted{\n font-family:Georgia,\"Times New Roman\",serif;\n font-size:22px;\n font-weight:400;\n line-height:1.55;\n}\n.home-light-ui .home-brand{font-size:28px}\n.home-light-ui .home-hero h1{font-size:28px}\n.home-light-ui .home-section h2{font-size:28px}\n.home-light-ui .home-task h3,.home-light-ui .home-reward h3{font-size:28px}\n@media(max-width:760px){\n .home-light-ui p,.home-light-ui .home-sub,.home-light-ui .home-task p,\n .home-light-ui .home-card p,.home-light-ui .home-reward p,\n .home-light-ui .home-trust .home-muted{font-size:22px}\n .home-light-ui h1,.home-light-ui h2,.home-light-ui h3{font-size:28px}\n}\n\nbody.home-light{background:#f5f7f5;color:#172332;color-scheme:light}\nbody.home-light .sidebar,body.home-light .topbar,body.home-light .mobile-nav,body.home-light .chat-fab{display:none!important}\nbody.home-light .main{margin:0;min-height:100vh;background:#f5f7f5}\nbody.home-light .wrap{max-width:1220px;padding:0 28px 56px}\n.home-light-ui{--ink:#172332;--sub:#586575;--paper:#f5f7f5;--card:#fff;--stroke:#e2e8e5;--accent:#087f78;--accent-soft:#e4f4f1;color:var(--ink);background:var(--paper);min-height:100vh}\n.home-light-ui a{color:inherit}\n.home-header{min-height:76px;display:flex;align-items:center;justify-content:space-between;gap:18px;border-bottom:1px solid var(--stroke);margin-bottom:28px}\n.home-brand{font-size:22px;font-weight:850;letter-spacing:-.8px;color:#172332!important}\n.home-brand b{color:var(--accent)}\n.home-nav{display:flex;align-items:center;gap:24px;color:#526070;font-size:13px;font-weight:650}\n.home-nav a:hover{color:var(--accent)}\n.home-head-actions{display:flex;align-items:center;gap:10px}\n.home-profile{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:#e2eeeb;color:#075e59;font-weight:800;font-size:12px}\n.home-hero{background:linear-gradient(125deg,#e9f5f1,#fff 70%);border:1px solid #d8e9e3;border-radius:25px;padding:30px;margin-bottom:22px}\n.home-hero h1{font-size:clamp(28px,4vw,40px);line-height:1.13;letter-spacing:-1.2px;margin:8px 0 9px}\n.home-sub{color:var(--sub);font-size:14px;max-width:700px;line-height:1.65}\n.home-card{background:var(--card);border:1px solid var(--stroke);border-radius:20px;padding:21px;box-shadow:0 5px 20px rgba(24,48,44,.035)}\n.home-section{margin-top:26px}\n.home-section-head{display:flex;justify-content:space-between;align-items:end;gap:12px;margin-bottom:13px}\n.home-section h2{font-size:19px;color:var(--ink);margin:0 0 5px;letter-spacing:-.35px}\n.home-balance{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}\n.home-balance-card{background:#123d3a;color:white;border:0;padding:25px}\n.home-balance-card .home-muted{color:#c6dfda}\n.home-balance-value{font-size:clamp(32px,5vw,44px);font-weight:850;letter-spacing:-1.6px;margin:7px 0}\n.home-btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:11px 17px;border:0;border-radius:999px;background:var(--accent);color:white!important;font-size:12px;font-weight:800;cursor:pointer}\n.home-btn:hover{background:#066c66}\n.home-btn:disabled{opacity:.45;cursor:not-allowed}\n.home-btn.secondary{background:#e8f2ef;color:#145e59!important;border:1px solid #d5e7e1}\n.home-tag{display:inline-flex;align-items:center;border-radius:99px;padding:5px 9px;background:#e7f4f1;color:#08736c;font-size:10px;font-weight:800}\n.home-muted{color:var(--sub);font-size:12px;line-height:1.6}\n.home-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}\n.home-task{border:1px solid var(--stroke);border-radius:17px;background:#fff;padding:17px;display:flex;flex-direction:column;min-height:190px}\n.home-task h3{font-size:15px;color:var(--ink);margin:9px 0 5px}\n.home-task p{font-size:12px;color:var(--sub);line-height:1.55;margin:0 0 14px}\n.home-task-foot{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:auto}\n.home-reward{border:1px solid var(--stroke);border-radius:17px;padding:18px;background:#fff}\n.home-reward-cost{font-size:24px;font-weight:850;color:#087f78;margin:8px 0}\n.home-progress{height:9px;border-radius:99px;background:#e8eeeb;overflow:hidden;margin:12px 0 8px}\n.home-progress span{display:block;height:100%;background:#0c988c;border-radius:99px}\n.home-mini{font-size:11px;color:var(--sub)}\n.home-trust{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}\n.home-trust article{padding:16px;border-radius:16px;background:#f8faf9;border:1px solid var(--stroke)}\n.home-trust strong{display:block;font-size:13px;margin-bottom:5px}\n.home-footer{border-top:1px solid var(--stroke);margin-top:30px;padding:20px 0 8px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#687582;font-size:11px}\n.home-light-ui .ledger th{color:#64727d}\n.home-light-ui .ledger td{border-color:#e7ece9;color:#243342}\n.home-light-ui .ledger td .muted{color:#687582}\n.home-light-ui .table-wrap{border:1px solid var(--stroke);border-radius:14px}\n.home-light-ui .ledger{min-width:520px}\n.home-light-ui .ledger th,.home-light-ui .ledger td{padding:12px}\n.home-light-ui .empty{color:#667481}\n.home-light-ui a:focus-visible,.home-light-ui button:focus-visible{outline:3px solid #087f78;outline-offset:3px}\n@media(max-width:760px){body.home-light .wrap{padding:0 15px 40px}.home-header{min-height:66px;flex-wrap:wrap;margin-bottom:18px}.home-nav{order:3;width:100%;overflow:auto;gap:20px;padding:0 0 13px;white-space:nowrap}.home-hero{padding:22px 18px}.home-balance{grid-template-columns:1fr}.home-grid{grid-template-columns:1fr}.home-trust{grid-template-columns:1fr}.home-head-actions .home-btn{padding:9px 12px}.home-section-head{align-items:start;flex-direction:column}}\n\n\n\n/* TRAINAI auth + workspace refinement — Material 3 / Linear */\n:root{--bg:#0e1013;--surface:rgba(26,29,36,.78);--surface2:#202630;--line:rgba(168,199,250,.14);--muted:#9aa0a6;--text:#f1f3f4;--blue:#a8c7fa}\nbody{background:#0e1013;color:#f1f3f4}\n.sidebar{background:rgba(19,22,28,.88);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-right:1px solid var(--line)}\n.topbar{background:rgba(14,16,19,.82);border-color:var(--line)}\n.nav-link{border:1px solid transparent;transition:background .2s ease,border-color .2s ease,color .2s ease,transform .2s ease}\n.nav-link:hover{background:rgba(168,199,250,.08);border-color:rgba(168,199,250,.1);transform:translateX(2px)}\n.nav-link.active{background:rgba(168,199,250,.11);border-color:rgba(168,199,250,.16);color:#a8c7fa}\n.sidebar-foot,.surface{background:rgba(26,29,36,.78);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-color:var(--line)}\n.chat-fab{transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}.chat-fab:hover{transform:translateY(-2px);border-color:#a8c7fa;box-shadow:0 10px 34px rgba(66,133,244,.2)}\n.auth-wrap{position:relative;isolation:isolate;overflow:hidden;min-height:calc(100vh - 70px);background:#0e1013}\n.auth-wrap:before{content:\"\";position:absolute;inset:0;z-index:-2;pointer-events:none;background-image:radial-gradient(rgba(255,255,255,.04) .8px,transparent .8px);background-size:24px 24px;mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%);-webkit-mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%)}\n.auth-wrap:after{content:\"\";position:absolute;z-index:-1;pointer-events:none;width:420px;height:420px;left:calc(50% - 390px);top:8%;border-radius:50%;background:rgba(168,199,250,.12);filter:blur(110px);opacity:.9;animation:trainaiAuroraA 18s ease-in-out infinite alternate}\n.auth-wrap .auth-card{position:relative;width:min(450px,100%);padding:30px;background:rgba(26,29,36,.78);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(168,199,250,.14);border-radius:25px;box-shadow:0 24px 80px rgba(0,0,0,.34)}\n.auth-wrap .auth-card:before{content:\"\";position:absolute;z-index:-1;width:340px;height:340px;right:-190px;bottom:-170px;border-radius:50%;background:rgba(66,133,244,.08);filter:blur(110px);animation:trainaiAuroraB 18s ease-in-out infinite alternate}\n.auth-wrap h1{color:#f1f3f4;letter-spacing:-.02em;font-family:Inter,\"Plus Jakarta Sans\",sans-serif;font-size:27px!important}\n.auth-wrap .filters{display:grid;grid-template-columns:1fr 1fr;position:relative;gap:4px;padding:4px;background:rgba(10,13,18,.55);border:1px solid var(--line);border-radius:999px;isolation:isolate}\n.auth-wrap .filters:before{content:\"\";position:absolute;z-index:-1;top:4px;bottom:4px;left:4px;width:calc(50% - 6px);border-radius:999px;background:#283342;border:1px solid rgba(168,199,250,.22);transition:transform .25s cubic-bezier(.2,0,0,1)}\n.auth-wrap .filters:has(#tabRegister.active):before{transform:translateX(100%)}\n.auth-wrap .filter{border:0;background:transparent;color:#9aa0a6;padding:10px 12px;border-radius:999px;transition:color .25s ease;font-size:12px}\n.auth-wrap .filter.active{background:transparent;color:#a8c7fa}\n.auth-wrap .field{gap:8px;margin:14px 0}.auth-wrap .field label{color:#d6dae0;font-size:12px}\n.auth-wrap .field input{background:rgba(14,16,19,.75);border:1px solid rgba(168,199,250,.17);border-radius:13px;color:#f1f3f4;min-height:48px;padding:13px 14px;transition:border-color .18s,box-shadow .18s}\n.auth-wrap .field input:focus{outline:0;border-color:#a8c7fa;box-shadow:0 0 0 2px rgba(168,199,250,.22),0 0 0 5px rgba(168,199,250,.07)}\n.auth-wrap .field input::placeholder{color:#727b87}\n.password-toggle{position:absolute;right:9px;top:31px;border:1px solid var(--line);background:#202630;color:#a8c7fa;border-radius:9px;padding:6px 9px;font-size:11px;font-weight:700}\n.password-hint{font-size:11px;color:#9aa0a6;margin:7px 0 0}.password-hint.valid{color:#81c995}\n.auth-wrap .btn-primary{background:#a8c7fa;color:#062e6f;min-height:46px;font-size:13px}.auth-wrap .btn-primary:hover{background:#bfd5fa}\n.security-note{display:flex;align-items:flex-start;gap:9px;padding:12px 13px;margin-top:20px;border:1px solid rgba(129,201,149,.2);background:rgba(129,201,149,.055);border-radius:13px;color:#b8c9bf;font-size:11px;line-height:1.55}.security-note .security-icon{flex:0 0 auto;color:#81c995;font-size:15px}\n.lock-indicator{margin-left:auto;color:#858d98;font-size:11px;opacity:.8}\n@keyframes trainaiAuroraA{0%{transform:translate3d(-12px,-10px,0) scale(.94);opacity:.65}50%{transform:translate3d(45px,28px,0) scale(1.08);opacity:1}100%{transform:translate3d(5px,55px,0) scale(.98);opacity:.72}}\n@keyframes trainaiAuroraB{0%{transform:translate3d(18px,8px,0) scale(.92);opacity:.55}50%{transform:translate3d(-35px,-30px,0) scale(1.08);opacity:.9}100%{transform:translate3d(-12px,22px,0) scale(.96);opacity:.6}}\n@media(prefers-reduced-motion:reduce){.auth-wrap:after,.auth-wrap .auth-card:before{animation:none!important;transform:none!important}.nav-link,.chat-fab,.auth-wrap .filters:before{transition:none!important}}\n@media(max-width:639px){.auth-wrap{min-height:calc(100vh - 130px);padding:16px}.auth-wrap .auth-card{padding:22px 19px;border-radius:22px}}\n\n\n/* TRAINAI visual elevation pass — Georgia headings + emerald/blue aurora */\n:root{--bg:#0e1013;--surface:rgba(26,29,36,.78);--line:rgba(168,199,250,.14);--blue:#a8c7fa;--text:#f1f3f4;--muted:#9aa0a6}\nbody{background:#0e1013;color:#f1f3f4}\nh1,h2,h3,h4,h5,h6,.page-head,.brand,.top-brand,.nav-link{font-family:Georgia,\"Times New Roman\",serif;letter-spacing:-.02em}\n.auth-wrap{background:#0e1013;isolation:isolate;overflow:hidden}\n.auth-wrap:before{background-image:radial-gradient(rgba(255,255,255,.04) .8px,transparent .8px);background-size:24px 24px;mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%);-webkit-mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%)}\n.auth-wrap:after{background:radial-gradient(circle,rgba(168,199,250,.16) 0%,rgba(66,133,244,.08) 42%,transparent 72%);filter:blur(110px);width:500px;height:500px;left:calc(50% - 470px);top:2%;animation:trainaiAuroraA 18s ease-in-out infinite alternate}\n.auth-wrap .auth-card{background:rgba(26,29,36,.78);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(168,199,250,.14);box-shadow:0 28px 90px rgba(0,0,0,.38),0 0 70px rgba(66,133,244,.055)}\n.auth-wrap .auth-card:before{background:radial-gradient(circle,rgba(16,185,129,.13) 0%,rgba(66,133,244,.08) 38%,transparent 72%);width:430px;height:430px;right:-220px;bottom:-210px;filter:blur(110px);animation:trainaiAuroraB 18s ease-in-out infinite alternate}\n.auth-wrap h1{font-family:Georgia,\"Times New Roman\",serif;font-size:28px!important;line-height:1.18;letter-spacing:-.02em;color:#f1f3f4}\n.auth-wrap .eyebrow{color:#a8c7fa;letter-spacing:.14em}\n.auth-wrap .filters:before{transition:transform .25s cubic-bezier(.2,0,0,1)}\n.auth-wrap .field input:focus{outline:0;border-color:#a8c7fa;box-shadow:0 0 0 2px #a8c7fa,0 0 0 6px rgba(168,199,250,.12)}\n.auth-wrap .btn-primary{background:linear-gradient(135deg,#b7d0fa,#a8c7fa);color:#062e6f;box-shadow:0 5px 20px rgba(66,133,244,.16)}\n.sidebar{background:rgba(26,29,36,.78);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-right:1px solid rgba(168,199,250,.14)}\n.nav-link{border:1px solid transparent;transition:background .2s ease,border-color .2s ease,color .2s ease,transform .2s ease}\n.nav-link:hover{background:rgba(168,199,250,.09);border-color:rgba(168,199,250,.12);transform:translateX(2px)}\n.nav-link.active{background:rgba(168,199,250,.12);border-color:rgba(168,199,250,.18);color:#a8c7fa}\n.chat-fab{transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}.chat-fab:hover{transform:translateY(-2px);border-color:#a8c7fa;box-shadow:0 10px 34px rgba(66,133,244,.24)}\n@media(prefers-reduced-motion:reduce){.auth-wrap:after,.auth-wrap .auth-card:before{animation:none!important;transform:none!important}.nav-link,.chat-fab,.auth-wrap .filters:before{transition:none!important}}\n
/* Unified TrainAI redesign — embedded Cloudflare Worker application */
:root{color-scheme:dark;--bg:#0e1013;--surface:rgba(26,29,36,.78);--surface2:#202630;--line:rgba(168,199,250,.14);--muted:#9aa0a6;--text:#f1f3f4;--blue:#a8c7fa;--green:#81c995;--amber:#fdd663}
html,body{background:#0e1013;color:#f1f3f4}
body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
h1,h2,h3,h4,h5,h6,.page-head{font-family:Georgia,"Times New Roman",serif;letter-spacing:-.02em}
h1{font-size:28px;line-height:1.18}h2{font-size:20px;line-height:1.25}h3{font-size:18px;line-height:1.3}
.surface,.sidebar-foot,.chat-drawer,.modal{background:rgba(26,29,36,.78);border-color:rgba(168,199,250,.14);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.sidebar{background:rgba(26,29,36,.78);border-color:rgba(168,199,250,.14);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.topbar{background:rgba(14,16,19,.84);border-color:rgba(168,199,250,.14)}
.nav-link{border:1px solid transparent;transition:background .2s ease,border-color .2s ease,color .2s ease,transform .2s ease}
.nav-link:hover{background:rgba(168,199,250,.08);border-color:rgba(168,199,250,.12);transform:translateX(2px)}
.nav-link.active{background:rgba(168,199,250,.12);border-color:rgba(168,199,250,.18);color:#a8c7fa}
.btn-primary{background:#a8c7fa;color:#062e6f;box-shadow:0 6px 22px rgba(66,133,244,.15)}
.btn-primary:hover{background:#c5d9ff}
.field input,.field textarea,.field select{background:rgba(14,16,19,.78);border-color:rgba(168,199,250,.17);color:#f1f3f4}
.field input:focus,.field textarea:focus,.field select:focus{outline:0;border-color:#a8c7fa;box-shadow:0 0 0 2px rgba(168,199,250,.2),0 0 0 5px rgba(168,199,250,.07)}
.auth-wrap{position:relative;isolation:isolate;overflow:hidden;min-height:calc(100vh - 70px);padding:28px 18px;background:#0e1013}
.auth-wrap:before{content:"";position:absolute;inset:0;z-index:-2;pointer-events:none;background-image:radial-gradient(rgba(255,255,255,.04) .8px,transparent .8px);background-size:24px 24px;mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%);-webkit-mask-image:radial-gradient(ellipse at center,#000 8%,transparent 78%)}
.auth-wrap:after{content:"";position:absolute;z-index:-1;pointer-events:none;width:440px;height:440px;left:calc(50% - 420px);top:4%;border-radius:50%;background:rgba(168,199,250,.12);filter:blur(110px);animation:trainaiGlowOne 18s ease-in-out infinite alternate}
.auth-wrap .auth-card{position:relative;width:min(460px,100%);padding:30px;background:rgba(26,29,36,.78);border:1px solid rgba(168,199,250,.14);border-radius:26px;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);box-shadow:0 28px 90px rgba(0,0,0,.38),0 0 65px rgba(66,133,244,.06)}
.auth-wrap .auth-card:before{content:"";position:absolute;z-index:-1;width:360px;height:360px;right:-190px;bottom:-180px;border-radius:50%;background:rgba(66,133,244,.08);filter:blur(110px);animation:trainaiGlowTwo 18s ease-in-out infinite alternate}
.auth-wrap h1{font-family:Georgia,"Times New Roman",serif;font-size:26px!important;line-height:1.2;letter-spacing:-.02em;color:#f1f3f4}
.auth-wrap .eyebrow{color:#a8c7fa;letter-spacing:.15em}
.auth-wrap .filters{display:grid;grid-template-columns:1fr 1fr;position:relative;gap:4px;padding:4px;background:rgba(10,13,18,.62);border:1px solid rgba(168,199,250,.14);border-radius:999px;isolation:isolate}
.auth-wrap .filters:before{content:"";position:absolute;z-index:-1;top:4px;bottom:4px;left:4px;width:calc(50% - 6px);border-radius:999px;background:#283342;border:1px solid rgba(168,199,250,.22);transition:transform .25s cubic-bezier(.2,0,0,1)}
.auth-wrap .filters:has(#tabRegister.active):before{transform:translateX(100%)}
.auth-wrap .filter{border:0;background:transparent;color:#9aa0a6;padding:10px 12px;border-radius:999px;transition:color .25s ease;font-size:12px}
.auth-wrap .filter.active{background:transparent;color:#a8c7fa}
.auth-wrap .field{gap:8px;margin:14px 0}
.auth-wrap .field label{color:#d6dae0;font-size:12px}
.auth-wrap .field input{background:rgba(14,16,19,.78);border:1px solid rgba(168,199,250,.17);border-radius:13px;color:#f1f3f4;min-height:48px;padding:13px 14px;transition:border-color .18s,box-shadow .18s}
.auth-wrap .field input:focus{outline:0;border-color:#a8c7fa;box-shadow:0 0 0 2px rgba(168,199,250,.2),0 0 0 5px rgba(168,199,250,.07)}
.auth-wrap .field input::placeholder{color:#727b87}
.auth-wrap .password-toggle{top:31px;border:1px solid rgba(168,199,250,.14);background:#202630;color:#a8c7fa;border-radius:9px;padding:7px 10px;font-size:11px;font-weight:700}
.auth-wrap .password-hint{font-size:11px;color:#9aa0a6;margin:7px 0 0}
.auth-wrap .password-hint.valid{color:#81c995}
.auth-wrap .btn-primary{background:#a8c7fa;color:#062e6f;min-height:46px;font-size:13px}
.auth-wrap .btn-primary:hover{background:#c5d9ff}
.auth-wrap .auth-error,.auth-wrap #authError{color:#f28b82}
.lock-indicator{margin-left:auto;color:#858d98;font-size:11px;opacity:.8}
.chat-fab{transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}
.chat-fab:hover{transform:translateY(-2px);border-color:#a8c7fa;box-shadow:0 10px 34px rgba(66,133,244,.2)}
/* Keep the public landing page dark and aligned with the workspace design. */
body.home-light{background:#0e1013;color:#f1f3f4;color-scheme:dark}
body.home-light .main{background:#0e1013}
.home-light-ui{--ink:#f1f3f4;--sub:#9aa0a6;--paper:#0e1013;--card:rgba(26,29,36,.78);--stroke:rgba(168,199,250,.14);--accent:#a8c7fa;--accent-soft:rgba(168,199,250,.08);color:#f1f3f4;background:#0e1013}
.home-header{border-color:rgba(168,199,250,.14)}
.home-brand{color:#f1f3f4!important}.home-brand b{color:#a8c7fa}
.home-nav{color:#9aa0a6}.home-nav a:hover{color:#a8c7fa}
.home-hero{background:radial-gradient(ellipse at 85% 0%,rgba(66,133,244,.13),transparent 45%),rgba(26,29,36,.72);border-color:rgba(168,199,250,.16)}
.home-card,.home-task,.home-reward{background:rgba(26,29,36,.78);border-color:rgba(168,199,250,.14);box-shadow:0 12px 40px rgba(0,0,0,.14)}
.home-section h2,.home-task h3{color:#f1f3f4}
.home-sub,.home-muted,.home-task p,.home-mini{color:#9aa0a6}
.home-balance-card{background:linear-gradient(135deg,#1d3442,#17242d);border:1px solid rgba(168,199,250,.18)}
.home-tag{background:rgba(168,199,250,.1);color:#a8c7fa}
.home-btn{background:#a8c7fa;color:#062e6f!important}.home-btn:hover{background:#c5d9ff}
.home-btn.secondary{background:#202630;color:#dce7f7!important;border-color:rgba(168,199,250,.16)}
.home-trust article{background:rgba(26,29,36,.78);border-color:rgba(168,199,250,.14)}
.home-footer{border-color:rgba(168,199,250,.14);color:#858d98}
@keyframes trainaiGlowOne{0%{transform:translate3d(-12px,-10px,0) scale(.94);opacity:.65}50%{transform:translate3d(42px,26px,0) scale(1.07);opacity:1}100%{transform:translate3d(5px,50px,0) scale(.98);opacity:.72}}
@keyframes trainaiGlowTwo{0%{transform:translate3d(15px,8px,0) scale(.92);opacity:.55}50%{transform:translate3d(-32px,-28px,0) scale(1.08);opacity:.9}100%{transform:translate3d(-10px,20px,0) scale(.96);opacity:.6}}
@media(max-width:639px){.auth-wrap{min-height:calc(100vh - 130px);padding:16px}.auth-wrap .auth-card{padding:23px 19px;border-radius:22px}}
@media(prefers-reduced-motion:reduce){.auth-wrap:after,.auth-wrap .auth-card:before{animation:none!important;transform:none!important}.nav-link,.chat-fab,.auth-wrap .filters:before{transition:none!important}}

/* TrainAI dashboard — premium dark workspace */
.dash-layout{display:flex;flex-direction:column;gap:22px;padding-bottom:34px}
.dash-layout .surface{background:rgba(19,24,34,.84);border:1px solid rgba(168,199,250,.13);border-radius:22px;box-shadow:0 12px 36px rgba(0,0,0,.12)}
.dash-wallet{position:relative;overflow:hidden;padding:clamp(22px,3.4vw,34px);border:1px solid rgba(168,199,250,.24);border-radius:25px;background:radial-gradient(ellipse at 92% 0%,rgba(79,70,229,.24),transparent 42%),linear-gradient(120deg,#182334 0%,#111a29 58%,#121a28 100%);box-shadow:0 20px 54px rgba(0,0,0,.22)}
.dash-wallet:after{content:"";position:absolute;right:-78px;bottom:-150px;width:300px;height:300px;border:1px solid rgba(168,199,250,.12);border-radius:50%;box-shadow:0 0 0 28px rgba(168,199,250,.025),0 0 0 58px rgba(168,199,250,.02);pointer-events:none}
.dash-wallet-top,.dash-section-top,.dash-progress-head,.dash-wallet-bottom,.dash-bonus-foot{display:flex;align-items:center;justify-content:space-between;gap:12px}
.dash-kicker{display:block;color:#9aa9bf;font-size:10px;font-weight:800;letter-spacing:1.35px}
.dash-status{display:inline-flex;align-items:center;gap:7px;margin-top:10px;color:#b8c7d9;font-size:11px}
.dash-status i{width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 12px rgba(16,185,129,.65)}
.dash-wallet-icon{display:grid;place-items:center;width:43px;height:43px;border:1px solid rgba(168,199,250,.2);border-radius:14px;background:rgba(168,199,250,.08);color:#a8c7fa;font-size:12px;font-weight:850}
.dash-balance{margin:19px 0 5px;color:#f1f3f4;font-size:clamp(34px,5.4vw,51px);font-weight:800;letter-spacing:-2px;line-height:1.1;font-variant-numeric:tabular-nums}
.dash-balance span{font-size:13px;font-weight:700;letter-spacing:.5px;color:#a8c7fa}
.dash-wallet-note,.dash-copy{margin:0;color:#aeb9c9;font-size:12px;line-height:1.65}
.dash-progress-head{margin-top:26px;color:#c4cfdd;font-size:11px}.dash-progress-head strong{color:#a8c7fa;font-variant-numeric:tabular-nums}
.dash-progress{height:8px;margin-top:9px;overflow:hidden;border-radius:99px;background:#2b3546}
.dash-progress span{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#4f46e5,#a8c7fa);box-shadow:0 0 16px rgba(168,199,250,.35);transition:width .35s ease}
.dash-wallet-bottom{margin-top:9px;color:#9aa8bb;font-size:10px}
.dash-withdraw{margin-top:21px;min-height:46px;padding-inline:19px;background:#a8c7fa!important;color:#062e6f!important;border:0!important;font-weight:850}
.dash-withdraw:disabled{opacity:.42;cursor:not-allowed}
.dash-payout-note{margin:10px 0 0;color:#8291a5;font-size:10px}
.dash-bonus{padding:24px;position:relative;overflow:hidden}
.dash-bonus:before{content:"";position:absolute;right:-44px;top:-65px;width:160px;height:160px;border-radius:50%;background:rgba(245,158,11,.07);filter:blur(5px);pointer-events:none}
.dash-bonus-pill{padding:5px 9px;border-radius:99px;border:1px solid rgba(245,158,11,.25);background:rgba(245,158,11,.09);color:#f6c56b;font-size:10px;font-weight:750}
.dash-bonus-value{margin:18px 0 7px;color:#f4c56d;font-size:clamp(29px,4vw,38px);font-weight:800;letter-spacing:-1.1px;font-variant-numeric:tabular-nums}
.dash-bonus-steps{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:22px 0 11px}
.dash-bonus-steps span{height:7px;border-radius:99px;background:#343b48}
.dash-bonus-steps span.complete{background:linear-gradient(90deg,#d97706,#fbbf24);box-shadow:0 0 12px rgba(245,158,11,.18)}
.dash-bonus-foot{font-size:11px;color:#cbd5e1}.dash-bonus-foot strong{font-weight:750}
.dash-info{border:0;background:transparent;color:#a8c7fa;font-size:10px;font-weight:700;cursor:pointer}
.dash-bonus-info{margin-top:13px;padding:12px;border:1px solid rgba(168,199,250,.14);border-radius:12px;background:rgba(168,199,250,.06);color:#aeb9c9;font-size:11px;line-height:1.6}
.dash-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.dash-stat{display:flex;align-items:center;gap:13px;padding:17px!important;min-width:0}
.dash-stat-icon{display:grid;place-items:center;flex:0 0 36px;height:36px;border-radius:12px;font-size:16px;font-weight:800}
.dash-stat-icon.blue{background:rgba(168,199,250,.12);color:#a8c7fa}.dash-stat-icon.violet{background:rgba(129,140,248,.13);color:#a5b4fc}.dash-stat-icon.amber{background:rgba(245,158,11,.12);color:#fbbf24}
.dash-stat strong{display:block;margin-top:5px;color:#f1f3f4;font-size:24px;line-height:1.1;font-variant-numeric:tabular-nums}
.dash-stat strong em{font-size:11px;color:#9aa0a6;font-style:normal;font-weight:600}
.dash-stat small{display:block;margin-top:5px;color:#8996a8;font-size:10px;line-height:1.4}
.dash-section{margin-top:8px}.dash-section-heading{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:14px}
.dash-section-heading h2{margin:6px 0 4px;color:#f1f3f4;font-family:Georgia,serif;font-size:22px;font-weight:500;letter-spacing:-.35px}
.dash-section-heading p{margin:0;color:#929eaf;font-size:11px;line-height:1.6}
.dash-text-link{flex:0 0 auto;color:#a8c7fa!important;font-size:11px;font-weight:750;text-decoration:none}
.dash-text-link:hover{color:#d2e3fc!important}
.dash-task-grid .task-card{background:rgba(19,24,34,.84);border:1px solid rgba(168,199,250,.13);border-radius:19px;box-shadow:none}
.dash-task-grid .task-card h3{color:#f1f3f4;font-family:Georgia,serif;font-size:18px;font-weight:500}
.dash-task-grid .task-card p{color:#9aa6b7;line-height:1.6}
.dash-task-grid .task-card .btn-secondary{border-color:rgba(168,199,250,.2);background:rgba(168,199,250,.08);color:#c9dcf7}
.dash-activity{padding:22px!important;overflow:hidden}
.dash-activity .ledger{color:#dce3ed}.dash-activity .ledger th{color:#8997aa}.dash-activity .ledger td{border-color:rgba(168,199,250,.1)}
.dash-footnote{margin:0;color:#758397;font-size:10px;line-height:1.6}
@media(min-width:900px){.dash-layout> .dash-wallet,.dash-layout> .dash-bonus{min-width:0}.dash-layout>.dash-wallet{grid-column:1}.dash-layout>.dash-bonus{grid-column:2}.dash-layout{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(290px,.75fr);align-items:stretch}.dash-stats,.dash-section,.dash-activity,.dash-footnote{grid-column:1/-1}}
@media(max-width:700px){.dash-stats{grid-template-columns:1fr}.dash-stat{padding:14px!important}.dash-section-heading{align-items:flex-start;flex-direction:column}.dash-wallet-bottom{align-items:flex-start;flex-direction:column;gap:4px}.dash-activity{padding:15px!important}.dash-activity .table-wrap{overflow-x:auto}.dash-activity .ledger{min-width:560px}}
@media(prefers-reduced-motion:reduce){.dash-progress span{transition:none}}

</style>\n</head>\n<body>\n<div class=\"shell\">\n<aside class=\"sidebar\" id=\"sidebar\">\n<a class=\"brand\" href=\"/\">TrainAI<b>.ug</b></a>\n<div class=\"nav-label\">Workspace</div>\n<nav class=\"nav-list\" id=\"sideNav\">\n<a class=\"nav-link\" data-route=\"/\" href=\"/\"><span class=\"nav-icon\">⌂</span>Home</a>\n<a class=\"nav-link\" data-route=\"/dashboard\" href=\"/dashboard\"><span class=\"nav-icon\">▦</span>Dashboard</a>\n<a class=\"nav-link\" data-route=\"/tasks\" href=\"/tasks\"><span class=\"nav-icon\">✧</span>AI Tasks <span class=\"tag blue\" id=\"taskBadge\">—</span></a>\n<a class=\"nav-link\" data-route=\"/statements\" href=\"/statements\"><span class=\"nav-icon\">▤</span>Statements</a>\n<a class=\"nav-link\" data-route=\"/referrals\" href=\"/referrals\"><span class=\"nav-icon\">♧</span>Referrals</a>\n<a class=\"nav-link\" data-route=\"/support\" href=\"/support\"><span class=\"nav-icon\">◌</span>Support</a>\n<a class=\"nav-link\" data-route=\"/profile\" href=\"/profile\"><span class=\"nav-icon\">⚙</span>Settings & account</a>\n</nav>\n</aside>\n<div class=\"main\">\n<header class=\"topbar\">\n<a class=\"top-brand\" href=\"/\">TrainAI.ug</a>\n<button id=\"sidebarToggle\" class=\"btn btn-secondary top-context\" type=\"button\" aria-label=\"Collapse navigation\">☰</button><div class=\"top-context muted small\">Contributor workspace</div>\n<div class=\"user-menu\">\n<a class=\"balance-pill\" href=\"/statements\"><span class=\"muted\">Available</span><strong id=\"topBalance\">— UGX</strong></a>\n<a class=\"avatar\" href=\"/profile\" id=\"userAvatar\" aria-label=\"My account\">TA</a>\n</div>\n</header>\n<main class=\"wrap\" id=\"view\"><div class=\"surface surface-pad\"><div class=\"skeleton loading-line\" style=\"width:40%\"></div><div class=\"skeleton loading-line\" style=\"width:80%;height:30px\"></div><div class=\"skeleton loading-line\" style=\"width:65%\"></div></div></main>\n</div>\n<nav class=\"mobile-nav\" id=\"mobileNav\">\n<a data-route=\"/dashboard\" href=\"/dashboard\"><i>⌂</i>Dashboard</a>\n<a data-route=\"/tasks\" href=\"/tasks\"><i>✧</i>Tasks</a>\n<a data-route=\"/statements\" href=\"/statements\"><i>▤</i>Statements</a>\n<a data-route=\"/support\" href=\"/support\"><i>◌</i>Support</a>\n</nav>\n</div>\n<button class=\"chat-fab\" id=\"chatFab\" type=\"button\">✦ Help</button>\n<div class=\"chat-drawer hidden\" id=\"chatDrawer\">\n<div style=\"display:flex;align-items:center;justify-content:space-between\"><strong>TrainAI Help</strong><button class=\"btn btn-quiet\" id=\"chatClose\" type=\"button\">Close ×</button></div>\n<p class=\"muted small\">Quick answers and support for your account.</p>\n<button class=\"quick-reply\" data-help=\"Check my payout status\">Check my payout status</button>\n<button class=\"quick-reply\" data-help=\"Why is my task still in review?\">Why is my task still in review?</button>\n<button class=\"quick-reply\" data-help=\"How to unlock 5,000 UGX bonus\">How to unlock 5,000 UGX bonus</button>\n<div id=\"chatAnswer\" class=\"muted small\" style=\"line-height:1.7;margin:12px 0\"></div>\n<form id=\"quickTicketForm\" style=\"border-top:1px solid var(--line);padding-top:12px\">\n<input id=\"quickTicketSubject\" required minlength=\"4\" maxlength=\"120\" placeholder=\"Support subject\" style=\"width:100%;background:#18191a;border:1px solid var(--line);border-radius:10px;padding:10px;color:var(--text);font-size:11px;margin-bottom:8px\">\n<textarea id=\"quickTicketMessage\" required minlength=\"10\" maxlength=\"3000\" placeholder=\"Describe your issue. Never include a PIN or password.\" style=\"width:100%;min-height:76px;background:#18191a;border:1px solid var(--line);border-radius:10px;padding:10px;color:var(--text);font-size:11px\"></textarea>\n<button class=\"btn btn-secondary\" type=\"submit\" style=\"width:100%;margin-top:8px\">Send support ticket</button>\n</form>\n<a class=\"btn btn-quiet\" href=\"/support\" style=\"width:100%\">Open Help Center</a>\n</div>\n<div id=\"modalRoot\"></div><div id=\"toastRoot\" aria-live=\"polite\"></div>\n<script>\n(function(){\n\"use strict\";\nconst MIN_PAYOUT=25000, BONUS=5000;\nconst state={user:null,surveys:[],completedIds:[],ledger:[],tickets:[],route:location.pathname,task:null,attemptId:null,taskStartedAt:0,answers:{},filter:\"All\",ledgerFilter:\"All\",authenticated:false};\nconst view=document.getElementById(\"view\");\nconst fmt=n=>Number(n||0).toLocaleString(\"en-UG\")+\" UGX\";\nconst esc=s=>String(s??\"\").replace(/[&<>\"']/g,c=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#39;\"}[c]));\nconst json=async(url,options={})=>{const r=await fetch(url,{credentials:\"same-origin\",cache:\"no-store\",...options,headers:{\"Content-Type\":\"application/json\",...(options.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok||d.success===false)throw new Error(d.error||\"Request failed. Please try again.\");return d};\nconst post=(url,body)=>json(url,{method:\"POST\",body:JSON.stringify(body)});\nfunction toast(message){const root=document.getElementById(\"toastRoot\");root.innerHTML='<div class=\"toast\">✦ '+esc(message)+'</div>';setTimeout(()=>{root.innerHTML=\"\"},3800)}\nfunction activeRoute(){const p=location.pathname.replace(/\\/+$/,\"\")||\"/\";const aliases={\"/index.html\":\"/\",\"/dashboard.html\":\"/dashboard\",\"/survey.html\":\"/tasks\",\"/wallet.html\":\"/statements\",\"/register.html\":\"/auth\"};return aliases[p]||p}\nfunction updateNav(){const route=activeRoute();document.querySelectorAll(\"[data-route]\").forEach(a=>a.classList.toggle(\"active\",a.dataset.route===route));}\nfunction setBalance(){const amount=state.user?.available_balance_ugx;document.getElementById(\"topBalance\").textContent=state.user?fmt(amount):\"Sign in\";document.getElementById(\"userAvatar\").textContent=state.user?.full_name?state.user.full_name.split(/\\s+/).map(x=>x[0]).join(\"\").slice(0,2).toUpperCase():\"TA\";document.getElementById(\"taskBadge\").textContent=state.surveys.filter(s=>!state.completedIds.includes(s.id)).length||\"0\";}\nasync function loadData(){try{const d=await json(\"/api/user\");state.user=d.user;state.surveys=d.surveys||[];state.completedIds=d.completedIds||[];state.ledger=d.ledger||[];state.authenticated=true;setBalance();return true}catch(e){state.user=null;state.authenticated=false;setBalance();return false}}\nfunction shellHead(kicker,title,sub,action){return '<div class=\"page-head\"><div><div class=\"eyebrow\">'+kicker+'</div><h1>'+title+'</h1><div class=\"lead\">'+sub+'</div></div>'+(action||\"\")+'</div>'}\nfunction statusTag(s,type){const x=String(s||\"pending\").toLowerCase();const label=type===\"withdrawal\"&&x===\"completed\"?\"Paid\":x===\"completed\"?\"Approved\":x===\"pending\"?\"In Review\":x.replace(/_/g,\" \");const cls=[\"approved\",\"completed\",\"paid\"].includes(x)?\"green\":[\"pending\",\"in_review\",\"processing\"].includes(x)?\"amber\":\"blue\";return '<span class=\"tag '+cls+'\">'+esc(label)+'</span>'}\nfunction renderHome(){\n if(!state.authenticated){renderPublicHome();return;}\n renderMemberHome();\n}\nfunction renderPublicHome(){\n view.innerHTML='<div class=\"home-light-ui\"><header class=\"home-header\"><a class=\"home-brand\" href=\"/\">TrainAI<b>.ug</b></a><nav class=\"home-nav\" aria-label=\"Main navigation\"><a href=\"#how\">How it works</a><a href=\"#earn\">Ways to earn</a><a href=\"#rewards\">Rewards</a><a href=\"#trust\">Trust & privacy</a></nav><div class=\"home-head-actions\"><a class=\"home-btn secondary\" href=\"/auth\">Sign in</a><a class=\"home-btn\" href=\"/auth\">Join free</a></div></header><section class=\"home-hero\"><span class=\"home-tag\">MADE FOR CONTRIBUTORS IN UGANDA</span><h1>Your local knowledge can help improve AI.</h1><p class=\"home-sub\">Complete short AI feedback tasks, help check language and answer quality, and earn rewards when your work is approved. Your wallet is shown in Ugandan shillings — no confusing points conversion.</p><div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:18px\"><a class=\"home-btn\" href=\"/auth\">Create your free account →</a><a class=\"home-btn secondary\" href=\"#how\">See how it works</a></div><p class=\"home-muted\" style=\"margin-top:13px\">A reserved 5,000 UGX welcome bonus unlocks after 3 approved tasks. It is conditional, not guaranteed income.</p></section><section id=\"how\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>How TrainAI works</h2><p class=\"home-muted\">A simple process, with rewards explained before you start.</p></div></div><div class=\"home-grid\"><article class=\"home-card\"><span class=\"home-tag\">01 · Join</span><h3>Set up your account</h3><p class=\"home-muted\">Register with your name, email and phone number. You do not need to share your Mobile Money PIN or OTP.</p></article><article class=\"home-card\"><span class=\"home-tag\">02 · Contribute</span><h3>Complete short tasks</h3><p class=\"home-muted\">Compare AI answers, check factual quality and review local-language content when tasks are available.</p></article><article class=\"home-card\"><span class=\"home-tag\">03 · Earn</span><h3>Get approved rewards</h3><p class=\"home-muted\">Each task shows its UGX reward. A reviewer checks your submission before it is credited to your available balance.</p></article></div></section><section id=\"earn\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Ways to contribute</h2><p class=\"home-muted\">Task availability can change. Rewards are displayed on each task.</p></div></div><div class=\"home-grid\"><article class=\"home-task\"><span class=\"home-tag\">Language quality</span><h3>Review local-language text</h3><p>Check whether wording is natural and understandable in the language shown in the task.</p><div class=\"home-task-foot\"><span class=\"home-mini\">Reward shown before you begin</span><span class=\"home-mini\">When available</span></div></article><article class=\"home-task\"><span class=\"home-tag\">Answer quality</span><h3>Compare AI responses</h3><p>Choose the clearer, more useful answer and add brief feedback where requested.</p><div class=\"home-task-foot\"><span class=\"home-mini\">Reward shown before you begin</span><span class=\"home-mini\">When available</span></div></article><article class=\"home-task\"><span class=\"home-tag\">Accuracy</span><h3>Check factual claims</h3><p>Flag unclear or unsupported statements. Do not submit private or personal information.</p><div class=\"home-task-foot\"><span class=\"home-mini\">Reward shown before you begin</span><span class=\"home-mini\">When available</span></div></article></div></section><section id=\"rewards\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Rewards, in plain UGX</h2><p class=\"home-muted\">No hidden points conversion: 1 UGX credited to your wallet equals 1 UGX.</p></div></div><div class=\"home-card\" style=\"display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap\"><div><span class=\"home-tag\">Mobile Money reward</span><h3 style=\"margin:10px 0 5px\">Cash out to MTN MoMo or Airtel Money</h3><p class=\"home-muted\">Minimum withdrawal request: 25,000 UGX. Your payout destination must be saved and locked.</p><strong style=\"font-size:24px;color:#087f78\">25,000 UGX minimum</strong></div><a class=\"home-btn\" href=\"/auth\">Join to earn rewards</a></div><p class=\"home-muted\" style=\"margin-top:10px\">Payout requests are manually reviewed. A submitted request is not proof that money has been transferred.</p></section><section id=\"trust\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Trust, privacy and support</h2><p class=\"home-muted\">Know what happens to your information before you take part.</p></div></div><div class=\"home-trust\"><article><strong>What AI work means</strong><span class=\"home-muted\">Your feedback helps evaluate response quality. TrainAI tasks are human review activities, not a promise that every answer is correct.</span></article><article><strong>What information is used</strong><span class=\"home-muted\">Account details support sign-in; task answers are reviewed for quality; saved payout details are used to process withdrawal requests. Avoid entering sensitive personal data in task answers.</span></article><article><strong>Keep payments safe</strong><span class=\"home-muted\">TrainAI does not need your MoMo PIN or OTP. Contact support if a task, account or payout request looks wrong.</span></article></div><div class=\"home-footer\"><span>© TrainAI.ug · Uganda</span><span><a href=\"#trust\">Privacy information</a> · <a href=\"/auth\">Sign in for support</a> · <a href=\"#how\">How it works</a></span></div></section></div>';\n}\nfunction renderMemberHome(){\n const u=state.user||{},bal=Number(u.available_balance_ugx||0),locked=Number(u.locked_bonus_ugx||0),done=Number(u.approved_task_count||0),pct=Math.min(100,Math.round(bal/MIN_PAYOUT*100)),remaining=Math.max(0,MIN_PAYOUT-bal),bonusDone=Math.min(3,done),first=(u.full_name||\"Contributor\").split(/\\\\s+/)[0],initials=(u.full_name||\"TA\").split(/\\\\s+/).map(x=>x[0]).join(\"\").slice(0,2).toUpperCase(),available=state.surveys.filter(x=>!state.completedIds.includes(x.id)).slice(0,3);\n const tasks=available.length?available.map(t=>'<article class=\"home-task\"><span class=\"home-tag\">'+esc(t.category||\"AI task\")+'</span><h3>'+esc(t.title)+'</h3><p>'+esc(t.description||\"Review the content and submit careful feedback.\")+'</p><div class=\"home-task-foot\"><strong style=\"color:#087f78;font-size:13px\">+'+fmt(t.reward_ugx)+'</strong><a class=\"home-btn secondary\" href=\"/tasks?task='+encodeURIComponent(t.id)+'\">Start task</a></div><div class=\"home-mini\" style=\"margin-top:9px\">Available · reviewed before reward credit</div></article>').join(\"\"):'<div class=\"home-card home-muted\">No new tasks are available right now. Check again later or visit the task list.</div>';\n const activity=ledgerRows(state.ledger.slice(0,5));\n view.innerHTML='<div class=\"home-light-ui\"><header class=\"home-header\"><a class=\"home-brand\" href=\"/\">TrainAI<b>.ug</b></a><nav class=\"home-nav\" aria-label=\"Main navigation\"><a href=\"#earn\">Ways to earn</a><a href=\"#rewards\">Rewards</a><a href=\"#activity\">Activity</a><a href=\"#how\">How it works</a></nav><div class=\"home-head-actions\"><a class=\"home-btn secondary\" href=\"/profile\">Account</a><a class=\"home-profile\" href=\"/profile\" aria-label=\"My account\">'+esc(initials)+'</a></div></header><section class=\"home-hero\"><span class=\"home-tag\">YOUR CONTRIBUTOR HOME</span><h1>Hello, '+esc(first)+'. Keep your progress moving.</h1><p class=\"home-sub\">Every approved task adds to your UGX reward balance. Your submitted work stays in review until it is approved.</p></section><section class=\"home-balance\"><article class=\"home-card home-balance-card\"><span class=\"home-muted\">AVAILABLE REWARDS</span><div class=\"home-balance-value\">'+fmt(bal)+'</div><p class=\"home-muted\">Approximate cash value: <strong style=\"color:#fff\">'+fmt(bal)+'</strong>. TrainAI displays wallet rewards directly in UGX — 1 UGX credited = 1 UGX.</p><button class=\"home-btn\" id=\"homeRedeem\" '+(bal<MIN_PAYOUT?'disabled':'')+'>Redeem rewards →</button><p class=\"home-muted\" style=\"margin-top:10px\">'+(bal<MIN_PAYOUT?'You need '+fmt(remaining)+' more in approved rewards to reach the minimum cashout.':'You have reached the 25,000 UGX minimum request threshold.')+'</p></article><article class=\"home-card\"><span class=\"home-tag\">NEXT REWARD</span><h3 style=\"margin:12px 0 5px\">Mobile Money cashout</h3><div class=\"home-reward-cost\">25,000 UGX</div><p class=\"home-muted\">Minimum request to MTN MoMo or Airtel Money. No platform fee is currently charged by TrainAI.</p><div class=\"home-progress\" role=\"progressbar\" aria-label=\"Progress to minimum cashout\" aria-valuemin=\"0\" aria-valuemax=\"25000\" aria-valuenow=\"'+Math.min(bal,MIN_PAYOUT)+'\"><span style=\"width:'+pct+'%\"></span></div><div class=\"home-mini\">'+fmt(bal)+' of 25,000 UGX · '+pct+'% complete</div></article></section><section id=\"earn\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Ways to earn</h2><p class=\"home-muted\">Choose a short task. Its reward and requirements are shown before you submit.</p></div><a class=\"home-btn secondary\" href=\"/tasks\">All tasks</a></div><div class=\"home-grid\">'+tasks+'</div></section><section id=\"rewards\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Rewards catalog</h2><p class=\"home-muted\">Only rewards currently supported by your account are listed here.</p></div></div><article class=\"home-reward\"><span class=\"home-tag\">UGX cash reward</span><h3 style=\"margin:10px 0 3px\">MTN MoMo / Airtel Money</h3><div class=\"home-reward-cost\">25,000 UGX minimum</div><p class=\"home-muted\">Request a payout to the Mobile Money account saved in Settings. Your payout details must be locked. Requests enter manual review; this catalog item does not mean an instant transfer.</p><button class=\"home-btn\" id=\"catalogRedeem\" '+(bal<MIN_PAYOUT?'disabled':'')+'>Redeem to Mobile Money</button><p class=\"home-mini\" style=\"margin-top:9px\">'+(bal<MIN_PAYOUT?'You are '+fmt(remaining)+' away from eligibility.':'You are eligible to request a cashout.')+'</p></article></section><section id=\"activity\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Recent activity</h2><p class=\"home-muted\">Approved earnings and payout requests in your account ledger.</p></div><a class=\"home-btn secondary\" href=\"/statements\">Full statements</a></div><div class=\"home-card\">'+activity+'</div></section><section id=\"how\" class=\"home-section\"><div class=\"home-section-head\"><div><h2>Your progress</h2><p class=\"home-muted\">Your reserved 5,000 UGX welcome bonus unlocks after three approved tasks.</p></div></div><article class=\"home-card\"><div style=\"display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap\"><strong>Welcome bonus progress</strong><span class=\"home-tag\">'+bonusDone+'/3 approved tasks</span></div><div class=\"home-progress\" role=\"progressbar\" aria-label=\"Approved tasks toward welcome bonus\" aria-valuemin=\"0\" aria-valuemax=\"3\" aria-valuenow=\"'+bonusDone+'\"><span style=\"width:'+(bonusDone/3*100)+'%\"></span></div><p class=\"home-muted\">Reserved bonus: '+fmt(locked)+'. Only approved tasks count; pending or rejected submissions do not.</p></article><div class=\"home-trust\" style=\"margin-top:14px\"><article><strong>How AI tasks work</strong><span class=\"home-muted\">You review or compare AI-generated content. Your feedback is checked by a reviewer before rewards are credited.</span></article><article><strong>What data is used</strong><span class=\"home-muted\">Account details support your account; task answers support quality review; locked payout details support withdrawal processing. Do not enter passwords, PINs or private personal details in task responses.</span></article><article><strong>Local community</strong><span class=\"home-muted\">Tasks may include Luganda and other locally relevant content when available. Invite friends to participate, but no referral reward is promised.</span></article></div></section><div class=\"home-footer\"><span>TrainAI.ug · Uganda</span><span><a href=\"#how\">Privacy information</a> · <a href=\"/support\">Support</a> · <a href=\"/referrals\">Invite friends</a></span></div></div>';\n const redeem=()=>openWithdraw();document.getElementById(\"homeRedeem\").onclick=redeem;document.getElementById(\"catalogRedeem\").onclick=redeem;\n}\nfunction renderAuth(){view.innerHTML='<div class=\"auth-wrap\"><section class=\"surface auth-card\"><div class=\"brand-mark\">T</div><div class=\"eyebrow\" style=\"margin-top:17px\">WELCOME TO TRAINAI.UG</div><h1 style=\"font-size:27px\">Your AI contributor account</h1><p class=\"muted small\">Sign in or create a free account to continue.</p><div class=\"filters\"><button class=\"filter active\" id=\"tabLogin\" type=\"button\">Sign in</button><button class=\"filter\" id=\"tabRegister\" type=\"button\">Create account</button></div><form id=\"authForm\"><div id=\"nameField\" class=\"field hidden\"><label for=\"fullName\">Full name</label><input id=\"fullName\" maxlength=\"100\" autocomplete=\"name\" placeholder=\"Your full name\"></div><div id=\"phoneField\" class=\"field hidden\"><label for=\"phone\">Ugandan Mobile Money number</label><input id=\"phone\" inputmode=\"tel\" autocomplete=\"tel\" placeholder=\"077… or +256 77…\"><span class=\"muted tiny\" id=\"networkHint\">MTN or Airtel number</span></div><div class=\"field\"><label for=\"email\">Email address</label><input id=\"email\" type=\"email\" required maxlength=\"254\" autocomplete=\"email\" placeholder=\"you@example.com\"></div><div class=\"field\"><label for=\"password\">Password</label><input id=\"password\" type=\"password\" required minlength=\"10\" maxlength=\"128\" autocomplete=\"current-password\" placeholder=\"At least 10 characters\"></div><div id=\"referralField\" class=\"field hidden\"><label for=\"referral\">Referral code (optional)</label><input id=\"referral\" maxlength=\"20\" placeholder=\"TAI-XXXXXXXX\"></div><p id=\"authError\" class=\"small\" style=\"color:var(--red)\" role=\"alert\"></p><button class=\"btn btn-primary\" id=\"authSubmit\" type=\"submit\" style=\"width:100%\">Sign in</button></form></section></div>';\nlet mode=\"login\";const form=document.getElementById(\"authForm\");document.getElementById(\"referral\").value=new URLSearchParams(location.search).get(\"ref\")||\"\";const toggle=m=>{mode=m;document.getElementById(\"tabLogin\").classList.toggle(\"active\",m===\"login\");document.getElementById(\"tabRegister\").classList.toggle(\"active\",m===\"register\");[\"nameField\",\"phoneField\",\"referralField\"].forEach(id=>document.getElementById(id).classList.toggle(\"hidden\",m!==\"register\"));document.getElementById(\"authSubmit\").textContent=m===\"login\"?\"Sign in\":\"Create free account\";document.getElementById(\"password\").autocomplete=m===\"login\"?\"current-password\":\"new-password\";};document.getElementById(\"tabLogin\").onclick=()=>toggle(\"login\");document.getElementById(\"tabRegister\").onclick=()=>toggle(\"register\");\nconst passwordInput=document.getElementById(\"password\");const passwordField=passwordInput.parentElement;passwordField.style.position=\"relative\";passwordInput.style.paddingRight=\"82px\";const eye=document.createElement(\"button\");eye.type=\"button\";eye.className=\"password-toggle\";eye.textContent=\"Show\";eye.setAttribute(\"aria-label\",\"Show password\");eye.onclick=()=>{const reveal=passwordInput.type===\"password\";passwordInput.type=reveal?\"text\":\"password\";eye.textContent=reveal?\"Hide\":\"Show\";eye.setAttribute(\"aria-label\",reveal?\"Hide password\":\"Show password\");};passwordField.append(eye);const passwordHint=document.createElement(\"p\");passwordHint.className=\"password-hint\";passwordHint.setAttribute(\"aria-live\",\"polite\");passwordHint.textContent=\"Use at least 10 characters.\";passwordField.append(passwordHint);passwordInput.addEventListener(\"input\",()=>{const valid=passwordInput.value.length>=10;passwordHint.textContent=valid?\"Password length looks good.\":passwordInput.value.length+\"/10 characters minimum\";passwordHint.classList.toggle(\"valid\",valid);passwordInput.setCustomValidity(valid?\"\":\"Use at least 10 characters.\");});document.querySelectorAll(\"#sideNav .nav-link\").forEach(link=>{if(!state.user){const lock=document.createElement(\"span\");lock.className=\"lock-indicator\";lock.textContent=\"◌\";lock.setAttribute(\"aria-label\",\"Sign in required\");link.append(lock);}});document.getElementById(\"phone\").addEventListener(\"input\",e=>{const d=e.target.value.replace(/\\D/g,\"\");let n=\"Mobile Money\";if(/^(077|078|076|039|25677|25678|25676|25639)/.test(d))n=\"MTN detected\";if(/^(070|075|074|25670|25675|25674)/.test(d))n=\"Airtel detected\";document.getElementById(\"networkHint\").textContent=n;});form.onsubmit=async e=>{e.preventDefault();const btn=document.getElementById(\"authSubmit\"),err=document.getElementById(\"authError\");err.textContent=\"\";btn.disabled=true;try{if(mode===\"register\"){const p=document.getElementById(\"phone\").value.trim();if(!/^(?:\\+?256|0)(?:70|74|75|76|77|78|39)\\d{7}$/.test(p.replace(/[\\s()-]/g,\"\")))throw new Error(\"Enter a valid Ugandan MTN or Airtel number.\");await post(\"/api/register\",{full_name:document.getElementById(\"fullName\").value.trim(),phone_number:p,email:document.getElementById(\"email\").value.trim(),password:document.getElementById(\"password\").value,referral_code:document.getElementById(\"referral\").value.trim()});toast(\"Account created. Your 5,000 UGX bonus is locked until 3 tasks are approved.\");}else{await post(\"/api/login\",{email:document.getElementById(\"email\").value.trim(),password:document.getElementById(\"password\").value});toast(\"Welcome back.\");}await loadData();navigate(\"/dashboard\");}catch(x){err.textContent=x.message||\"Could not complete this request.\";}finally{btn.disabled=false;}};}\nfunction renderDashboard(){
 const u=state.user||{},bal=Number(u.available_balance_ugx||0),locked=Number(u.locked_bonus_ugx||0),done=Number(u.approved_task_count||0),pct=Math.min(100,Math.round(bal/MIN_PAYOUT*100)),remaining=Math.max(0,MIN_PAYOUT-bal),bonusDone=Math.min(3,done),quality=u.quality_score==null?"—":u.quality_score+"%",first=(u.full_name||"Contributor").trim().split(/\s+/)[0],streak=Number(u.current_streak||0),available=state.surveys.filter(x=>!state.completedIds.includes(x.id)).slice(0,4);
 const tasks=taskCards(available);
 view.innerHTML=shellHead("CONTRIBUTOR OVERVIEW","Good to see you, "+esc(first)+".","Your work, rewards and progress — all in one place.",'<a class="btn btn-primary" href="/tasks">Explore AI tasks <span aria-hidden="true">↗</span></a>')+
 '<div class="dash-layout">'+
 '<section class="dash-wallet">'+
 '<div class="dash-wallet-top"><div><span class="dash-kicker">AVAILABLE BALANCE</span><span class="dash-status"><i></i> Approved rewards</span></div><span class="dash-wallet-icon" aria-hidden="true">UGX</span></div>'+
 '<div class="dash-balance">'+fmt(bal)+' <span>UGX</span></div>'+
 '<p class="dash-wallet-note">Your approved rewards, ready for an eligible withdrawal.</p>'+
 '<div class="dash-progress-head"><span>Withdrawal progress</span><strong>'+pct+'%</strong></div>'+
 '<div class="dash-progress" role="progressbar" aria-label="Progress toward minimum withdrawal" aria-valuemin="0" aria-valuemax="'+MIN_PAYOUT+'" aria-valuenow="'+Math.min(bal,MIN_PAYOUT)+'"><span style="width:'+pct+'%"></span></div>'+
 '<div class="dash-wallet-bottom"><span>'+(remaining?fmt(remaining)+' more to reach the minimum':'Minimum withdrawal reached')+'</span><span>Minimum '+fmt(MIN_PAYOUT)+'</span></div>'+
 '<button class="btn btn-primary dash-withdraw" id="withdrawOpen" '+(bal<MIN_PAYOUT?'disabled':'')+'>Withdraw to Mobile Money <span aria-hidden="true">→</span></button>'+
 '<p class="dash-payout-note">MTN MoMo · Airtel Money · Requests are manually reviewed</p>'+
 '</section>'+
 '<section class="surface dash-bonus">'+
 '<div class="dash-section-top"><span class="dash-kicker">WELCOME BONUS</span><span class="dash-bonus-pill">Locked</span></div>'+
 '<div class="dash-bonus-value">'+fmt(locked)+'</div>'+
 '<p class="dash-copy">Complete 3 approved tasks to unlock the reserved 5,000 UGX bonus.</p>'+
 '<div class="dash-bonus-steps" aria-label="'+bonusDone+' of 3 approved tasks completed">'+[0,1,2].map(i=>'<span class="'+(i<bonusDone?'complete':'')+'"></span>').join('')+'</div>'+
 '<div class="dash-bonus-foot"><strong>'+bonusDone+' of 3 approved</strong><button id="bonusInfo" class="dash-info" type="button" aria-expanded="false">How it works <span aria-hidden="true">ⓘ</span></button></div>'+
 '<div id="bonusInfoPanel" class="dash-bonus-info hidden">Only approved tasks count. Pending or rejected submissions do not count. After the third approval, the reserved bonus moves into your available balance automatically.</div>'+
 '</section></div>'+
 '<section class="dash-stats" aria-label="Your contributor statistics">'+
 '<article class="surface dash-stat"><span class="dash-stat-icon blue">✓</span><div><span class="dash-kicker">APPROVED TASKS</span><strong>'+done+'</strong><small>Counted toward your bonus</small></div></article>'+
 '<article class="surface dash-stat"><span class="dash-stat-icon violet">◈</span><div><span class="dash-kicker">APPROVAL ACCURACY</span><strong>'+quality+'</strong><small>Based on reviewed tasks</small></div></article>'+
 '<article class="surface dash-stat"><span class="dash-stat-icon amber">↗</span><div><span class="dash-kicker">CURRENT STREAK</span><strong>'+streak+' <em>days</em></strong><small>Approved activity streak</small></div></article>'+
 '</section>'+
 '<section class="dash-section"><div class="dash-section-heading"><div><span class="dash-kicker">READY WHEN YOU ARE</span><h2>Available AI tasks</h2><p>Choose a task that matches your skills. Rewards are shown before you begin.</p></div><a class="dash-text-link" href="/tasks">Browse all tasks <span aria-hidden="true">→</span></a></div><div class="grid two dash-task-grid" id="dashboardTasks">'+tasks+'</div></section>'+
 '<section class="surface dash-activity"><div class="dash-section-heading"><div><span class="dash-kicker">WALLET HISTORY</span><h2>Recent activity</h2><p>Track approved rewards and withdrawal requests.</p></div><a class="dash-text-link" href="/statements">View statements <span aria-hidden="true">→</span></a></div>'+ledgerRows(state.ledger.slice(0,4))+'</section>'+
 '<p class="dash-footnote">Rewards are subject to review. A withdrawal request marked pending or processing is not proof of a completed Mobile Money transfer.</p>'+
 '</div>';
 const withdraw=document.getElementById("withdrawOpen");if(withdraw)withdraw.onclick=openWithdraw;
 const bonusInfo=document.getElementById("bonusInfo");if(bonusInfo)bonusInfo.onclick=()=>{const panel=document.getElementById("bonusInfoPanel"),open=panel.classList.toggle("hidden")===false;bonusInfo.setAttribute("aria-expanded",String(open));};
}
function taskCategory(s){const c=(String(s.category||\"\")+\" \"+String(s.title||\"\")).toLowerCase();if(c.includes(\"language\")||c.includes(\"luganda\")||c.includes(\"translation\"))return \"Luganda Translation\";if(c.includes(\"factual\")||c.includes(\"fact check\"))return \"Factual Check\";return \"Response Comparison\";}\nfunction taskCards(tasks){if(!tasks.length)return '<div class=\"surface empty\">No new tasks are available right now. Check again later.</div>';return tasks.map(s=>'<article class=\"surface task-card\"><div class=\"eyebrow\">'+esc(s.category||\"AI task\")+'</div><h3>'+esc(s.title)+'</h3><p class=\"muted small\">'+esc(s.description||\"Compare AI responses and submit careful feedback.\")+'</p><div class=\"task-meta\"><span class=\"tag\">~2 mins</span><span class=\"tag green\">+'+fmt(s.reward_ugx)+'</span><span class=\"tag\">Easy</span></div><a class=\"btn btn-secondary\" href=\"/tasks?task='+encodeURIComponent(s.id)+'\">Open task →</a></article>').join(\"\");}\nfunction renderTasks(){const cats=[\"All\",\"Luganda Translation\",\"Response Comparison\",\"Factual Check\"];const filtered=state.surveys.filter(s=>state.filter===\"All\"||taskCategory(s)===state.filter).filter(s=>!state.completedIds.includes(s.id));view.innerHTML=shellHead(\"CONTRIBUTE TO AI\",\"AI task workspace\",\"Choose a task, compare the responses carefully and submit your feedback.\")+'<div class=\"filters\">'+cats.map(c=>'<button class=\"filter '+(state.filter===c?'active':'')+'\" data-filter=\"'+esc(c)+'\">'+esc(c)+'</button>').join(\"\")+'</div><div class=\"grid two\">'+taskCards(filtered)+'</div>';document.querySelectorAll(\"[data-filter]\").forEach(b=>b.onclick=()=>{state.filter=b.dataset.filter;renderTasks()});const wanted=new URLSearchParams(location.search).get(\"task\");if(wanted){const task=state.surveys.find(s=>s.id===wanted);if(task&&!state.completedIds.includes(task.id))startTask(task);}}\nasync function startTask(task){try{const d=await post(\"/api/tasks/start\",{surveyId:task.id});state.task=task;state.attemptId=d.attemptId;state.taskStartedAt=Date.now();state.answers={};renderTaskDetail();}catch(e){toast(e.message)}}\nfunction renderTaskDetail(){const t=state.task;let qs=[];try{qs=JSON.parse(t.questions_json||\"[]\")}catch{};view.innerHTML='<div class=\"page-head\"><div><div class=\"eyebrow\">'+esc(t.category||\"AI TASK\")+'</div><h1>'+esc(t.title)+'</h1><p class=\"lead\">'+esc(t.description||\"Read the prompt and compare both responses.\")+'</p></div><button class=\"btn btn-secondary\" id=\"backTasks\">← All tasks</button></div><div class=\"notice\">Your submission is reviewed before any reward is credited. Choose carefully. Do not include personal or payment details in your answers.</div><section class=\"surface surface-pad\" style=\"margin-top:16px\"><div class=\"metric-label\">Potential task reward</div><div class=\"metric-value green\">'+fmt(t.reward_ugx)+'</div><div class=\"muted tiny\">10-second minimum review time applies.</div></section><div id=\"questionList\">'+qs.map((q,i)=>'<section class=\"surface surface-pad\" style=\"margin-top:15px\"><div class=\"eyebrow\">QUESTION '+(i+1)+'</div><h3 style=\"margin-top:8px\">'+esc(q.q||q.prompt||\"Compare these responses\")+'</h3><div class=\"response\"><span class=\"tag blue\">RESPONSE A</span><p>'+esc(q.a||q.response_a||\"\")+'</p></div><div class=\"response\"><span class=\"tag\">RESPONSE B</span><p>'+esc(q.b||q.response_b||\"\")+'</p></div><div class=\"choice-row\">'+[['A','Response A is much better'],['TIE','Tie'],['B','Response B is much better']].map(x=>'<button class=\"choice\" data-q=\"'+i+'\" data-choice=\"'+x[0]+'\">'+x[1]+'</button>').join(\"\")+'</div><div class=\"filters\" style=\"margin:10px 0 0\"><span class=\"muted tiny\" style=\"align-self:center\">Quick feedback:</span>'+[\"Accurate\",\"Natural Luganda\",\"Hallucination\"].map(tag=>'<button class=\"filter\" data-feedback=\"'+i+'\" data-tag=\"'+tag+'\">'+tag+'</button>').join(\"\")+'</div></section>').join(\"\")+'</div><div style=\"display:flex;justify-content:flex-end;margin-top:18px\"><button class=\"btn btn-primary\" id=\"submitTask\">Submit for review →</button></div>';document.getElementById(\"backTasks\").onclick=()=>{state.task=null;history.replaceState({},\"\",\"/tasks\");renderTasks()};document.querySelectorAll(\"[data-choice]\").forEach(b=>b.onclick=()=>{state.answers[b.dataset.q]=state.answers[b.dataset.q]||{};state.answers[b.dataset.q].choice=b.dataset.choice;document.querySelectorAll('[data-q=\"'+b.dataset.q+'\"]').forEach(x=>x.classList.toggle(\"selected\",x===b))});document.querySelectorAll(\"[data-tag]\").forEach(b=>b.onclick=()=>{state.answers[b.dataset.feedback]=state.answers[b.dataset.feedback]||{};state.answers[b.dataset.feedback].feedback=b.dataset.tag;b.classList.toggle(\"active\")});document.getElementById(\"submitTask\").onclick=submitTask;}\nasync function submitTask(){const t=state.task;let qs=[];try{qs=JSON.parse(t.questions_json||\"[]\")}catch{};const answers=qs.map((q,i)=>({question:i,choice:state.answers[i]?.choice,feedback:state.answers[i]?.feedback||null}));if(answers.some(a=>![\"A\",\"B\",\"TIE\"].includes(a.choice))){toast(\"Please answer every comparison.\");return}const btn=document.getElementById(\"submitTask\");btn.disabled=true;try{await post(\"/api/submissions\",{surveyId:t.id,answers,attemptId:state.attemptId});toast(\"✦ \"+fmt(t.reward_ugx)+\" submitted for review — not yet earned.\");state.task=null;state.attemptId=null;history.replaceState({},\"\",\"/tasks\");await loadData();renderTasks();}catch(e){toast(e.message);btn.disabled=false;}}\nfunction ledgerRows(rows){if(!rows.length)return '<div class=\"empty\">No transactions yet. Approved rewards will appear here.</div>';return '<div class=\"table-wrap\"><table class=\"ledger\"><thead><tr><th>Date</th><th>Activity</th><th>Reference</th><th>Amount</th><th>Status</th></tr></thead><tbody>'+rows.map((x,i)=>'<tr '+(String(x.type||\"\").toLowerCase()===\"withdrawal\"?'data-receipt=\"'+i+'\" style=\"cursor:pointer\"':\"\")+'><td>'+esc(x.created_at?new Date(x.created_at).toLocaleString():\"—\")+'</td><td><strong>'+esc(String(x.type||x.transaction_type||\"Activity\").replace(/_/g,\" \"))+'</strong><div class=\"muted tiny\">'+esc(x.details||\"\")+'</div></td><td class=\"muted\">'+esc(x.reference||\"—\")+'</td><td style=\"font-weight:800;color:'+(x.type===\"withdrawal\"?\"var(--text)\":\"var(--green)\")+'\">'+(x.type===\"withdrawal\"?\"−\":\"+\")+fmt(x.amount_ugx)+'</td><td>'+statusTag(x.status,x.type)+'</td></tr>').join(\"\")+'</tbody></table></div>';}\nfunction showReceipt(item){const root=document.getElementById(\"modalRoot\");root.innerHTML='<div class=\"modal-backdrop\" id=\"receiptBackdrop\"><section class=\"modal\"><div style=\"display:flex;justify-content:space-between;align-items:center\"><h2>Withdrawal receipt</h2><button class=\"btn btn-quiet\" id=\"receiptClose\">×</button></div><div class=\"metric-value\">'+fmt(item.amount_ugx)+'</div><p class=\"muted small\">Reference: '+esc(item.reference||\"Not assigned\")+'</p><p class=\"small\">Status: '+esc(item.status||\"pending\")+'</p><p class=\"small\">Date: '+esc(item.created_at||\"—\")+'</p><p class=\"muted small\">'+esc(item.details||\"Manual Mobile Money payout request\")+'</p><div class=\"notice\">This receipt records your request. It is not proof of a completed Mobile Money transfer.</div></section></div>';document.getElementById(\"receiptClose\").onclick=()=>root.innerHTML=\"\";document.getElementById(\"receiptBackdrop\").onclick=e=>{if(e.target.id===\"receiptBackdrop\")root.innerHTML=\"\"};}\nfunction renderStatements(){const opts=[\"All\",\"Approved\",\"In Review\",\"Bonus Unlocks\",\"Withdrawals\"];let rows=state.ledger.filter(x=>{const t=String(x.type||\"\").toLowerCase(),s=String(x.status||\"\").toLowerCase();if(state.ledgerFilter===\"Approved\")return s===\"completed\"||s===\"approved\";if(state.ledgerFilter===\"In Review\")return s===\"pending\"||s===\"processing\";if(state.ledgerFilter===\"Bonus Unlocks\")return t.includes(\"bonus\");if(state.ledgerFilter===\"Withdrawals\")return t===\"withdrawal\";return true});view.innerHTML=shellHead(\"ACCOUNT ACTIVITY\",\"Statements & ledger\",\"A clear record of submitted rewards, approved credits and withdrawal requests.\")+'<div class=\"filters\">'+opts.map(o=>'<button class=\"filter '+(state.ledgerFilter===o?'active':'')+'\" data-ledger=\"'+o+'\">'+o+'</button>').join(\"\")+'</div><section class=\"surface surface-pad\">'+ledgerRows(rows)+'</section><p class=\"footer-note\">Transaction references are generated by TrainAI. A withdrawal marked pending or processing is not a completed Mobile Money transfer.</p>';document.querySelectorAll(\"[data-ledger]\").forEach(b=>b.onclick=()=>{state.ledgerFilter=b.dataset.ledger;renderStatements()});document.querySelectorAll(\"[data-receipt]\").forEach(row=>row.onclick=()=>showReceipt(rows[Number(row.dataset.receipt)]));}\nasync function renderSupport(){view.innerHTML=shellHead(\"HELP CENTER\",\"How can we help?\",\"Ask about your account, task reviews, bonus eligibility or withdrawal requests.\")+'<section class=\"grid two\"><div class=\"surface surface-pad\"><h2>Create a support ticket</h2><form id=\"ticketForm\"><div class=\"field\"><label>Subject</label><input id=\"ticketSubject\" required minlength=\"4\" maxlength=\"120\" placeholder=\"What do you need help with?\"></div><div class=\"field\"><label>Message</label><textarea id=\"ticketMessage\" required minlength=\"10\" maxlength=\"3000\" placeholder=\"Explain what happened. Do not include your password or PIN.\"></textarea></div><button class=\"btn btn-primary\" type=\"submit\">Send ticket</button></form></div><div class=\"surface surface-pad\"><h2>Common questions</h2><div class=\"faq\"><details><summary>Why is my task in review?</summary><p>Every submission is checked before a reward is credited. Pending submissions do not count toward the bonus.</p></details><details><summary>How do I check a payout?</summary><p>Open Statements to view the latest status and reference. A pending request is not a transfer confirmation.</p></details><details><summary>How do I unlock my bonus?</summary><p>Complete three tasks that are approved by the review team.</p></details></div></div></section><section class=\"surface surface-pad\" style=\"margin-top:18px\"><h2>Your support tickets</h2><div id=\"ticketList\" class=\"muted small\">Loading…</div></section>';document.getElementById(\"ticketForm\").onsubmit=async e=>{e.preventDefault();try{await post(\"/api/support\",{subject:document.getElementById(\"ticketSubject\").value.trim(),message:document.getElementById(\"ticketMessage\").value.trim()});toast(\"Support ticket submitted.\");document.getElementById(\"ticketForm\").reset();await loadTickets()}catch(x){toast(x.message)}};await loadTickets();}\nasync function loadTickets(){const el=document.getElementById(\"ticketList\");if(!el)return;try{const d=await json(\"/api/support\");const rows=d.tickets||[];el.innerHTML=rows.length?rows.map(t=>'<div style=\"padding:12px 0;border-bottom:1px solid var(--line)\"><strong>'+esc(t.subject)+'</strong><span class=\"right\">'+statusTag(t.ticket_status)+'</span><p class=\"muted tiny\">'+esc(t.created_at)+'</p><p class=\"small\">'+esc(t.message)+'</p></div>').join(\"\"):'No support tickets yet.'}catch(e){el.textContent=e.message}}\nasync function renderProfile(){const u=state.user||{};view.innerHTML=shellHead(\"ACCOUNT SETTINGS\",\"Your account\",\"Manage your profile and secure the Mobile Money destination for withdrawals.\")+'<div class=\"grid two\"><section class=\"surface surface-pad\"><h2>Profile details</h2><div class=\"field\"><label>Full name</label><input value=\"'+esc(u.full_name||\"\")+'\" disabled></div><div class=\"field\"><label>Email address</label><input value=\"'+esc(u.email||\"\")+'\" disabled></div><div class=\"field\"><label>Registration phone</label><input value=\"'+esc(u.phone_number||\"\")+'\" disabled></div><button class=\"btn btn-secondary\" id=\"logoutButton\">Sign out</button></section><section class=\"surface surface-pad\"><h2>Mobile Money payout account</h2><p class=\"muted small\">Check the registered account name and number carefully. Locking prevents accidental changes before a withdrawal.</p><form id=\"payoutForm\"><div class=\"field\"><label>Account holder name</label><input id=\"payoutName\" required maxlength=\"120\" value=\"'+esc(u.payout_name||\"\")+'\" '+(u.payout_locked?'disabled':'')+'></div><div class=\"field\"><label>Network</label><select id=\"payoutNetwork\" '+(u.payout_locked?'disabled':'')+'><option value=\"\">Choose network</option><option value=\"MTN\" '+(u.payout_network===\"MTN\"?\"selected\":\"\")+'>MTN MoMo</option><option value=\"AIRTEL\" '+(u.payout_network===\"AIRTEL\"?\"selected\":\"\")+'>Airtel Money</option></select></div><div class=\"field\"><label>Mobile Money number</label><input id=\"payoutNumber\" required inputmode=\"tel\" placeholder=\"+256 7…\" value=\"'+esc(u.payout_number||\"\")+'\" '+(u.payout_locked?'disabled':'')+'></div>'+(u.payout_locked?'<div class=\"notice success\">✓ Your payout account is locked. Contact support if your registered details need correction.</div>':'<div class=\"notice\">Once locked, these payout details cannot be edited from this page. Verify them before continuing.</div><button class=\"btn btn-primary\" type=\"submit\" style=\"margin-top:14px\">Save & lock payout account</button>')+'</form></section></div><p class=\"footer-note\">TrainAI does not request your Mobile Money PIN or one-time password. Never share these with anyone.</p>';document.getElementById(\"logoutButton\").onclick=logout;const form=document.getElementById(\"payoutForm\");if(!u.payout_locked)form.onsubmit=async e=>{e.preventDefault();if(!confirm(\"Lock this payout name, network and number? You will need support to change them later.\"))return;try{await post(\"/api/profile\",{payout_name:document.getElementById(\"payoutName\").value.trim(),payout_network:document.getElementById(\"payoutNetwork\").value,payout_number:document.getElementById(\"payoutNumber\").value.trim()});await loadData();toast(\"Payout account saved and locked.\");renderProfile()}catch(x){toast(x.message)}};}\nasync function renderReferrals(){const d=await json(\"/api/referrals\");const link=location.origin+\"/auth?ref=\"+encodeURIComponent(d.referral_code||\"\");view.innerHTML=shellHead(\"INVITE OTHERS\",\"Your referral link\",\"Share TrainAI with people who may enjoy helping improve AI.\")+'<section class=\"surface surface-pad\" style=\"max-width:680px\"><div class=\"metric-label\">Your referral code</div><div class=\"metric-value blue\">'+esc(d.referral_code||\"Not available\")+'</div><div class=\"field\"><label>Share link</label><input id=\"refLink\" readonly value=\"'+esc(link)+'\"></div><button class=\"btn btn-primary\" id=\"copyRef\">Copy referral link</button><div class=\"muted-line\"></div><div class=\"metric-label\">Registered referrals</div><div class=\"metric-value\">'+Number(d.referral_count||0)+'</div><p class=\"muted small\">Referral tracking is informational. No referral reward is promised or credited at this time.</p></section>';document.getElementById(\"copyRef\").onclick=()=>{navigator.clipboard?.writeText(link).then(()=>toast(\"Referral link copied.\")).catch(()=>toast(\"Select and copy the link.\"))};}\nfunction openWithdraw(){\n const u=state.user||{},bal=Number(u.available_balance_ugx||0),root=document.getElementById(\"modalRoot\");\n if(bal<MIN_PAYOUT){toast(\"You need at least 25,000 UGX available to request a withdrawal.\");return}\n if(!u.payout_locked||!u.payout_number||!u.payout_network){toast(\"Save and lock your Mobile Money payout account in Settings first.\");return}\n const network=String(u.payout_network).toUpperCase(),phone=String(u.payout_number),name=String(u.payout_name||\"Name not supplied\");\n const digits=phone.replace(/\\D/g,\"\").replace(/^256/,\"\").replace(/^0/,\"\"),prefix=digits.slice(0,2);\n const detected=[\"77\",\"78\",\"76\",\"39\"].includes(prefix)?\"MTN\":[\"70\",\"75\",\"74\"].includes(prefix)?\"AIRTEL\":\"UNKNOWN\";\n if(detected!==network){toast(\"Your saved network does not match your phone number prefix. Contact Support before withdrawing.\");return}\n const carrierClass=network===\"MTN\"?\"mtn\":\"airtel\",carrierName=network===\"MTN\"?\"MTN MoMo\":\"Airtel Money\";\n let step=1,amount=MIN_PAYOUT,submitting=false,showBalance=false,receipt=null,lastFocus=document.activeElement;\n const money=n=>Number(n||0).toLocaleString(\"en-UG\")+\" UGX\";\n const publicRef=id=>\"#WDL-\"+String(id||\"\").replace(/-/g,\"\").toUpperCase();\n let onKey=null;const close=()=>{root.innerHTML=\"\";document.body.style.overflow=\"\";if(onKey)document.removeEventListener(\"keydown\",onKey);if(lastFocus&&lastFocus.focus)lastFocus.focus()};\n const shell=(content)=>'<div class=\"checkout-backdrop\" id=\"checkoutBackdrop\"><section class=\"checkout-sheet\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"checkoutTitle\" aria-describedby=\"checkoutDescription\" tabindex=\"-1\"><div class=\"checkout-top\"><div><div class=\"checkout-kicker\">TrainAI · Mobile Money</div><h2 class=\"checkout-title\" id=\"checkoutTitle\">'+(step===1?\"Withdraw funds\":step===2?\"Review your request\":\"Request received\")+'</h2><p class=\"muted small\" id=\"checkoutDescription\">'+(step===1?\"Choose an amount and confirm your saved payout destination.\":step===2?\"Check every detail before submitting.\":\"Your withdrawal request has been recorded.\")+'</p></div><button type=\"button\" class=\"btn btn-quiet\" id=\"checkoutClose\" aria-label=\"Close withdrawal checkout\">×</button></div><div class=\"checkout-steps\" aria-label=\"Checkout progress\"><span class=\"'+(step>=1?\"active\":\"\")+'\"></span><span class=\"'+(step>=2?\"active\":\"\")+'\"></span><span class=\"'+(step>=3?\"active\":\"\")+'\"></span></div>'+content+'</section></div>';\n const bindClose=()=>{const closeBtn=document.getElementById(\"checkoutClose\");closeBtn.onclick=close;document.getElementById(\"checkoutBackdrop\").onclick=e=>{if(e.target.id===\"checkoutBackdrop\"&&!submitting)close()};};\n const renderAmount=()=>{\n  step=1;\n  const valid=Number.isSafeInteger(amount)&&amount>=MIN_PAYOUT&&amount<=bal;\n  root.innerHTML=shell('<div class=\"checkout-balance\"><div class=\"checkout-balance-label\"><span>Available balance</span><button type=\"button\" class=\"checkout-eye\" id=\"balanceEye\" aria-label=\"'+(showBalance?\"Hide\":\"Show\")+' available balance\">'+(showBalance?\"◉ Hide\":\"👁️ Show\")+'</button></div><div class=\"checkout-balance-value\" id=\"balanceValue\">'+(showBalance?money(bal):\"•••••• UGX\")+'</div></div><form id=\"checkoutAmountForm\" novalidate><div class=\"checkout-field\"><label for=\"checkoutAmount\">Withdrawal amount (UGX)</label><input class=\"checkout-input\" id=\"checkoutAmount\" type=\"number\" inputmode=\"numeric\" min=\"'+MIN_PAYOUT+'\" max=\"'+bal+'\" step=\"1\" value=\"'+amount+'\" aria-describedby=\"checkoutAmountHint checkoutError\" required><div class=\"muted tiny\" id=\"checkoutAmountHint\">Minimum 25,000 UGX · Maximum '+money(bal)+'</div><div class=\"checkout-quick\"><button type=\"button\" class=\"checkout-chip\" data-amount=\"'+MIN_PAYOUT+'\" aria-pressed=\"'+(amount===MIN_PAYOUT)+'\">25,000 UGX</button><button type=\"button\" class=\"checkout-chip\" data-amount=\"50000\" '+(bal<50000?\"disabled\":\"\")+' aria-pressed=\"'+(amount===50000)+'\">50,000 UGX</button><button type=\"button\" class=\"checkout-chip\" data-amount=\"'+bal+'\" aria-pressed=\"'+(amount===bal)+'\">Max</button></div><div class=\"checkout-error\" id=\"checkoutError\" role=\"alert\"></div></div><div class=\"checkout-field\"><label>Locked payout destination</label><div class=\"checkout-destination\"><div class=\"checkout-destination-head\"><span class=\"checkout-carrier '+carrierClass+'\">'+carrierName+'</span><span class=\"checkout-lock\">✓ SAVED & LOCKED</span></div><div class=\"checkout-destination-name\">'+esc(name)+'</div><div class=\"checkout-destination-number\">'+esc(phone)+'</div></div></div><div class=\"checkout-breakdown\" aria-live=\"polite\"><div class=\"checkout-breakdown-row\"><span>Withdrawal amount</span><strong id=\"breakAmount\">'+money(amount)+'</strong></div><div class=\"checkout-breakdown-row\"><span>Platform fee</span><strong>0 UGX</strong></div><div class=\"checkout-breakdown-row total\"><span>Net you receive</span><strong id=\"breakNet\">'+money(amount)+'</strong></div></div><div class=\"checkout-notice\">Manual payout review: this request is queued for administrator review. No Mobile Money transfer is sent automatically.</div><div class=\"checkout-actions\"><button class=\"checkout-btn primary\" id=\"checkoutContinue\" type=\"submit\" '+(!valid?\"disabled\":\"\")+'>Continue to review <span aria-hidden=\"true\">→</span></button></div></form>');\n  bindClose();\n  const input=document.getElementById(\"checkoutAmount\"),err=document.getElementById(\"checkoutError\"),next=document.getElementById(\"checkoutContinue\");\n  const update=()=>{amount=input.value===\"\"?NaN:Number(input.value);const ok=Number.isSafeInteger(amount)&&amount>=MIN_PAYOUT&&amount<=bal;document.getElementById(\"breakAmount\").textContent=Number.isFinite(amount)?money(amount):\"—\";document.getElementById(\"breakNet\").textContent=Number.isFinite(amount)?money(amount):\"—\";err.textContent=ok?\"\":amount<MIN_PAYOUT?\"Minimum withdrawal is 25,000 UGX.\":amount>bal?\"Amount exceeds your available balance.\":\"Enter a whole amount in UGX.\";next.disabled=!ok;document.querySelectorAll(\"[data-amount]\").forEach(b=>b.setAttribute(\"aria-pressed\",String(Number(b.dataset.amount)===amount)))};\n  input.oninput=update;\n  document.querySelectorAll(\"[data-amount]\").forEach(b=>b.onclick=()=>{amount=Number(b.dataset.amount);input.value=String(amount);update()});\n  document.getElementById(\"balanceEye\").onclick=()=>{showBalance=!showBalance;document.getElementById(\"balanceValue\").textContent=showBalance?money(bal):\"•••••• UGX\";document.getElementById(\"balanceEye\").textContent=showBalance?\"◉ Hide\":\"👁️ Show\";document.getElementById(\"balanceEye\").setAttribute(\"aria-label\",(showBalance?\"Hide\":\"Show\")+\" available balance\")};\n  document.getElementById(\"checkoutAmountForm\").onsubmit=e=>{e.preventDefault();update();if(!next.disabled)renderReview()};\n  document.getElementById(\"checkoutAmount\").focus();\n };\n const renderReview=()=>{\n  step=2;\n  root.innerHTML=shell('<div class=\"checkout-review\"><div class=\"muted tiny\">YOU ARE REQUESTING</div><div class=\"checkout-review-amount\">'+money(amount)+'</div><div class=\"checkout-review-row\"><span>Payout account name</span><strong>'+esc(name)+'</strong></div><div class=\"checkout-review-row\"><span>Carrier</span><strong><span class=\"checkout-carrier '+carrierClass+'\">'+carrierName+'</span></strong></div><div class=\"checkout-review-row\"><span>Phone number</span><strong>'+esc(phone)+'</strong></div><div class=\"checkout-review-row\"><span>Platform fee</span><strong>0 UGX</strong></div><div class=\"checkout-review-row\"><span>Net you receive</span><strong style=\"color:#81c995\">'+money(amount)+'</strong></div></div><div class=\"checkout-notice\">Security reminder: verify your number carefully. TrainAI will never ask for your Mobile Money PIN or one-time password.</div><div class=\"checkout-actions\"><button class=\"checkout-btn secondary\" type=\"button\" id=\"checkoutEdit\">← Edit details</button><button class=\"checkout-btn primary\" type=\"button\" id=\"checkoutConfirm\">Confirm & Request Payout</button></div><div class=\"checkout-error\" id=\"checkoutError\" role=\"alert\"></div>');\n  bindClose();\n  document.getElementById(\"checkoutEdit\").onclick=renderAmount;\n  document.getElementById(\"checkoutConfirm\").onclick=submit;\n };\n const renderReceipt=async d=>{\n  step=3;receipt={amount,network,carrierName,phone,name,reference:d.reference||publicRef(d.withdrawalId),createdAt:d.createdAt||new Date().toISOString(),status:d.status||\"pending\"};\n  root.innerHTML=shell('<div class=\"checkout-success-mark\" aria-hidden=\"true\">✓</div><h3 style=\"font-size:19px;margin:0 0 5px\">Request queued for review</h3><p class=\"muted small\">Your withdrawal request was saved. This is not a Mobile Money transfer confirmation.</p><div class=\"checkout-review\"><div class=\"checkout-review-row\"><span>Reference ID</span><strong>'+esc(receipt.reference)+'</strong></div><div class=\"checkout-review-row\"><span>Amount</span><strong style=\"color:#81c995\">'+money(amount)+'</strong></div><div class=\"checkout-review-row\"><span>Destination</span><strong>'+esc(carrierName+\" · \"+phone)+'</strong></div><div class=\"checkout-review-row\"><span>Requested</span><strong>'+esc(new Date(receipt.createdAt).toLocaleString(\"en-UG\"))+'</strong></div><div class=\"checkout-review-row\"><span>Status</span><strong><span class=\"checkout-carrier\" style=\"color:#fdd663;border-color:#8b7735;background:rgba(253,214,99,.08)\">Queued for Review</span></strong></div></div><div class=\"checkout-actions\"><button class=\"checkout-btn secondary\" id=\"copyCheckoutReceipt\" type=\"button\">Copy receipt details</button><button class=\"checkout-btn primary\" id=\"viewCheckoutStatements\" type=\"button\">View in Statements</button></div>');\n  bindClose();\n  document.getElementById(\"copyCheckoutReceipt\").onclick=async()=>{const text=[\"TrainAI.ug withdrawal receipt\", \"Reference: \"+receipt.reference,\"Amount: \"+money(amount),\"Payout name: \"+name,\"Carrier: \"+carrierName,\"Phone: \"+phone,\"Platform fee: 0 UGX\",\"Net: \"+money(amount),\"Requested: \"+new Date(receipt.createdAt).toLocaleString(\"en-UG\"),\"Status: Queued for Review\",\"This is a request receipt, not proof of a completed Mobile Money transfer.\"].join(\"\\n\");try{await navigator.clipboard.writeText(text);toast(\"Receipt details copied.\")}catch{toast(\"Clipboard unavailable. Please copy the reference from this screen.\")}};\n  document.getElementById(\"viewCheckoutStatements\").onclick=async()=>{close();await loadData();navigate(\"/statements\")};\n  await loadData();\n };\n const submit=async()=>{\n  if(submitting)return;\n  submitting=true;const btn=document.getElementById(\"checkoutConfirm\"),err=document.getElementById(\"checkoutError\");document.getElementById(\"checkoutClose\").disabled=true;btn.disabled=true;btn.innerHTML='<span class=\"checkout-spin\" aria-hidden=\"true\"></span>Submitting…';err.textContent=\"\";\n  try{const d=await post(\"/api/withdraw\",{amount,network,phone});submitting=false;await renderReceipt(d)}\n  catch(e){submitting=false;document.getElementById(\"checkoutClose\").disabled=false;btn.disabled=false;btn.textContent=\"Confirm & Request Payout\";err.textContent=e.message||\"We could not submit your request. Please try again.\"}\n };\n root.innerHTML=shell(\"\");\n document.body.style.overflow=\"hidden\";\n renderAmount();\n onKey=e=>{if(e.key===\"Escape\"&&!submitting){close();document.removeEventListener(\"keydown\",onKey)}if(e.key===\"Tab\"){const panel=root.querySelector('[role=\"dialog\"]');if(!panel)return;const focusables=[...panel.querySelectorAll('button:not(:disabled),input:not(:disabled),a[href]')];if(!focusables.length)return;const first=focusables[0],last=focusables[focusables.length-1];if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}}};\n document.addEventListener(\"keydown\",onKey);\n\n}\nasync function logout(){try{await post(\"/api/logout\",{})}catch{}state.user=null;state.authenticated=false;navigate(\"/\");}\nasync function render(){const route=activeRoute();state.route=route;document.body.classList.toggle(\"home-light\",route===\"/\" );updateNav();if(route===\"/\"||route===\"/index.html\"){renderHome();return}if(route===\"/auth\"||route===\"/register\"||route===\"/login\"){if(state.authenticated){navigate(\"/dashboard\");return}renderAuth();return}if(!state.authenticated){navigate(\"/auth\");return}if(route===\"/dashboard\"){renderDashboard();return}if(route===\"/tasks\"||route===\"/survey\"){renderTasks();return}if(route===\"/statements\"||route===\"/wallet\"){renderStatements();return}if(route===\"/support\"){await renderSupport();return}if(route===\"/profile\"||route===\"/settings\"){renderProfile();return}if(route===\"/referrals\"){await renderReferrals();return}renderDashboard();}\nfunction navigate(path){history.pushState({},\"\",path);render();window.scrollTo(0,0)}\ndocument.addEventListener(\"click\",e=>{const a=e.target.closest(\"a[href^='/']\");if(!a||a.target||e.metaKey||e.ctrlKey||e.shiftKey)return;const href=a.getAttribute(\"href\");if(href.startsWith(\"/#\"))return;e.preventDefault();const url=new URL(href,location.origin);history.pushState({},\"\",url.pathname+url.search+url.hash);render();window.scrollTo(0,0)});\nwindow.addEventListener(\"popstate\",render);\nconst sidebarToggle=document.getElementById(\"sidebarToggle\");if(sidebarToggle)sidebarToggle.onclick=()=>{const collapsed=document.getElementById(\"sidebar\").classList.toggle(\"collapsed\");document.querySelector(\".main\").classList.toggle(\"expanded\",collapsed);sidebarToggle.setAttribute(\"aria-label\",collapsed?\"Expand navigation\":\"Collapse navigation\")};document.getElementById(\"chatFab\").onclick=()=>document.getElementById(\"chatDrawer\").classList.toggle(\"hidden\");document.getElementById(\"chatClose\").onclick=()=>document.getElementById(\"chatDrawer\").classList.add(\"hidden\");document.getElementById(\"quickTicketForm\").onsubmit=async e=>{e.preventDefault();try{await post(\"/api/support\",{subject:document.getElementById(\"quickTicketSubject\").value.trim(),message:document.getElementById(\"quickTicketMessage\").value.trim()});document.getElementById(\"quickTicketForm\").reset();toast(\"Support ticket sent. Your account ID was attached automatically.\");}catch(x){toast(x.message)}};document.querySelectorAll(\"[data-help]\").forEach(b=>b.onclick=()=>{const q=b.dataset.help;const answers={\"Check my payout status\":\"Open Statements to view the latest request status. Pending means queued for manual review; Paid is shown only after a transfer is confirmed.\",\"Why is my task still in review?\":\"Every task is checked before its reward is credited. Pending tasks do not count toward your 3-task bonus unlock.\",\"How to unlock 5,000 UGX bonus\":\"Complete 3 tasks that are approved. The 5,000 UGX bonus then moves from locked to available automatically.\"};document.getElementById(\"chatAnswer\").textContent=answers[q]||\"Please create a support ticket for help.\"});\nasync function boot(){const ok=await loadData();const route=activeRoute();if(!ok&&route!==\"/\"&&route!==\"/auth\"&&route!==\"/register\"&&route!==\"/login\"){history.replaceState({},\"\",\"/auth\")}render();}\nboot();\n})();\n</script>\n</body>\n</html>\n";
const sec={"X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","X-Frame-Options":"DENY","Cache-Control":"no-store"};
export default {async fetch(request,env){const url=new URL(request.url),path=url.pathname;if(path==="/answer-club-admin"||path==="/answer-club-admin.html")return new Response(ANSWER_CLUB_ADMIN,{headers:{...sec,"Content-Type":"text/html; charset=utf-8"}});const routes={"/api/register":registerHandler,"/api/login":loginHandler,"/api/auth":authHandler,"/api/logout":logoutHandler,"/api/user":userHandler,"/api/dashboard":userHandler,"/api/tasks":userHandler,"/api/tasks/start":tasksStartHandler,"/api/submit":submissionHandler,"/api/submissions":submissionHandler,"/api/withdraw":withdrawHandler,"/api/withdrawals":withdrawHandler,"/api/profile":profileHandler,"/api/referrals":referralsHandler,"/api/support":supportHandler,"/api/admin/review":adminReviewHandler,"/api/admin/withdrawals":adminWithdrawalsHandler,"/api/admin/answer-club":adminClubHandler};if(routes[path]){try{const r=await routes[path]({request,env});const h=new Headers(r.headers);h.set("X-Content-Type-Options","nosniff");h.set("Referrer-Policy","strict-origin-when-cross-origin");return new Response(r.body,{status:r.status,statusText:r.statusText,headers:h});}catch(e){return Response.json({success:false,error:"The request could not be completed."},{status:500,headers:sec});}}if(path.startsWith("/api/"))return Response.json({success:false,error:"API route not found."},{status:404,headers:sec});const contributorRoutes=new Set(["/","/index.html","/dashboard","/dashboard.html","/tasks","/survey","/survey.html","/statements","/wallet","/wallet.html","/support","/profile","/settings","/auth","/register","/register.html","/login","/referrals"]);const key=path.slice(1);const html=contributorRoutes.has(path)?APP_SHELL:PAGES[key];if(!html)return new Response("Not found",{status:404,headers:sec});return new Response(html,{headers:{...sec,"Content-Type":"text/html; charset=utf-8"}});}};