function json(body, status = 200) {
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

export async function onRequestGet({ request, env }) {
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
