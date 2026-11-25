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

export async function onRequestPost({ request, env }) {
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
