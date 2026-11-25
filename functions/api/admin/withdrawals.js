function json(body, status = 200) {
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

export async function onRequest({ request, env }) {
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
      `SELECT id, user_id, amount_ugx, request_status
       FROM withdrawal_requests WHERE id = ?`
    ).bind(withdrawalId).first();

    if (!withdrawal) return json({ success: false, error: "Withdrawal not found." }, 404);
    if (withdrawal.request_status !== "pending") {
      return json({ success: false, error: "This withdrawal has already been processed." }, 409);
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
