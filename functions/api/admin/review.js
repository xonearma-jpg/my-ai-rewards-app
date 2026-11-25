function json(body, status = 200) {
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

export async function onRequest({ request, env }) {
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
