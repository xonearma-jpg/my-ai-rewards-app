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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function onRequestPost({ request, env }) {
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
