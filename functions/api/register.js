const json = (body, status = 200, headers = {}) =>
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

export async function onRequestPost({ request, env }) {
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
         VALUES (?, ?, 'WELCOME_BONUS', 5000, 'locked', 'locked', ?, ?)`
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
