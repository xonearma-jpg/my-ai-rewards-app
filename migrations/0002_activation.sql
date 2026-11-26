-- TrainAI Uganda one-time lifetime activation payments
CREATE TABLE IF NOT EXISTS activation_payments (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 amount_ugx INTEGER NOT NULL CHECK (amount_ugx = 20000),
 network TEXT NOT NULL CHECK (network IN ('MTN','AIRTEL')),
 payer_phone TEXT NOT NULL,
 transaction_reference TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 reviewed_at TEXT,
 admin_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_activation_payments_status_created ON activation_payments(status,created_at);
CREATE INDEX IF NOT EXISTS idx_activation_payments_user ON activation_payments(user_id,status);
