-- TrainAI Uganda: additive Gemini-era platform upgrade.
-- Apply only after reviewing the matching Worker release. Safe to re-run only once.

ALTER TABLE users ADD COLUMN payout_name TEXT;
ALTER TABLE users ADD COLUMN payout_number TEXT;
ALTER TABLE users ADD COLUMN payout_network TEXT;
ALTER TABLE users ADD COLUMN payout_locked INTEGER NOT NULL DEFAULT 0 CHECK (payout_locked IN (0,1));
ALTER TABLE users ADD COLUMN referral_code TEXT;
ALTER TABLE users ADD COLUMN referred_by TEXT;

UPDATE users
SET referral_code = 'TAI-' || upper(substr(hex(randomblob(5)), 1, 8))
WHERE referral_code IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code
ON users(referral_code) WHERE referral_code IS NOT NULL;

CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 4 AND 120),
  message TEXT NOT NULL CHECK (length(message) BETWEEN 10 AND 3000),
  ticket_status TEXT NOT NULL DEFAULT 'open'
    CHECK (ticket_status IN ('open','in_progress','resolved','closed')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_created
ON support_tickets(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS task_attempts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  survey_id TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  submitted_at TEXT,
  UNIQUE(user_id, survey_id, id)
);

CREATE INDEX IF NOT EXISTS idx_task_attempts_user
ON task_attempts(user_id, started_at DESC);

-- Balanced, append-only journal: every supported wallet transaction creates
-- one debit and one credit. Amounts are stored as integer UGX.
CREATE TABLE IF NOT EXISTS wallet_journal_entries (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES wallet_transactions(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  account_code TEXT NOT NULL,
  entry_side TEXT NOT NULL CHECK (entry_side IN ('debit','credit')),
  amount_ugx INTEGER NOT NULL CHECK (amount_ugx > 0),
  reference TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(transaction_id, account_code, entry_side)
);

CREATE INDEX IF NOT EXISTS idx_wallet_journal_user_created
ON wallet_journal_entries(user_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_wallet_transaction_journal_insert
AFTER INSERT ON wallet_transactions
WHEN NEW.transaction_type IN ('welcome_bonus_locked','bonus_unlocked','survey_reward','withdrawal')
BEGIN
  INSERT OR IGNORE INTO wallet_journal_entries
    (id, transaction_id, user_id, account_code, entry_side, amount_ugx, reference)
  SELECT lower(hex(randomblob(16))), NEW.id, NEW.user_id,
    CASE NEW.transaction_type
      WHEN 'welcome_bonus_locked' THEN 'promotion_expense'
      WHEN 'bonus_unlocked' THEN 'user_locked_liability'
      WHEN 'survey_reward' THEN 'task_reward_expense'
      WHEN 'withdrawal' THEN 'user_available_liability'
    END,
    'debit', NEW.amount_ugx, NEW.reference;

  INSERT OR IGNORE INTO wallet_journal_entries
    (id, transaction_id, user_id, account_code, entry_side, amount_ugx, reference)
  SELECT lower(hex(randomblob(16))), NEW.id, NEW.user_id,
    CASE NEW.transaction_type
      WHEN 'welcome_bonus_locked' THEN 'user_locked_liability'
      WHEN 'bonus_unlocked' THEN 'user_available_liability'
      WHEN 'survey_reward' THEN 'user_available_liability'
      WHEN 'withdrawal' THEN 'withdrawal_payable'
    END,
    'credit', NEW.amount_ugx, NEW.reference;
END;

-- Reverse a pending withdrawal's original journal if the request is rejected.
CREATE TRIGGER IF NOT EXISTS trg_withdrawal_journal_reversal
AFTER UPDATE OF transaction_status ON wallet_transactions
WHEN OLD.transaction_type = 'withdrawal'
  AND OLD.transaction_status = 'pending'
  AND NEW.transaction_status = 'reversed'
BEGIN
  INSERT OR IGNORE INTO wallet_journal_entries
    (id, transaction_id, user_id, account_code, entry_side, amount_ugx, reference)
  VALUES
    (lower(hex(randomblob(16))), NEW.id, NEW.user_id, 'withdrawal_payable',
     'debit', NEW.amount_ugx, NEW.reference || '-REV'),
    (lower(hex(randomblob(16))), NEW.id, NEW.user_id, 'user_available_liability',
     'credit', NEW.amount_ugx, NEW.reference || '-REV');
END;

-- Settle the payable to cash only when an administrator marks a manually
-- verified transfer as paid. This records settlement; it does not send money.
CREATE TRIGGER IF NOT EXISTS trg_withdrawal_journal_settlement
AFTER UPDATE OF transaction_status ON wallet_transactions
WHEN OLD.transaction_type = 'withdrawal'
  AND OLD.transaction_status = 'pending'
  AND NEW.transaction_status = 'completed'
BEGIN
  INSERT OR IGNORE INTO wallet_journal_entries
    (id, transaction_id, user_id, account_code, entry_side, amount_ugx, reference)
  VALUES
    (lower(hex(randomblob(16))), NEW.id, NEW.user_id, 'withdrawal_payable',
     'debit', NEW.amount_ugx, NEW.reference || '-SETTLED'),
    (lower(hex(randomblob(16))), NEW.id, NEW.user_id, 'mobile_money_clearing',
     'credit', NEW.amount_ugx, NEW.reference || '-SETTLED');
END;

-- Unlock the promotional 5,000 UGX bonus exactly once after the third
-- approved task. The update and transaction insert run inside the review
-- transaction that changes survey_responses.review_status.
CREATE TRIGGER IF NOT EXISTS trg_unlock_welcome_bonus_after_third_approval
AFTER UPDATE OF review_status ON survey_responses
WHEN NEW.review_status = 'approved'
  AND OLD.review_status <> 'approved'
BEGIN
  UPDATE users
  SET available_balance_ugx = available_balance_ugx + locked_bonus_ugx,
      locked_bonus_ugx = 0,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
  WHERE id = NEW.user_id
    AND locked_bonus_ugx >= 5000
    AND (SELECT COUNT(*) FROM survey_responses
         WHERE user_id = NEW.user_id AND review_status = 'approved') >= 3
    AND NOT EXISTS (
      SELECT 1 FROM wallet_transactions
      WHERE user_id = NEW.user_id AND transaction_type = 'bonus_unlocked'
    );

  INSERT INTO wallet_transactions
    (id, user_id, transaction_type, amount_ugx, balance_bucket,
     transaction_status, reference, notes)
  SELECT lower(hex(randomblob(16))), NEW.user_id, 'bonus_unlocked', 5000,
         'available', 'completed', 'BONUS-UNLOCK-' || NEW.user_id,
         '5,000 UGX welcome bonus unlocked after three approved tasks'
  WHERE changes() = 1;

  UPDATE wallet_transactions
  SET transaction_status = 'completed',
      notes = COALESCE(notes,'') || ' | Eligibility met; bonus unlocked'
  WHERE user_id = NEW.user_id
    AND transaction_type = 'welcome_bonus_locked'
    AND transaction_status = 'pending'
    AND EXISTS (
      SELECT 1 FROM wallet_transactions
      WHERE user_id = NEW.user_id AND transaction_type = 'bonus_unlocked'
    );
END;
