-- TrainAI.ug Answer CLUB foundation.
-- Apply only after review/approval; this migration has NOT been run against production.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS club_plans (
  plan_code TEXT PRIMARY KEY,
  plan_name TEXT NOT NULL,
  billing_type TEXT NOT NULL CHECK (billing_type IN ('one_time','monthly')),
  price_ugx INTEGER NOT NULL CHECK (price_ugx > 0),
  sort_order INTEGER NOT NULL,
  benefits_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(benefits_json)),
  grants_permanent_base_access INTEGER NOT NULL DEFAULT 0 CHECK (grants_permanent_base_access IN (0,1)),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

INSERT OR IGNORE INTO club_plans
  (plan_code, plan_name, billing_type, price_ugx, sort_order, grants_permanent_base_access)
VALUES
  ('ONE_35K','Answer CLUB 35K','one_time',35000,1,1),
  ('ONE_45K','Answer CLUB 45K','one_time',45000,2,1),
  ('ONE_55K','Answer CLUB 55K','one_time',55000,3,1),
  ('ONE_65K','Answer CLUB 65K','one_time',65000,4,1),
  ('ONE_75K','Answer CLUB 75K','one_time',75000,5,1),
  ('ONE_85K','Answer CLUB 85K','one_time',85000,6,1),
  ('ONE_95K','Answer CLUB 95K','one_time',95000,7,1),
  ('MONTH_100K','Answer CLUB 100K Monthly','monthly',100000,8,1),
  ('MONTH_150K','Answer CLUB 150K Monthly','monthly',150000,9,1),
  ('MONTH_200K','Answer CLUB 200K Monthly','monthly',200000,10,1),
  ('MONTH_300K','Answer CLUB 300K Monthly','monthly',300000,11,1),
  ('MONTH_400K','Answer CLUB 400K Monthly','monthly',400000,12,1),
  ('MONTH_500K','Answer CLUB 500K Monthly','monthly',500000,13,1),
  ('MONTH_750K','Answer CLUB 750K Monthly','monthly',750000,14,1),
  ('MONTH_1M','Answer CLUB 1M Monthly','monthly',1000000,15,1);

CREATE TABLE IF NOT EXISTS club_payment_submissions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_code TEXT NOT NULL REFERENCES club_plans(plan_code),
  amount_ugx INTEGER NOT NULL CHECK (amount_ugx > 0),
  payment_method TEXT NOT NULL CHECK (payment_method IN ('MTN','AIRTEL','BANK')),
  payer_phone TEXT,
  transaction_reference TEXT NOT NULL UNIQUE,
  payment_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (payment_status IN ('pending','verified','rejected')),
  submitted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  reviewed_at TEXT,
  reviewed_by TEXT,
  admin_note TEXT
);

CREATE TABLE IF NOT EXISTS club_memberships (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_code TEXT NOT NULL REFERENCES club_plans(plan_code),
  payment_submission_id TEXT NOT NULL UNIQUE REFERENCES club_payment_submissions(id),
  billing_type TEXT NOT NULL CHECK (billing_type IN ('one_time','monthly')),
  membership_status TEXT NOT NULL CHECK (membership_status IN ('active','expired','cancelled')),
  started_at TEXT NOT NULL,
  expires_at TEXT,
  permanent_base_access INTEGER NOT NULL DEFAULT 0 CHECK (permanent_base_access IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  CHECK (
    (billing_type = 'one_time' AND expires_at IS NULL) OR
    (billing_type = 'monthly' AND expires_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_club_memberships_user_status
  ON club_memberships(user_id, membership_status, billing_type, expires_at);

CREATE TABLE IF NOT EXISTS club_reward_pool_ledger (
  id TEXT PRIMARY KEY,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('subscription_contribution','client_funding','admin_adjustment','survey_reward')),
  direction TEXT NOT NULL CHECK (direction IN ('inflow','outflow')),
  amount_ugx INTEGER NOT NULL CHECK (amount_ugx > 0),
  payment_submission_id TEXT REFERENCES club_payment_submissions(id),
  client_survey_id TEXT,
  user_id TEXT REFERENCES users(id),
  reference TEXT UNIQUE,
  note TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS club_client_surveys (
  id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  client_contact TEXT,
  survey_title TEXT NOT NULL,
  survey_description TEXT NOT NULL,
  client_budget_ugx INTEGER NOT NULL DEFAULT 0 CHECK (client_budget_ugx >= 0),
  reward_budget_ugx INTEGER NOT NULL DEFAULT 0 CHECK (reward_budget_ugx >= 0),
  survey_id TEXT REFERENCES surveys(id),
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft','awaiting_funding','funded','published','closed','cancelled')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS club_question_sets (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  topic TEXT NOT NULL,
  country_code TEXT NOT NULL DEFAULT 'UG',
  question_format TEXT NOT NULL DEFAULT 'multiple_choice'
    CHECK (question_format = 'multiple_choice'),
  questions_json TEXT NOT NULL CHECK (json_valid(questions_json)),
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft','scheduled','published','archived')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  scheduled_for TEXT,
  published_at TEXT,
  source_client_survey_id TEXT REFERENCES club_client_surveys(id)
);

CREATE INDEX IF NOT EXISTS idx_club_question_sets_schedule
  ON club_question_sets(status, scheduled_for);
