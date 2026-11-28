-- TrainAI.ug Answer CLUB pricing and membership rules.
-- Reconcile existing rows (INSERT OR IGNORE in 0002 does not update previously seeded plans).
-- Monthly subscriptions grant permanent base access, but monthly-only benefits expire with the subscription.

PRAGMA foreign_keys = ON;

UPDATE club_plans SET
  plan_name = 'Answer CLUB 35K',
  billing_type = 'one_time',
  price_ugx = 35000,
  sort_order = 1,
  benefits_json = '["Permanent access to purchased one-time membership benefits"]',
  grants_permanent_base_access = 1,
  is_active = 1
WHERE plan_code = 'ONE_35K';

UPDATE club_plans SET plan_name='Answer CLUB 45K', billing_type='one_time', price_ugx=45000, sort_order=2,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_45K';
UPDATE club_plans SET plan_name='Answer CLUB 55K', billing_type='one_time', price_ugx=55000, sort_order=3,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_55K';
UPDATE club_plans SET plan_name='Answer CLUB 65K', billing_type='one_time', price_ugx=65000, sort_order=4,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_65K';
UPDATE club_plans SET plan_name='Answer CLUB 75K', billing_type='one_time', price_ugx=75000, sort_order=5,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_75K';
UPDATE club_plans SET plan_name='Answer CLUB 85K', billing_type='one_time', price_ugx=85000, sort_order=6,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_85K';
UPDATE club_plans SET plan_name='Answer CLUB 95K', billing_type='one_time', price_ugx=95000, sort_order=7,
  benefits_json='["Permanent access to purchased one-time membership benefits"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='ONE_95K';

UPDATE club_plans SET plan_name='Answer CLUB 100K Monthly', billing_type='monthly', price_ugx=100000, sort_order=8,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_100K';
UPDATE club_plans SET plan_name='Answer CLUB 150K Monthly', billing_type='monthly', price_ugx=150000, sort_order=9,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_150K';
UPDATE club_plans SET plan_name='Answer CLUB 200K Monthly', billing_type='monthly', price_ugx=200000, sort_order=10,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_200K';
UPDATE club_plans SET plan_name='Answer CLUB 300K Monthly', billing_type='monthly', price_ugx=300000, sort_order=11,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_300K';
UPDATE club_plans SET plan_name='Answer CLUB 400K Monthly', billing_type='monthly', price_ugx=400000, sort_order=12,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_400K';
UPDATE club_plans SET plan_name='Answer CLUB 500K Monthly', billing_type='monthly', price_ugx=500000, sort_order=13,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_500K';
UPDATE club_plans SET plan_name='Answer CLUB 750K Monthly', billing_type='monthly', price_ugx=750000, sort_order=14,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_750K';
UPDATE club_plans SET plan_name='Answer CLUB 1M Monthly', billing_type='monthly', price_ugx=1000000, sort_order=15,
  benefits_json='["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]', grants_permanent_base_access=1, is_active=1
WHERE plan_code='MONTH_1M';

INSERT OR IGNORE INTO club_plans
  (plan_code,plan_name,billing_type,price_ugx,sort_order,benefits_json,grants_permanent_base_access,is_active)
VALUES
  ('ONE_35K','Answer CLUB 35K','one_time',35000,1,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_45K','Answer CLUB 45K','one_time',45000,2,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_55K','Answer CLUB 55K','one_time',55000,3,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_65K','Answer CLUB 65K','one_time',65000,4,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_75K','Answer CLUB 75K','one_time',75000,5,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_85K','Answer CLUB 85K','one_time',85000,6,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('ONE_95K','Answer CLUB 95K','one_time',95000,7,'["Permanent access to purchased one-time membership benefits"]',1,1),
  ('MONTH_100K','Answer CLUB 100K Monthly','monthly',100000,8,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_150K','Answer CLUB 150K Monthly','monthly',150000,9,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_200K','Answer CLUB 200K Monthly','monthly',200000,10,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_300K','Answer CLUB 300K Monthly','monthly',300000,11,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_400K','Answer CLUB 400K Monthly','monthly',400000,12,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_500K','Answer CLUB 500K Monthly','monthly',500000,13,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_750K','Answer CLUB 750K Monthly','monthly',750000,14,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1),
  ('MONTH_1M','Answer CLUB 1M Monthly','monthly',1000000,15,'["Permanent access to one-time membership benefits","Monthly benefits while subscription is active"]',1,1);
