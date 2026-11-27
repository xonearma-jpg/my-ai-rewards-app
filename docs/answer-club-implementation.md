# Answer CLUB implementation notes

This branch contains the first Answer CLUB foundation for TrainAI.ug.

## Membership catalogue

One-time plans:
- UGX 35,000
- UGX 45,000
- UGX 55,000
- UGX 65,000
- UGX 75,000
- UGX 85,000
- UGX 95,000

Monthly plans:
- UGX 100,000
- UGX 150,000
- UGX 200,000
- UGX 300,000
- UGX 400,000
- UGX 500,000
- UGX 750,000
- UGX 1,000,000

A verified one-time purchase grants permanent access to its purchased benefits. A verified monthly purchase grants monthly benefits only for its active paid period and also grants permanent access to the one-time membership benefit base. Expired monthly benefits must not remain active.

## Reward pool and client surveys

The migration adds separate payment-verification, membership, client-survey, question-set and reward-pool ledger tables. The ledger is designed to record verified subscription and client-funding inflows and approved survey-reward outflows. It does not assume that every shilling collected is available for rewards: the pool allocation policy must be explicitly configured and published before funds are distributed.

## Question cadence and pilot content

The first sample question set is in `content/answer-club/uganda-social-pilot-001.json`. It uses single-select A-D questions about Uganda and social life. Opinion questions intentionally have no “correct” answer.

A recurring weekly Monday draft-preparation task has also been set up as the practical supported approximation of a five-working-day cycle. Each generated set remains a draft until the project owner approves it for publication.

## Deployment and payment safety

- This work is on `redesign/full-platform`; `main` is not changed.
- `migrations/0002_answer_club.sql` has been committed but has NOT been applied to the live D1 database.
- No live membership payment is accepted by this foundation yet.
- Before enabling payments, configure and verify the official MTN/Airtel collection destination (or payment provider), define the reward-pool allocation, and implement admin-only payment verification.
- Never ask members for a Mobile Money PIN or OTP.
- Never promise guaranteed earnings or guaranteed access to paid surveys.
