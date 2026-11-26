# TrainAI Uganda — Lifetime Activation Setup

This feature charges a one-time UGX 20,000 activation fee. Registration remains free. Existing accounts remain active because the migration gives them `activation_status = 'active'`.

## Before opening payments

1. Apply the D1 migration once:

   ```bash
   npx wrangler d1 execute ai-rewards-db --remote --file=migrations/0002_activation.sql
   ```

2. Configure the official business Mobile Money receiving numbers in the Cloudflare Worker environment. Set at least one:
   - `ACTIVATION_MTN_NUMBER`
   - `ACTIVATION_AIRTEL_NUMBER`
   - `ACTIVATION_ACCOUNT_NAME` (optional display name)

   Use Cloudflare Dashboard → Workers & Pages → my-ai-rewards-app → Settings → Variables and Secrets. Keep the receiving numbers private until they are confirmed as official TrainAI business collection accounts.

3. Confirm `ADMIN_API_KEY` is set as a Worker secret. The admin review page is `/admin-activation.html`.

4. Deploy the Worker only after the migration and receiving numbers are configured.

## Payment verification

- The app records the payer's network, phone number and Mobile Money transaction ID.
- A payment remains pending until an administrator checks the actual MTN/Airtel statement.
- Approving a verified UGX 20,000 transaction changes `activation_status` to `active` for that user.
- Rejecting a payment does not activate the account.
- The app does not initiate or send Mobile Money transfers.
- Do not approve screenshots alone; verify the transaction reference in the receiving account's statement.

## Important

Do not advertise or collect the activation fee until the official receiving account, payment verification process, genuine earning tasks and withdrawal funding are ready. Do not promise earnings or use new members' fees as the source of payouts to existing members.
