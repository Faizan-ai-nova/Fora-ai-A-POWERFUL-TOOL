# Fora AI — Payment Setup Guide

## Pricing
| Plan | INR | USD (approx) | Billing |
|------|-----|--------------|---------|
| Free | ₹0 | $0 | Lifetime (6 scans) |
| Pro Monthly | ₹199 | ~$2.4 | Monthly |
| Pro Yearly | ₹2330 | ~$28 | Yearly (2 months free) |

---

## 1. Razorpay Setup (UPI / Card / Net Banking)

1. Create account at https://dashboard.razorpay.com
2. Go to **Settings → API Keys → Generate Key**
3. Add to Railway environment variables:
```
RAZORPAY_KEY_ID=rzp_live_xxxxxxxxxx
RAZORPAY_KEY_SECRET=your_secret_here
```
4. For webhooks, go to **Settings → Webhooks → Add New Webhook**:
   - URL: `https://yourdomain.com/payments/webhook/razorpay/`
   - Events: `payment.captured`, `subscription.cancelled`

---

## 2. PayPal Setup (International payments)

1. Create app at https://developer.paypal.com → My Apps → Create App
2. Switch to **Live** mode when ready
3. Add to Railway:
```
PAYPAL_CLIENT_ID=your_client_id
PAYPAL_CLIENT_SECRET=your_secret
PAYPAL_MODE=live
```
4. Create billing plans in PayPal dashboard and store their IDs via Django admin:
   - `Plan.paypal_plan_id` for each plan

---

## 3. Run migrations after deploy

```bash
python manage.py migrate
```

This will:
- Create the `Plan` and `Subscription` tables
- Seed Free / Pro Monthly (₹199) / Pro Yearly (₹2330) plans automatically

---

## 4. Install razorpay package

Already added to `requirements.txt`:
```
razorpay==1.4.2
```

---

## Files changed
| File | Change |
|------|--------|
| `payments/providers/razorpay_provider.py` | NEW — Razorpay integration |
| `payments/views.py` | Updated — removed Stripe, added Razorpay verify endpoint |
| `payments/urls.py` | Updated — added razorpay/verify/ and razorpay webhook |
| `subscriptions/models.py` | Updated — added `price_inr`, `billing_period` fields |
| `subscriptions/migrations/0001_initial.py` | Fresh migration |
| `subscriptions/migrations/0002_seed_plans.py` | Seeds 3 plans with INR prices |
| `freebug_ai/settings.py` | Replaced Stripe vars with Razorpay vars |
| `requirements.txt` | Added razorpay, removed stripe |
| `templates/payments/razorpay_checkout.html` | NEW — Razorpay widget checkout page |
| `templates/subscriptions/pricing.html` | Updated — INR prices, monthly/yearly toggle |
| `templates/subscriptions/upgrade.html` | Updated — INR prices |
