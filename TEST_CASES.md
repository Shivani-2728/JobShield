# JobShield Test Cases

## Test 1 — Clean Job

Expected:

🟢 LOW CONCERN

Fraud indicators:

0

---

## Test 2 — Recruitment Fee Scam

Example indicators:

- Registration fee
- UPI payment
- Immediate payment
- Refundable deposit

Expected:

🔴 HIGH-RISK INDICATORS DETECTED

---

## Test 3 — Sensitive Information Scam

Example indicators:

- OTP
- PIN
- CVV
- Bank account details

Expected:

🔴 HIGH-RISK INDICATORS DETECTED

---

## Test 4 — Fake Recruiter Domain

Example:

Claimed company:

Amazon

Official domain:

amazon.jobs

Recruiter:

hr@career-amazonjobs.com

Expected:

🔴 RECRUITER EMAIL DOMAIN MISMATCH

---

## Test 5 — Subtle WhatsApp Recruitment

Example:

Recruiter asks candidate to continue on WhatsApp.

No payment request.

No credential request.

Expected:

🟡 NEEDS VERIFICATION

---

## Test 6 — Genuine WhatsApp Follow-up

Example:

Candidate applies through official careers portal.

Recruiter email matches company domain.

WhatsApp is used only for interview scheduling.

No payment request.

Expected:

🟢 LOW CONCERN

---

## Test 7 — Real Vacancy + Fake Recruiter

Example:

Real company.

Real job title.

Real official vacancy.

Fake recruiter email.

Expected:

Recruiter identity concern should still be displayed.

The real vacancy should NOT automatically make the recruiter trusted.

---

## Test 8 — Suspicious External Domain

Example:

Claimed company:

Amazon

Official domain:

amazon.jobs

Job link:

career-amazonjobs-example.com

Expected:

🔴 DOMAIN MISMATCH / HIGH-RISK INDICATOR

---

## Test 9 — Vacancy Cannot Be Checked

Example:

Career page requires login or blocks automated requests.

Expected:

ℹ️ COULD NOT VERIFY OFFICIAL VACANCY

The application should not automatically label it as fake.

---

## Test 10 — JavaScript / Anti-Bot Website

Expected:

ℹ️ COULD NOT VERIFY

The application should explain that the page could not be independently checked.