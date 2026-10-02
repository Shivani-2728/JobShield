# JobShield 🛡️

JobShield is a **job scam detection and verification assistant** built with Python and Streamlit.

It analyzes job posts, recruiter messages, screenshots, company information, recruiter email domains, URLs, and other available signals to identify **potential fraud indicators** and help users verify suspicious job opportunities.

> JobShield provides evidence-based indicators and verification signals. It does not claim that a result is 100% genuine or 100% fraudulent.

---

## 🎯 Project Objective

Job scams can appear through social media, messaging platforms, job portals, and websites.

JobShield is designed to help users identify common warning signs such as:

- Registration or application fees
- UPI or payment requests
- Requests for OTPs or sensitive credentials
- Urgent payment or joining pressure
- Unrealistic job promises
- Suspicious recruiter email domains
- Suspicious or shortened URLs
- Mismatch between recruiter information and company domain
- Job vacancy verification signals

---

## 🚀 Key Features

### 📷 Screenshot Analysis
Upload a screenshot of a job advertisement or recruiter message and extract text using OCR.

### 📝 Job Post Analysis
Analyze copied job descriptions, recruiter messages, and other job-related text.

### 🏢 Company Verification
Compare the provided company information with available public company and career information.

### 📧 Recruiter Email Verification
Check whether the recruiter email domain matches the claimed company domain.

### 🔗 URL Analysis
Analyze supplied job or company URLs and identify suspicious domain-related signals.

### 💳 Payment & Credential Detection
Detect indicators related to:

- Registration fees
- Processing fees
- Training fees
- Placement fees
- UPI / QR payment requests
- OTP requests
- Password / PIN / CVV requests
- Banking credentials
- Cryptocurrency or gift-card payment requests

### 📱 Communication Context
Consider communication platforms such as WhatsApp and Telegram together with other legitimacy signals rather than treating their use alone as proof of fraud.

### 🔎 Official Vacancy Verification
Where publicly available information allows it, compare the submitted job with official career or vacancy information.

### 📊 Evidence-Based Risk Levels

Results are presented using evidence-based levels such as:

- `LOW CONCERN`
- `NEEDS VERIFICATION`
- `SUSPICIOUS`
- `HIGH-RISK INDICATORS DETECTED`

### 📄 Downloadable Report
Generate a text report containing the analysis results and detected indicators.

### 🚨 Cyber Crime Reporting Guidance
Provides guidance for reporting suspected cybercrime in India through the official reporting channel.

---

## 🔄 How JobShield Works

```text
User Input
    │
    ├── Screenshot
    ├── Job Text / Recruiter Message
    ├── Company Details
    ├── Recruiter Details
    └── Job / Company URL
            │
            ▼
      Text Extraction
        (OCR when needed)
            │
            ▼
     Fraud Indicator Engine
            │
            ├── Payment Indicators
            ├── Credential Requests
            ├── Urgency / Pressure
            ├── Unrealistic Claims
            ├── Email / Domain Checks
            ├── URL Checks
            └── Communication Context
            │
            ▼
    Verification & Evidence
            │
            ▼
      Risk / Concern Level
            │
            ▼
      Detailed Analysis
            │
            ▼
       Downloadable Report
