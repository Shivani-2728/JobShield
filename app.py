import re
import ipaddress
import socket
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime

import requests
import streamlit as st
from PIL import Image

# Protect against excessively large images
Image.MAX_IMAGE_PIXELS = 20_000_000
import pytesseract
from bs4 import BeautifulSoup


# ============================================================
# JOBSHIELD
# Job Scam Detection & Verification Assistant
# ============================================================


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="JobShield",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# STYLING
# ============================================================

st.markdown(
    """
    <style>

    .risk-box {
        padding: 18px 20px;
        border-radius: 12px;
        margin: 10px 0 20px 0;
        font-size: 21px;
        font-weight: 700;
    }

    .green-box {
        background: #e8f8ee;
        color: #087443;
    }

    .yellow-box {
        background: #fff7df;
        color: #825900;
    }

    .orange-box {
        background: #fff0e6;
        color: #9b4300;
    }

    .red-box {
        background: #ffe8e8;
        color: #a50000;
    }

    .grey-box {
        background: #f1f3f5;
        color: #444444;
    }

    .evidence-box {
        padding: 14px 16px;
        border: 1px solid #dddddd;
        border-radius: 9px;
        margin-bottom: 9px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# CONSTANTS
# ============================================================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/154.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9"
}


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "rediffmail.com"
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "shorturl.at",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly"
}


SOCIAL_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "whatsapp.com",
    "telegram.org",
    "telegram.me",
    "t.me",
    "x.com"
}


JOB_PLATFORMS = {
    "naukri.com",
    "indeed.com",
    "glassdoor.com",
    "foundit.in",
    "monster.com",
    "wellfound.com",
    "instahyre.com",
    "apna.co",
    "cutshort.io",
    "shine.com",
    "workindia.in",
    "timesjobs.com",
    "jooble.org",
    "ziprecruiter.com",
    "simplyhired.com",
    "dice.com",
    "workday.com",
    "myworkdayjobs.com",
    "greenhouse.io",
    "lever.co",
    "smartrecruiters.com"
}


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url):
    if not url:
        return ""

    url = url.strip()

    if not re.match(
        r"^https?://",
        url,
        re.I
    ):
        url = "https://" + url

    return url


def clean_domain(url):
    if not url:
        return ""

    try:
        parsed = urlparse(
            normalize_url(url)
        )

        host = parsed.hostname or ""

        return host.lower().removeprefix("www.")

    except Exception:
        return ""


def is_safe_public_url(url):
    """
    Basic protection against localhost/private/internal addresses.
    """

    if not url:
        return False

    url = normalize_url(url)

    try:

        parsed = urlparse(url)

        if parsed.scheme not in (
            "http",
            "https"
        ):
            return False

        host = parsed.hostname

        if not host:
            return False

        host = host.lower()

        if host in {
            "localhost",
            "localhost.localdomain",
            "ip6-localhost"
        }:
            return False

        # ----------------------------------------------------
        # Direct IP
        # ----------------------------------------------------

        try:

            ip = ipaddress.ip_address(
                host
            )

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return False

            return True

        except ValueError:
            pass

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        try:

            addresses = socket.getaddrinfo(
                host,
                None
            )

            for item in addresses:

                ip_string = item[4][0]

                ip = ipaddress.ip_address(
                    ip_string
                )

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return False

        except socket.gaierror:

            return False

        return True

    except Exception:

        return False


def domain_category(domain):
    domain = (
        domain
        or ""
    ).lower().removeprefix("www.")

    if domain in SOCIAL_DOMAINS:
        return "social"

    if domain in JOB_PLATFORMS:
        return "job_platform"

    if domain in URL_SHORTENERS:
        return "shortener"

    return "other"


# ============================================================
# WEB FETCHING
# ============================================================

def fetch_page(url):
    """
    Returns:
        status_code,
        final_url,
        title,
        visible_text,
        links
    """

    if not url:
        return 0, "", "", "", []

    url = normalize_url(url)

    if not is_safe_public_url(url):
        return 0, "", "", "", []

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=15,
            allow_redirects=True
        )

        final_url = response.url

        if not is_safe_public_url(
            final_url
        ):
            return 0, "", "", "", []

        content_type = response.headers.get(
            "content-type",
            ""
        ).lower()

        if "html" not in content_type:

            return (
                response.status_code,
                final_url,
                "",
                "",
                []
            )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for tag in soup([
            "script",
            "style",
            "noscript",
            "svg",
            "template"
        ]):

            tag.decompose()

        title = ""

        if soup.title:

            title = soup.title.get_text(
                " ",
                strip=True
            )

        visible_text = soup.get_text(
            " ",
            strip=True
        )

        visible_text = re.sub(
            r"\s+",
            " ",
            visible_text
        )

        links = []

        for anchor in soup.find_all(
            "a",
            href=True
        ):

            href = anchor.get(
                "href",
                ""
            ).strip()

            link_text = anchor.get_text(
                " ",
                strip=True
            )

            if not href:
                continue

            absolute_url = urljoin(
                final_url,
                href
            )

            if absolute_url.startswith(
                (
                    "http://",
                    "https://"
                )
            ):

                links.append(
                    (
                        link_text,
                        absolute_url
                    )
                )

        return (
            response.status_code,
            final_url,
            title,
            visible_text,
            links
        )

    except requests.RequestException:

        return 0, "", "", "", []

    except Exception:

        return 0, "", "", "", []


# ============================================================
# TEXT HELPERS
# ============================================================

def normalize_text(text):

    text = (
        text or ""
    ).lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def word_tokens(text):

    return set(
        word
        for word in re.findall(
            r"[a-z0-9]+",
            normalize_text(text)
        )
        if len(word) > 1
    )


def normalize_title(title):

    title = normalize_text(
        title
    )

    title = re.sub(
        r"^(job title|position|role)\s*[:\-]\s*",
        "",
        title
    )

    title = re.sub(
        r"\b(remote|hybrid|onsite|on-site)\b",
        " ",
        title
    )

    title = re.sub(
        r"\s+",
        " ",
        title
    )

    return title.strip()


# ============================================================
# EXTRACTION
# ============================================================

def extract_emails(text):

    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text or ""
    )

    return sorted(
        set(emails)
    )


def extract_phones(text):

    candidates = re.findall(
        r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)",
        text or ""
    )

    result = []

    for candidate in candidates:

        digits = re.sub(
            r"\D",
            "",
            candidate
        )

        if 10 <= len(digits) <= 15:

            result.append(
                candidate.strip()
            )

    return sorted(
        set(result)
    )


def extract_urls(text):

    urls = re.findall(
        r"https?://[^\s<>\"]+",
        text or "",
        re.I
    )

    cleaned = []

    for url in urls:

        cleaned.append(
            url.rstrip(
                ".,);]}>"
            )
        )

    return sorted(
        set(cleaned)
    )


# ============================================================
# TITLE MATCHING
# ============================================================

def extract_salary_info(text):

    if not text:
        return []

    patterns = [
        r"₹\s?[\d,]+(?:\.\d+)?\s*(?:lpa|lakhs?|lakh|crore|cr|per\s+month|monthly|per\s+year|annually|pa)?",
        r"\b\d+(?:\.\d+)?\s*(?:lpa|lakhs?|lakh|crore|cr)\b",
        r"\b(?:salary|ctc|pay|package)\s*[:\-]?\s*(?:₹|\$)?\s?[\d,]+(?:\.\d+)?\s*[A-Za-z]*",
        r"\$\s?[\d,]+(?:\.\d+)?\s*(?:per\s+month|monthly|per\s+year|annually)?"
    ]

    results = []

    for pattern in patterns:

        matches = re.findall(
            pattern,
            text,
            re.I
        )

        for match in matches:

            value = (
                match
                .strip()
                .rstrip(".,;")
            )

            if value and value not in results:

                results.append(
                    value
                )

    return results[:10]


def extract_location_info(text):

    if not text:
        return []

    patterns = [
        r"(?:job\s+location|location|work\s+location|office\s+location)\s*[:\-]\s*([A-Za-z][A-Za-z0-9 ,./&()\-]{2,70})",
        r"(?:based\s+in|based\s+at)\s+([A-Za-z][A-Za-z0-9 ,./&()\-]{2,60})"
    ]

    results = []

    for pattern in patterns:

        matches = re.findall(
            pattern,
            text,
            re.I
        )

        for match in matches:

            value = (
                match
                .strip()
                .rstrip(".,;")
            )

            if value and value not in results:

                results.append(
                    value
                )

    return results[:10]


def official_application_detected(text):

    text = (text or "").lower()

    patterns = [
        r"\bapply through (the )?(official )?(careers?|jobs?)",
        r"\bapply through (the )?official portal\b",
        r"\bapply on (the )?official website\b",
        r"\bapply via (the )?official website\b",
        r"\bofficial careers website\b",
        r"\bofficial careers page\b",
        r"\bsubmit your application through\b"
    ]

    return any(
        re.search(
            pattern,
            text,
            re.I
        )
        for pattern in patterns
    )
def title_similarity(
    requested_title,
    actual_title
):

    requested = normalize_title(
        requested_title
    )

    actual = normalize_title(
        actual_title
    )

    if not requested or not actual:
        return 0

    if requested == actual:
        return 100

    if requested in actual:
        return 94

    if actual in requested:
        return 88

    requested_words = word_tokens(
        requested
    )

    actual_words = word_tokens(
        actual
    )

    if not requested_words:
        return 0

    overlap = len(
        requested_words &
        actual_words
    )

    ratio = (
        overlap /
        len(requested_words)
    )

    if ratio >= 0.90:
        return 84

    if ratio >= 0.75:
        return 76

    if ratio >= 0.50:
        return 58

    return 0


def is_internship_title(title):

    tokens = word_tokens(
        title
    )

    return bool(
        tokens & {
            "intern",
            "internship",
            "trainee",
            "apprentice",
            "apprenticeship"
        }
    )


def seniority_tokens(title):

    return (
        word_tokens(title)
        & {
            "intern",
            "internship",
            "trainee",
            "junior",
            "jr",
            "senior",
            "sr",
            "lead",
            "principal",
            "manager",
            "director",
            "head"
        }
    )


def seniority_mismatch(
    requested_title,
    actual_title
):

    requested = seniority_tokens(
        requested_title
    )

    actual = seniority_tokens(
        actual_title
    )

    if not requested and not actual:
        return False

    return requested != actual


# ============================================================
# FRAUD INDICATOR ENGINE
# ============================================================

def detect_fraud_indicators(
    text,
    recruiter_email="",
    company_website="",
    job_url=""
):

    text = text or ""
    lower = text.lower()

    findings = []

    def add(
        severity,
        category,
        message
    ):
        findings.append(
            {
                "severity": severity,
                "category": category,
                "message": message
            }
        )

    # --------------------------------------------------------
    # CONTEXT SIGNALS
    # --------------------------------------------------------

    official_application_patterns = [
        r"\bapply through (the )?(company'?s? )?(official )?(careers?|jobs?)\b",
        r"\bapply through (the )?official portal\b",
        r"\bapply on (the )?official website\b",
        r"\bapply via (the )?official website\b",
        r"\bsubmit your application through\b",
        r"\bapply through our careers page\b",
        r"\bapply through our official website\b",
        r"\bofficial careers website\b",
        r"\bofficial careers page\b",
        r"\bofficial job portal\b"
    ]

    official_application_present = any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in official_application_patterns
    )

    recruiter_email_matches = False

    if (
        recruiter_email
        and company_website
        and "@" in recruiter_email
    ):
        recruiter_email_matches = domains_match(
            recruiter_email,
            company_website
        )

    # --------------------------------------------------------
    # HIGH: PAYMENT
    # --------------------------------------------------------

    payment_patterns = [
        r"\bregistration fee\b",
        r"\bprocessing fee\b",
        r"\btraining fee\b",
        r"\bplacement fee\b",
        r"\bsecurity deposit\b",
        r"\bsecurity fee\b",
        r"\binterview fee\b",
        r"\bcertificate fee\b",
        r"\bverification fee\b",
        r"\bjoining fee\b",
        r"\bpay.*fee\b",
        r"\bfee.*pay\b",
        r"\bpay.*deposit\b",
        r"\bdeposit.*pay\b",
        r"\brefundable fee\b",
        r"\brefundable deposit\b",
        r"\bpayment required\b",
        r"\bpay before joining\b",
        r"\bpay to get the job\b",
        r"\bpay to secure\b",
        r"\bjob fee\b",
        r"\brecruitment payment\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in payment_patterns
    ):
        add(
            "high",
            "Payment",
            "Recruitment-related payment or fee request detected."
        )

    # --------------------------------------------------------
    # HIGH: SENSITIVE CREDENTIALS
    # --------------------------------------------------------

    credential_patterns = [
        r"\botp\b",
        r"\bone time password\b",
        r"\bpassword\b",
        r"\bpin\b",
        r"\bcvv\b",
        r"\bcard details\b",
        r"\bdebit card\b",
        r"\bcredit card\b",
        r"\bbank account number\b",
        r"\bbanking details\b",
        r"\bnet banking\b",
        r"\baccount credentials\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in credential_patterns
    ):
        add(
            "high",
            "Sensitive credentials",
            "The communication asks for or mentions sensitive account or financial credentials."
        )

    # --------------------------------------------------------
    # HIGH: UPI / QR
    # --------------------------------------------------------

    payment_method_patterns = [
        r"\bupi\b",
        r"\bupi id\b",
        r"\bscan.*qr\b",
        r"\bqr.*scan\b",
        r"\bscan.*code\b",
        r"\bsend.*upi\b",
        r"\bpay.*upi\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in payment_method_patterns
    ):
        add(
            "high",
            "Payment",
            "UPI or QR-payment instructions detected."
        )

    # --------------------------------------------------------
    # MEDIUM: PRESSURE
    # --------------------------------------------------------

    urgency_patterns = [
        r"\bpay immediately\b",
        r"\bpay now\b",
        r"\bact immediately\b",
        r"\bwithin \d+ minutes\b",
        r"\bwithin \d+ hours\b",
        r"\burgent\b",
        r"\blast chance\b",
        r"\btoday only\b",
        r"\boffer expires\b",
        r"\blimited seats\b",
        r"\bdo it now\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in urgency_patterns
    ):
        add(
            "medium",
            "Pressure",
            "The message uses urgency or pressure to make the applicant act quickly."
        )

    # --------------------------------------------------------
    # MEDIUM: UNREALISTIC CLAIMS
    # --------------------------------------------------------

    unrealistic_patterns = [
        r"\bguaranteed job\b",
        r"\b100% job\b",
        r"\bno interview\b",
        r"\bwithout interview\b",
        r"\binstant joining\b",
        r"\bguaranteed placement\b",
        r"\beasy money\b",
        r"\bhigh salary.*no experience\b",
        r"\bearn .* without experience\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in unrealistic_patterns
    ):
        add(
            "medium",
            "Job claim",
            "The post contains an unusually strong employment or earning promise."
        )

    # --------------------------------------------------------
    # LOW: WHATSAPP / TELEGRAM
    #
    # Do NOT treat messaging alone as fraud.
    # If the message also provides an official application
    # route and the recruiter email matches the company,
    # suppress this low-level signal.
    # --------------------------------------------------------

    messaging_patterns = [
        r"\bwhatsapp only\b",
        r"\btelegram only\b",
        r"\bcontact only on whatsapp\b",
        r"\bcontact me on whatsapp\b",
        r"\bcontact.*on whatsapp\b",
        r"\bcontact.*via whatsapp\b",
        r"\brecruitment.*whatsapp\b",
        r"\brecruiter.*whatsapp\b",
        r"\bmessage.*on whatsapp\b",
        r"\bmessage.*via whatsapp\b",
        r"\bwhatsapp.*recruitment\b",

        r"\bcontact only on telegram\b",
        r"\bcontact me on telegram\b",
        r"\bcontact.*on telegram\b",
        r"\bcontact.*via telegram\b",
        r"\brecruitment.*telegram\b",
        r"\brecruiter.*telegram\b",
        r"\bmessage.*on telegram\b",
        r"\bmessage.*via telegram\b"
    ]

    messaging_present = any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in messaging_patterns
    )

    if messaging_present:

        legitimate_context = (
            official_application_present
            and (
                recruiter_email_matches
                or not recruiter_email
            )
        )

        if not legitimate_context:

            add(
                "low",
                "Recruiter communication",
                "Recruitment is being moved to WhatsApp or Telegram. Verify the recruiter's identity independently before continuing."
            )

    # --------------------------------------------------------
    # HIGH: UNUSUAL PAYMENT METHODS
    # --------------------------------------------------------

    unusual_payment_patterns = [
        r"\bbitcoin\b",
        r"\bcrypto payment\b",
        r"\bcryptocurrency payment\b",
        r"\bgift card\b",
        r"\bgoogle play card\b",
        r"\bapple gift card\b",
        r"\bsteam gift card\b"
    ]

    if any(
        re.search(
            pattern,
            lower,
            re.I
        )
        for pattern in unusual_payment_patterns
    ):
        add(
            "high",
            "Payment",
            "Cryptocurrency or gift-card payment instructions detected."
        )

    # --------------------------------------------------------
    # HIGH: RECRUITER DOMAIN MISMATCH
    # --------------------------------------------------------

    if (
        recruiter_email
        and company_website
        and "@"
        in recruiter_email
    ):

        recruiter_domain = (
            recruiter_email
            .split("@", 1)[1]
            .strip()
            .lower()
            .removeprefix("www.")
        )

        company_domain = clean_domain(
            company_website
        )

        if (
            recruiter_domain
            and company_domain
            and recruiter_domain != company_domain
        ):
            add(
                "high",
                "Recruiter identity",
                "RECRUITER EMAIL DOMAIN MISMATCH: The recruiter email does not match the claimed company's official domain."
            )

    # --------------------------------------------------------
    # URLS INSIDE TEXT
    # --------------------------------------------------------

    for url in extract_urls(
        text
    )[:20]:

        domain = clean_domain(
            url
        )

        if domain in URL_SHORTENERS:

            add(
                "medium",
                "URL",
                "A shortened URL was found in the job communication."
            )

        if domain.startswith(
            "xn--"
        ):

            add(
                "medium",
                "URL",
                "A punycode/IDN domain was detected. Verify the destination carefully."
            )

    # --------------------------------------------------------
    # USER-SUPPLIED JOB URL
    # --------------------------------------------------------

    findings.extend(
        analyze_job_url(
            job_url,
            company_website
        )
    )

    return deduplicate_findings(
        findings
    )
def analyze_job_url(
    job_url,
    company_website
):

    findings = []

    if not job_url:
        return findings

    domain = clean_domain(
        job_url
    )

    category = domain_category(
        domain
    )

    company_domain = clean_domain(
        company_website
    )

    # URL shortener
    if category == "shortener":

        findings.append(
            {
                "severity": "medium",
                "category": "URL",
                "message": (
                    "The job link uses a URL-shortening service."
                )
            }
        )

    # Different domain
    if (
        company_domain
        and domain
        and domain != company_domain
    ):

        if category == "social":

            findings.append(
                {
                    "severity": "low",
                    "category": "URL",
                    "message": (
                        "The job post is hosted on a social-media platform."
                    )
                }
            )

        elif category == "job_platform":

            findings.append(
                {
                    "severity": "low",
                    "category": "URL",
                    "message": (
                        "The job post is hosted on a third-party job platform."
                    )
                }
            )

        elif category == "other":

            findings.append(
                {
                    "severity": "high",
                    "category": "URL",
                    "message": (
                        "The supplied job URL uses a different domain "
                        "from the claimed company website."
                    )
                }
            )

    return findings


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_findings(
    findings
):

    result = []
    seen = set()

    for item in findings:

        key = (
            item.get("severity"),
            item.get("category"),
            item.get("message")
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            item
        )

    return result


# ============================================================
# OVERALL STATUS
# ============================================================

def overall_status(
    findings
):

    high = sum(
        1
        for item in findings
        if item["severity"] == "high"
    )

    medium = sum(
        1
        for item in findings
        if item["severity"] == "medium"
    )

    low = sum(
        1
        for item in findings
        if item["severity"] == "low"
    )

    if high >= 2:

        return (
            "HIGH-RISK INDICATORS DETECTED",
            "red-box"
        )

    if high == 1:

        return (
            "SUSPICIOUS",
            "orange-box"
        )

    if medium >= 1:

        return (
            "NEEDS VERIFICATION",
            "yellow-box"
        )

    if low >= 1:

        return (
            "NEEDS VERIFICATION",
            "yellow-box"
        )

    return (
        "LOW CONCERN",
        "green-box"
    )
def inspect_website(
    company_website
):

    if not company_website:

        return {
            "status": "NOT PROVIDED",
            "domain": "",
            "title": "",
            "message": (
                "Company website was not provided."
            )
        }

    status, final_url, title, _, _ = fetch_page(
        company_website
    )

    if status == 200:

        return {
            "status": "REACHABLE",
            "domain": clean_domain(
                final_url
            ),
            "title": title,
            "message": (
                "The supplied company website "
                "responded successfully."
            )
        }

    return {
        "status": "COULD NOT VERIFY",
        "domain": clean_domain(
            company_website
        ),
        "title": "",
        "message": (
            "The supplied company website "
            "could not be reached or verified."
        )
    }


# ============================================================
# COMPANY DOMAIN SIGNAL
# ============================================================

def company_name_match(
    company_name,
    company_website
):

    if (
        not company_name
        or not company_website
    ):

        return "NEEDS VERIFICATION"

    company_words = word_tokens(
        company_name
    )

    domain_words = word_tokens(
        clean_domain(
            company_website
        ).replace(
            ".",
            " "
        )
    )

    if company_words & domain_words:

        return "MATCH"

    return "NEEDS VERIFICATION"

def domains_match(
    email,
    website
):

    if (
        not email
        or not website
        or '@' not in email
    ):
        return False

    email_domain = (
        email
        .split('@', 1)[1]
        .strip()
        .lower()
        .removeprefix('www.')
    )

    company_domain = clean_domain(
        website
    )

    if not email_domain or not company_domain:
        return False

    return (
        email_domain == company_domain
        or email_domain.endswith(
            '.' + company_domain
        )
    )

def find_careers_pages(
    company_website
):

    if not company_website:
        return []

    home = normalize_url(
        company_website
    )

    status, final_url, _, _, links = fetch_page(
        home
    )

    if status == 0:
        return []

    domain = clean_domain(
        final_url
    )

    keywords = [
        "career",
        "careers",
        "jobs",
        "job openings",
        "job opportunities",
        "work with us",
        "join us",
        "join our team",
        "vacancies",
        "opportunities",
        "employment"
    ]

    candidates = []

    for link_text, href in links:

        if clean_domain(href) != domain:
            continue

        combined = (
            f"{link_text} {href}"
        ).lower()

        if any(
            keyword in combined
            for keyword in keywords
        ):

            candidates.append(
                href
            )

    common_paths = [
        "/careers",
        "/career",
        "/jobs",
        "/job",
        "/work-with-us",
        "/join-us",
        "/join-our-team"
    ]

    for path in common_paths:

        candidate = urljoin(
            final_url,
            path
        )

        if clean_domain(candidate) == domain:

            candidates.append(
                candidate
            )

    result = []
    seen = set()

    for candidate in candidates:

        candidate = normalize_url(
            candidate
        )

        key = candidate.rstrip(
            "/"
        ).lower()

        if key in seen:
            continue

        if not is_safe_public_url(
            candidate
        ):
            continue

        seen.add(
            key
        )

        result.append(
            candidate
        )

    return result[:15]


# ============================================================
# AMAZON SEARCH
# ============================================================

def amazon_search_jobs(
    job_title
):

    search_url = (
        "https://www.amazon.jobs/en/search.json"
    )

    params = {
        "base_query": job_title,
        "offset": 0,
        "result_limit": 50,
        "sort": "relevant"
    }

    try:

        response = requests.get(
            search_url,
            params=params,
            headers={
                **HEADERS,
                "Accept": (
                    "application/json,"
                    "text/plain,*/*"
                )
            },
            timeout=15
        )

        if response.status_code != 200:

            return {
                "status": "COULD NOT VERIFY",
                "jobs": [],
                "search_page": response.url,
                "message": (
                    f"Amazon Jobs returned HTTP "
                    f"{response.status_code}."
                )
            }

        data = response.json()

        jobs = data.get(
            "jobs",
            []
        )

        if not isinstance(
            jobs,
            list
        ):
            jobs = []

        return {
            "status": "SUCCESS",
            "jobs": jobs,
            "search_page": response.url,
            "message": (
                "Amazon Jobs search completed."
            )
        }

    except Exception as e:

        return {
            "status": "COULD NOT VERIFY",
            "jobs": [],
            "search_page": search_url,
            "message": (
                f"Amazon Jobs search could not be completed: {e}"
            )
        }


# ============================================================
# AMAZON VACANCY
# ============================================================

def verify_amazon_vacancy(
    job_title
):

    result = amazon_search_jobs(
        job_title
    )

    if result["status"] != "SUCCESS":

        return {
            "status": "COULD NOT VERIFY",
            "message": result["message"],
            "matches": [],
            "related": [],
            "search_page": result["search_page"]
        }

    jobs = result["jobs"]

    if not jobs:

        return {
            "status": "NOT FOUND",
            "message": (
                "Amazon Jobs returned no results "
                "for the requested title."
            ),
            "matches": [],
            "related": [],
            "search_page": result["search_page"]
        }

    strong = []
    related = []

    for job in jobs:

        actual_title = str(
            job.get(
                "title",
                ""
            )
        ).strip()

        if not actual_title:
            continue

        score = title_similarity(
            job_title,
            actual_title
        )

        if score < 55:
            continue

        job_path = job.get(
            "job_path",
            ""
        )

        if not job_path:
            continue

        if job_path.startswith(
            (
                "http://",
                "https://"
            )
        ):

            job_url = job_path

        else:

            job_url = urljoin(
                "https://www.amazon.jobs",
                job_path
            )

        item = {
            "title": actual_title,
            "url": job_url,
            "score": score,
            "internship": is_internship_title(
                actual_title
            ),
            "location": str(
                job.get(
                    "location",
                    ""
                )
            ).strip()
        }

        if (
            score >= 75
            and not seniority_mismatch(
                job_title,
                actual_title
            )
        ):

            strong.append(
                item
            )

        else:

            related.append(
                item
            )

    strong = unique_vacancies(
        strong
    )

    related = unique_vacancies(
        related
    )

    strong.sort(
        key=lambda item: (
            item["score"],
            not item["internship"]
        ),
        reverse=True
    )

    related.sort(
        key=lambda item: (
            item["score"],
            not item["internship"]
        ),
        reverse=True
    )

    normal = [
        item
        for item in strong
        if not item["internship"]
    ]

    internship = [
        item
        for item in strong
        if item["internship"]
    ]

    if normal:

        return {
            "status": "FOUND",
            "message": (
                f"Amazon Jobs returned "
                f"{len(normal)} strong matching "
                f"regular vacancy result(s)."
            ),
            "matches": normal[:5],
            "related": (
                internship + related
            )[:5],
            "search_page": result["search_page"]
        }

    if internship or related:

        return {
            "status": "RELATED ONLY",
            "message": (
                "Amazon Jobs returned related or "
                "internship/trainee results, but no "
                "strong regular-vacancy match."
            ),
            "matches": [],
            "related": (
                internship + related
            )[:5],
            "search_page": result["search_page"]
        }

    return {
        "status": "NOT FOUND",
        "message": (
            "Amazon Jobs search completed, but "
            "a strong matching vacancy was not found."
        ),
        "matches": [],
        "related": [],
        "search_page": result["search_page"]
    }


# ============================================================
# GENERIC VACANCY
# ============================================================

def verify_generic_vacancy(
    company_website,
    job_title
):

    careers_pages = find_careers_pages(
        company_website
    )

    if not careers_pages:

        return {
            "status": "COULD NOT VERIFY",
            "message": (
                "No public careers/jobs page could "
                "be identified or reached."
            ),
            "matches": [],
            "related": [],
            "search_page": "",
            "checked": []
        }

    matches = []
    related = []
    checked = []

    for careers_url in careers_pages:

        status, final_url, page_title, page_text, links = fetch_page(
            careers_url
        )

        if status != 200:
            continue

        checked.append(
            final_url
        )

        # Careers page itself
        page_score = title_similarity(
            job_title,
            page_title
        )

        if page_score >= 75:

            matches.append(
                {
                    "title": page_title or "Careers page",
                    "url": final_url,
                    "score": page_score,
                    "internship": is_internship_title(
                        page_title
                    ),
                    "location": ""
                }
            )

        # Vacancy links
        for link_text, href in links[:150]:

            candidate_title = (
                link_text.strip()
                or urlparse(href).path.split("/")[-1]
            )

            score = title_similarity(
                job_title,
                candidate_title
            )

            if score >= 55:

                status2, final2, title2, text2, _ = fetch_page(
                    href
                )

                if status2 != 200:
                    continue

                actual_title = (
                    title2
                    or candidate_title
                )

                detailed_score = title_similarity(
                    job_title,
                    actual_title
                )

                if detailed_score >= 75:

                    matches.append(
                        {
                            "title": actual_title,
                            "url": final2,
                            "score": detailed_score,
                            "internship": is_internship_title(
                                actual_title
                            ),
                            "location": ""
                        }
                    )

                elif detailed_score >= 55:

                    related.append(
                        {
                            "title": actual_title,
                            "url": final2,
                            "score": detailed_score,
                            "internship": is_internship_title(
                                actual_title
                            ),
                            "location": ""
                        }
                    )

    matches = unique_vacancies(
        matches
    )

    related = unique_vacancies(
        related
    )

    matches.sort(
        key=lambda item: (
            item["score"],
            not item["internship"]
        ),
        reverse=True
    )

    related.sort(
        key=lambda item: (
            item["score"],
            not item["internship"]
        ),
        reverse=True
    )

    normal = [
        item
        for item in matches
        if not item["internship"]
    ]

    internship = [
        item
        for item in matches
        if item["internship"]
    ]

    if normal:

        return {
            "status": "FOUND",
            "message": (
                "A strong matching vacancy was found "
                "on a public employer careers/jobs page."
            ),
            "matches": normal[:5],
            "related": (
                internship + related
            )[:5],
            "search_page": "",
            "checked": checked[:5]
        }

    if internship or related:

        return {
            "status": "RELATED ONLY",
            "message": (
                "Related job results were found, but "
                "no strong regular vacancy was identified."
            ),
            "matches": [],
            "related": (
                internship + related
            )[:5],
            "search_page": "",
            "checked": checked[:5]
        }

    if checked:

        return {
            "status": "NOT FOUND",
            "message": (
                "The requested job title was not found "
                "on the careers pages that could be checked."
            ),
            "matches": [],
            "related": [],
            "search_page": "",
            "checked": checked[:5]
        }

    return {
        "status": "COULD NOT VERIFY",
        "message": (
            "Careers pages were identified, but their "
            "contents could not be checked."
        ),
        "matches": [],
        "related": [],
        "search_page": "",
        "checked": careers_pages[:5]
    }


# ============================================================
# UNIQUE VACANCIES
# ============================================================

def unique_vacancies(
    items
):

    result = []

    seen_urls = set()
    seen_titles = set()

    for item in items:

        url_key = (
            item["url"]
            .rstrip("/")
            .lower()
        )

        title_key = normalize_title(
            item["title"]
        )

        if (
            url_key in seen_urls
            or title_key in seen_titles
        ):
            continue

        seen_urls.add(
            url_key
        )

        seen_titles.add(
            title_key
        )

        result.append(
            item
        )

    return result


# ============================================================
# MAIN VACANCY FUNCTION
# ============================================================

def verify_vacancy(
    company_website,
    job_title
):

    if (
        not company_website
        or not job_title
    ):

        return {
            "status": "COULD NOT VERIFY",
            "message": (
                "Company website and job title are required."
            ),
            "matches": [],
            "related": [],
            "search_page": "",
            "checked": []
        }

    domain = clean_domain(
        company_website
    )

    if "amazon.jobs" in domain:

        return verify_amazon_vacancy(
            job_title
        )

    return verify_generic_vacancy(
        company_website,
        job_title
    )


# ============================================================
# REPORT
# ============================================================

def build_report(
    platform,
    company_name,
    job_title,
    location,
    company_website,
    recruiter_email,
    job_url,
    findings,
    website_result,
    vacancy_result,
    overall_result
):

    lines = []

    lines.append(
        "JOBSHIELD FRAUD DETECTION REPORT"
    )

    lines.append(
        "=" * 60
    )

    lines.append(
        f"Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append("")

    lines.append(
        f"Overall assessment: {overall_result}"
    )

    lines.append("")

    lines.append(
        "INPUT INFORMATION"
    )

    lines.append(
        f"Source: {platform}"
    )

    lines.append(
        f"Company: {company_name or 'Not provided'}"
    )

    lines.append(
        f"Job title: {job_title or 'Not provided'}"
    )

    lines.append(
        f"Location: {location or 'Not provided'}"
    )

    lines.append(
        f"Company website: "
        f"{company_website or 'Not provided'}"
    )

    lines.append(
        f"Recruiter email: "
        f"{recruiter_email or 'Not provided'}"
    )

    lines.append(
        f"Job URL: "
        f"{job_url or 'Not provided'}"
    )

    lines.append("")

    lines.append(
        "COMPANY WEBSITE"
    )

    lines.append(
        f"Status: {website_result.get('status', '')}"
    )

    lines.append(
        f"Domain: {website_result.get('domain', '')}"
    )

    lines.append("")

    lines.append(
        "OFFICIAL VACANCY"
    )

    lines.append(
        f"Status: {vacancy_result.get('status', '')}"
    )

    lines.append(
        f"Message: {vacancy_result.get('message', '')}"
    )

    for vacancy in vacancy_result.get(
        "matches",
        []
    ):

        lines.append(
            f"Matching vacancy: "
            f"{vacancy.get('title', '')}"
        )

        lines.append(
            f"Official URL: "
            f"{vacancy.get('url', '')}"
        )

        if vacancy.get(
            "location"
        ):

            lines.append(
                f"Official location: "
                f"{vacancy.get('location')}"
            )

    lines.append("")

    lines.append(
        "FRAUD / SAFETY INDICATORS"
    )

    if findings:

        for item in findings:

            lines.append(
                (
                    f"[{item['severity'].upper()}] "
                    f"{item['category']}: "
                    f"{item['message']}"
                )
            )

    else:

        lines.append(
            "No current rule-based fraud indicators detected."
        )

    lines.append("")

    lines.append(
        "IMPORTANT"
    )

    lines.append(
        "JobShield provides evidence-based indicators "
        "and public-information checks."
    )

    lines.append(
        "The report is not legal proof of fraud or identity."
    )

    lines.append(
        "A genuine company or genuine vacancy can still be "
        "used by an impersonating or fraudulent recruiter."
    )

    return "\n".join(
        lines
    )


# ============================================================
# MAIN UI
# ============================================================

st.title(
    "🛡️ JobShield"
)

st.subheader(
    "Job Scam Detection & Verification Assistant"
)

st.write(
    "Check suspicious job posts from Facebook, Instagram, "
    "LinkedIn, WhatsApp, Telegram, Naukri, Indeed, company "
    "websites and other sources."
)

st.info(
    "JobShield does not use a fake/genuine percentage. "
    "It evaluates warning indicators, recruiter details, "
    "public company information and available vacancy data."
)


# ============================================================
# SCREENSHOT
# ============================================================

st.subheader(
    "1. Upload Job Screenshot"
)

uploaded_image = st.file_uploader(
    "Upload screenshot of job post or recruiter message",
    type=[
        "png",
        "jpg",
        "jpeg"
    ]
)

ocr_text = ""

if uploaded_image:

    try:

        image = Image.open(
            uploaded_image
        )

        st.image(
            image,
            caption="Uploaded screenshot",
            use_container_width=True
        )

        with st.spinner(
            "Reading screenshot..."
        ):

            ocr_text = pytesseract.image_to_string(
                image
            )

        if ocr_text.strip():

            with st.expander(
                "Show extracted text"
            ):

                st.text_area(
                    "OCR text",
                    ocr_text,
                    height=220
                )

    except Exception as e:

        st.warning(
            f"Could not read screenshot: {e}"
        )


# ============================================================
# INPUT FORM
# ============================================================

st.subheader(
    "2. Job Details"
)

with st.form(
    "jobshield_form"
):

    platform = st.selectbox(
        "Where did you find this job?",
        [
            "Facebook",
            "Instagram",
            "LinkedIn",
            "WhatsApp",
            "Telegram",
            "Naukri",
            "Indeed",
            "Other job portal",
            "Company website",
            "Other website",
            "Unknown"
        ]
    )

    job_text = st.text_area(
        "Paste job post / job description / recruiter message",
        height=180
    )

    recruiter_text = st.text_area(
        "Recruiter details",
        height=120
    )

    company_name = st.text_input(
        "Claimed company name",
        placeholder="Example: Amazon"
    )

    job_title = st.text_input(
        "Job title",
        placeholder="Example: Cloud Support Associate"
    )

    location = st.text_input(
        "Job location",
        placeholder="Example: Pune / Remote / Berlin"
    )

    company_website = st.text_input(
        "Company official website",
        placeholder="https://www.example.com"
    )

    recruiter_email = st.text_input(
        "Recruiter email",
        placeholder="recruiter@example.com"
    )

    job_url = st.text_input(
        "Job post URL",
        placeholder="https://..."
    )

    submitted = st.form_submit_button(
        "🔎 Analyze Job for Fraud",
        use_container_width=True
    )


# ============================================================
# ANALYSIS
# ============================================================

if submitted:

    # --------------------------------------------------------
    # COMBINE TEXT
    # --------------------------------------------------------

    combined_text = "\n".join(
        value
        for value in [
            ocr_text,
            job_text,
            recruiter_text
        ]
        if value
    ).strip()


    # --------------------------------------------------------
    # EXTRACT
    # --------------------------------------------------------

    emails_found = extract_emails(
        combined_text
    )

    phones_found = extract_phones(
        combined_text
    )

    urls_found = extract_urls(
        combined_text
    )


    # --------------------------------------------------------
    # FRAUD ENGINE
    # --------------------------------------------------------

    findings = detect_fraud_indicators(
        combined_text,
        recruiter_email,
        company_website,
        job_url
    )


    # --------------------------------------------------------
    # WEBSITE
    # --------------------------------------------------------

    website_result = inspect_website(
        company_website
    )


    # --------------------------------------------------------
    # VACANCY
    # --------------------------------------------------------

    vacancy_result = verify_vacancy(
        company_website,
        job_title
    )


    # --------------------------------------------------------
    # FINAL STATUS
    # --------------------------------------------------------

    overall_result, css_class = overall_status(
        findings
    )


    # ========================================================
    # JOBSHIELD ASSESSMENT
    # ========================================================

    st.subheader(
        "🛡️ JobShield Assessment"
    )

    if overall_result == "HIGH-RISK INDICATORS DETECTED":

        st.markdown(
            """
            <div class="risk-box red-box">
            🔴 HIGH-RISK INDICATORS DETECTED
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            "JobShield found multiple strong indicators "
            "associated with job scams."
        )

        st.warning(
            "Do not send money or sensitive credentials "
            "until the recruiter and offer have been independently verified."
        )

    elif overall_result == "SUSPICIOUS":

        st.markdown(
            """
            <div class="risk-box orange-box">
            🟠 SUSPICIOUS
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            "JobShield detected strong warning indicators "
            "that require attention."
        )

    elif overall_result == "NEEDS VERIFICATION":

        st.markdown(
            """
            <div class="risk-box yellow-box">
            🟡 NEEDS VERIFICATION
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            "Some warning or verification concerns were detected."
        )

    else:

        st.markdown(
            """
            <div class="risk-box green-box">
            🟢 LOW CONCERN
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            "No major rule-based fraud indicators were detected."
        )

        st.caption(
            "Low concern is not a guarantee that the job or recruiter is genuine."
        )


    # ========================================================
    # FRAUD INDICATORS
    # ========================================================

    st.subheader(
        f"🚩 Fraud / Safety Indicators: {len(findings)}"
    )

    if findings:

        for item in findings:

            st.markdown(
                f"""
                <div class="evidence-box">
                <b>{item['severity'].upper()}</b>
                — {item['category']}<br>
                {item['message']}
                </div>
                """,
                unsafe_allow_html=True
            )

    else:

        st.write(
            "No current rule-based fraud indicators were detected."
        )


    # ========================================================
    # ========================================================
    # EXTRACTED INFORMATION
    # ========================================================

    salary_found = extract_salary_info(
        combined_text
    )

    location_found = extract_location_info(
        combined_text
    )

    official_application = official_application_detected(
        combined_text
    )

    if (
        emails_found
        or phones_found
        or urls_found
        or salary_found
        or location_found
    ):

        st.subheader(
            "📌 Information Found"
        )

        if emails_found:

            st.write(
                "**Email addresses:**"
            )

            for email in emails_found:

                st.code(
                    email
                )

        if phones_found:

            st.write(
                "**Phone numbers:**"
            )

            for phone in phones_found:

                st.code(
                    phone
                )

        if urls_found:

            st.write(
                "**URLs:**"
            )

            for url in urls_found:

                st.code(
                    url
                )

        if salary_found:

            st.write(
                "**Salary / compensation found:**"
            )

            for salary in salary_found:

                st.code(
                    salary
                )

        if location_found:

            st.write(
                "**Location found in post:**"
            )

            for detected_location in location_found:

                st.code(
                    detected_location
                )

        st.write(
            "**Official application route mentioned:** "
            + ("YES" if official_application else "NO / NOT DETECTED")
        )
    # COMPANY VERIFICATION
    # ========================================================

    st.subheader(
        "🌐 Company Verification"
    )

    st.write(
        f"**Website status:** "
        f"{website_result['status']}"
    )

    if website_result["domain"]:

        st.write(
            f"**Domain:** "
            f"{website_result['domain']}"
        )

    if website_result["title"]:

        st.write(
            f"**Page title:** "
            f"{website_result['title']}"
        )

    st.write(
        website_result["message"]
    )

    if (
        company_name
        and company_website
    ):

        name_signal = company_name_match(
            company_name,
            company_website
        )

        if name_signal == "MATCH":

            st.success(
                "Company name has a matching signal with the supplied website domain."
            )

        else:

            st.warning(
                "Company name and website domain could not be confidently matched."
            )


    # ========================================================
    # RECRUITER VERIFICATION
    # ========================================================

    st.subheader(
        "📧 Recruiter Verification"
    )

    if recruiter_email:

        st.write(
            f"**Recruiter email:** {recruiter_email}"
        )

        if company_website:

            recruiter_domain = ""

            if "@" in recruiter_email:

                recruiter_domain = (
                    recruiter_email
                    .split("@", 1)[1]
                    .strip()
                    .lower()
                    .removeprefix("www.")
                )

            company_domain = clean_domain(
                company_website
            )

            if (
                recruiter_domain
                and company_domain
                and recruiter_domain == company_domain
            ):

                st.success(
                    "✅ RECRUITER EMAIL DOMAIN MATCH"
                )

                st.write(
                    "The recruiter email uses the same domain "
                    "as the supplied company website."
                )

            elif (
                recruiter_domain
                and recruiter_domain in FREE_EMAIL_DOMAINS
            ):

                st.error(
                    "🔴 RECRUITER IDENTITY COULD NOT BE VERIFIED"
                )

                st.write(
                    "The recruiter is using a free email address "
                    "instead of the claimed company's official email domain."
                )

            else:

                st.error(
                    "🔴 RECRUITER EMAIL DOMAIN MISMATCH"
                )

                st.write(
                    "The recruiter email does not match "
                    "the claimed company's official domain."
                )

        else:

            st.info(
                "Add the company website to verify the recruiter email domain."
            )

    else:

        st.info(
            "Recruiter email was not provided."
        )


    # ========================================================
    # JOB URL
    # ========================================================

    st.subheader(
        "🔗 Job URL Analysis"
    )

    if job_url:

        job_url_domain = clean_domain(
            job_url
        )

        st.write(
            f"**Job URL domain:** "
            f"{job_url_domain}"
        )

        category = domain_category(
            job_url_domain
        )

        if category == "social":

            st.info(
                "The job URL is hosted on a social-media platform."
            )

        elif category == "job_platform":

            st.info(
                "The job URL is hosted on a third-party job platform."
            )

        elif category == "shortener":

            st.warning(
                "The job URL is a shortened link."
            )

        if is_safe_public_url(
            job_url
        ):

            status, final_url, page_title, _, _ = fetch_page(
                job_url
            )

            if status == 200:

                st.success(
                    "The supplied job URL is reachable."
                )

                if (
                    final_url
                    and final_url
                    != normalize_url(job_url)
                ):

                    st.write(
                        f"**Final URL after redirect:** "
                        f"{final_url}"
                    )

                if page_title:

                    st.write(
                        f"**Page title:** "
                        f"{page_title}"
                    )

            else:

                st.warning(
                    "The job URL could not be successfully checked."
                )

        else:

            st.error(
                "The supplied job URL failed the public URL safety check."
            )

    else:

        st.info(
            "Job post URL was not provided."
        )


    # ========================================================
    # OFFICIAL VACANCY
    # ========================================================

    st.subheader(
        "🔎 Official Vacancy Verification"
    )

    vacancy_status = vacancy_result["status"]

    if vacancy_status == "FOUND":

        st.markdown(
            """
            <div class="risk-box green-box">
            ✅ VACANCY FOUND ON EMPLOYER JOB SYSTEM
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            vacancy_result["message"]
        )

        st.write(
            "**Matching vacancies:**"
        )

        for index, vacancy in enumerate(
            vacancy_result["matches"],
            start=1
        ):

            st.write(
                f"**{index}. {vacancy['title']}**"
            )

            if vacancy.get(
                "location"
            ):

                st.caption(
                    f"Official location: "
                    f"{vacancy['location']}"
                )

            st.link_button(
                "Open official vacancy",
                vacancy["url"]
            )

        if vacancy_result["related"]:

            st.write(
                "**Related results not prioritized:**"
            )

            for item in vacancy_result["related"]:

                extra = ""

                if item.get(
                    "internship"
                ):

                    extra = (
                        " — internship/trainee variant"
                    )

                st.write(
                    f"• {item['title']}{extra}"
                )


    elif vacancy_status == "RELATED ONLY":

        st.markdown(
            """
            <div class="risk-box yellow-box">
            🟡 RELATED VACANCIES FOUND
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            vacancy_result["message"]
        )

        for item in vacancy_result["related"]:

            st.write(
                f"• {item['title']}"
            )

            st.link_button(
                "Open related vacancy",
                item["url"]
            )

        if vacancy_result.get(
            "search_page"
        ):

            st.link_button(
                "Open employer job search",
                vacancy_result["search_page"]
            )


    elif vacancy_status == "NOT FOUND":

        st.markdown(
            """
            <div class="risk-box orange-box">
            ⚠️ VACANCY NOT FOUND ON CHECKED PUBLIC PAGES
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            vacancy_result["message"]
        )

        if vacancy_result.get(
            "search_page"
        ):

            st.link_button(
                "Open employer job search",
                vacancy_result["search_page"]
            )

        elif vacancy_result.get(
            "checked"
        ):

            with st.expander(
                "Show checked pages"
            ):

                for page in vacancy_result["checked"]:

                    st.write(
                        page
                    )


    else:

        st.markdown(
            """
            <div class="risk-box grey-box">
            ℹ️ COULD NOT VERIFY OFFICIAL VACANCY
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write(
            vacancy_result["message"]
        )

        if vacancy_result.get(
            "search_page"
        ):

            st.link_button(
                "Open employer job search",
                vacancy_result["search_page"]
            )


    # ========================================================
    # JOB POST VS OFFICIAL INFORMATION
    # ========================================================

    st.subheader(
        "🧩 Job Post vs Official Information"
    )

    # Company
    if (
        company_name
        and company_website
    ):

        signal = company_name_match(
            company_name,
            company_website
        )

        if signal == "MATCH":

            st.success(
                "Company: ✅ MATCH SIGNAL"
            )

        else:

            st.warning(
                "Company: ⚠️ NEEDS VERIFICATION"
            )

    # Title
    if vacancy_status == "FOUND":

        st.success(
            "Job title: ✅ OFFICIAL MATCH FOUND"
        )

    elif vacancy_status == "RELATED ONLY":

        st.warning(
            "Job title: ⚠️ ONLY RELATED RESULTS FOUND"
        )

    elif vacancy_status == "NOT FOUND":

        st.warning(
            "Job title: ⚠️ NOT FOUND"
        )

    else:

        st.info(
            "Job title: ℹ️ COULD NOT VERIFY"
        )

    # Email
    if (
        recruiter_email
        and company_website
    ):

        if domains_match(
            recruiter_email,
            company_website
        ):

            st.success(
                "Recruiter email: ✅ DOMAIN MATCH"
            )

        else:

            st.error(
                "Recruiter email: 🔴 DOMAIN MISMATCH"
            )

    # Location
    if location:

        if vacancy_status == "FOUND":

            locations = [
                item.get(
                    "location",
                    ""
                )
                for item in vacancy_result["matches"]
                if item.get("location")
            ]

            if locations:

                user_words = word_tokens(
                    location
                )

                location_match = False

                for official_location in locations:

                    official_words = word_tokens(
                        official_location
                    )

                    if (
                        user_words &
                        official_words
                    ):

                        location_match = True
                        break

                if location_match:

                    st.success(
                        "Location: ✅ MATCH SIGNAL"
                    )

                else:

                    st.warning(
                        "Location: ⚠️ DOES NOT CLEARLY MATCH"
                    )

            else:

                st.info(
                    "Location: ℹ️ OFFICIAL LOCATION NOT AVAILABLE"
                )

        else:

            st.info(
                "Location: ℹ️ COULD NOT COMPARE"
            )


    # ========================================================
    # STRONG EVIDENCE SUMMARY
    # ========================================================

    if findings:

        high_findings = [
            item
            for item in findings
            if item["severity"] == "high"
        ]

        medium_findings = [
            item
            for item in findings
            if item["severity"] == "medium"
        ]

        if (
            len(high_findings) >= 2
            or (
                len(high_findings) >= 1
                and len(medium_findings) >= 2
            )
        ):

            st.subheader(
                "🚨 Strong Evidence Summary"
            )

            st.error(
                (
                    "Multiple independent warning signals "
                    "are present in this job communication."
                )
            )

            for item in findings:

                st.write(
                    f"• {item['message']}"
                )


    # ========================================================
    # SAFETY CHECKLIST
    # ========================================================

    st.subheader(
        "🔍 Before you trust the job"
    )

    checklist = [
        "Do not pay recruitment, registration, training, placement or security fees.",
        "Do not share OTPs, PINs, passwords, CVV or banking credentials.",
        "Verify the employer through an independently found official website.",
        "Verify the recruiter independently instead of trusting the message alone.",
        "Keep the original screenshot, messages, URLs, phone numbers and payment records.",
        "A real company or real vacancy does not automatically prove that the recruiter contacting you is genuine."
    ]

    for item in checklist:

        st.write(
            f"✓ {item}"
        )


    # ========================================================
    # REPORT
    # ========================================================

    st.subheader(
        "📄 Evidence & Report"
    )

    report = build_report(
        platform,
        company_name,
        job_title,
        location,
        company_website,
        recruiter_email,
        job_url,
        findings,
        website_result,
        vacancy_result,
        overall_result
    )

    st.download_button(
        "⬇️ Download JobShield Report",
        data=report,
        file_name="jobshield_report.txt",
        mime="text/plain",
        use_container_width=True
    )

    with st.expander(
        "Preview report"
    ):

        st.text(
            report
        )


    # ========================================================
    # OFFICIAL REPORTING
    # ========================================================

    st.subheader(
        "🚨 Suspected Job Scam?"
    )

    st.write(
        "Keep the original evidence and use the official "
        "cybercrime reporting channel for formal reporting."
    )

    st.link_button(
        "Open National Cyber Crime Reporting Portal",
        "https://www.cybercrime.gov.in/",
        use_container_width=True
    )

    st.write(
        "**Cyber Crime Helpline: 1930**"
    )


    # ========================================================
    # FINAL NOTE
    # ========================================================

    st.caption(
        "JobShield is a fraud-detection and verification assistant. "
        "Its result is based on detected indicators and available "
        "public information. It does not establish legal guilt, "
        "identity or criminal activity."
    )
