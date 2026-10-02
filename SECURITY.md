# Security Policy

## Reporting a Security Issue

If you find a security issue in JobShield, please do not publish
sensitive exploit details publicly before the issue can be reviewed.

Open a GitHub security advisory or contact the project maintainer
through the repository's official contact method.

## Security Practices

JobShield is designed to:

- Avoid storing secrets in source code
- Ignore local secret files in Git
- Use Streamlit XSRF and CORS protections
- Limit uploaded file size
- Restrict user-supplied URL access to public destinations
- Re-check redirected URL destinations
- Avoid automatically submitting police/cybercrime complaints

## Important Limitation

JobShield is a prototype/MVP and is not guaranteed to be
completely secure or immune to attacks.

Before production deployment, the application should undergo
a professional security review, especially the server-side
URL fetching functionality.

## Privacy

Do not commit passwords, API keys, access tokens, private
credentials, or user evidence containing sensitive information
to the public repository.
