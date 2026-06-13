# VULN: Outdated base image with known CVEs
FROM python:3.7-slim

# VULN: Running as root (no USER directive)
WORKDIR /app

# VULN: Secrets passed as ENV variables (detectable by scanners)
ENV DATABASE_URL=postgresql://cloudcart:CloudCartDB_Pass123!@postgres:5432/cloudcart
ENV SECRET_KEY=cloudcart-super-secret-key-12345-do-not-share
ENV JWT_SECRET=jwt-secret-hardcoded-in-source-code
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV STRIPE_API_KEY=sk_live_51HCloudCartFakeStripeKeyForTraining
ENV FLASK_DEBUG=true
ENV FLASK_ENV=development

COPY requirements-vulnerable.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads && chmod 777 uploads

# VULN: No HEALTHCHECK directive

EXPOSE 5000

# VULN: Running as root
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--reload", "wsgi:app"]
