FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as a non-root user by default.
# Note: uid/gid 1000 matches the default Ubuntu user on many hosts, simplifying volume permissions.
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin app && \
    chown -R 1000:1000 /app

COPY --chown=1000:1000 requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=1000:1000 payments /app/payments
COPY --chown=1000:1000 scripts /app/scripts
COPY --chown=1000:1000 contracts /app/contracts

USER 1000:1000

CMD ["python", "-m", "payments.main"]
