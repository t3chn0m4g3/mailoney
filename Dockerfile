FROM python:3.14-alpine

WORKDIR /app

# Python runtime defaults only. Application settings should come from
# mailoney.toml, docker-compose.yml, or explicit runtime environment variables.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy application code and install the package
COPY pyproject.toml README.md LICENSE mailoney.toml ./
COPY mailoney ./mailoney
COPY main.py ./main.py
RUN pip install --no-cache-dir .

# Run as non-root user for better security
RUN addgroup -S mailoney && \
    adduser -S -G mailoney mailoney && \
    mkdir -p /app/log && \
    chown -R mailoney:mailoney /app

USER mailoney

# Expose SMTP, SMTPS, and Submission
EXPOSE 25 465 587

# Run the application
ENTRYPOINT ["python", "main.py"]
