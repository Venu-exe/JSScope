FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/Venu-exe/JSScope"
LABEL org.opencontainers.image.description="JavaScript endpoint, GraphQL and secret extractor for bug bounty recon"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY pyproject.toml README.md LICENSE jsscope.py ./
RUN pip install --no-cache-dir .

ENTRYPOINT ["jsscope"]
