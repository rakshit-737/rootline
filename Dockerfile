# ROOTLINE API + attack-replay UI. Lab use only, no authentication. It listens on 0.0.0.0 inside the
# container; publish it on loopback only:  docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/rootline
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests/fixtures ./fixtures
RUN pip install --no-cache-dir ".[api,ml,stix]" && useradd -r -u 10001 rootline
USER rootline
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \n  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
# Preloads the committed OTRF Log4Shell excerpt (Sysmon + AUOMS, fused) so the UI has a story.
CMD ["rootline", "serve", "fixtures/log4shell_sysmon.json", "fixtures/log4shell_auoms.json", "--fuse", "--host", "0.0.0.0", "--port", "8000"]
