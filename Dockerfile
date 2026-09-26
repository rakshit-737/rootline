# ROOTLINE API + attack-replay UI. Lab use only; binds to 0.0.0.0 inside the container.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY tests/fixtures ./fixtures
RUN pip install --no-cache-dir ".[api,ml,stix]" && useradd -r -u 10001 rootline
USER rootline
EXPOSE 8000
# Preloads the committed OTRF Log4Shell excerpt (Sysmon + AUOMS, fused) so the UI has a story.
CMD ["rootline", "serve", "fixtures/log4shell_sysmon.json", "fixtures/log4shell_auoms.json", "--host", "0.0.0.0", "--port", "8000"]
