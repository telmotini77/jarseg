FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cyberseg_engine ./cyberseg_engine
CMD ["python", "-m", "cyberseg_engine.main"]
