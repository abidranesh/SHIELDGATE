FROM python:3.12-slim
RUN useradd --create-home app
WORKDIR /home/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER app
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/notes')"
CMD ["python", "-m", "flask", "--app", "app", "run", "--host", "0.0.0.0", "--port", "8000"]
