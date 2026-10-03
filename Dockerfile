# Using the official Python image as a starting point
FROM python:3.12-slim

# Everything inside the container will live in /app
WORKDIR /app

# Copy dependencies
COPY app/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy our Hades-Warden app
COPY app/hades ./hades

# our app listens on port 8000
EXPOSE 8000

# Starts FastAPI when container starts
CMD ["fastapi", "run", "hades/main.py", "--host", "0.0.0.0", "--port", "8000"]
