FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y p7zip-full

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy all app files (including certs/templates if any)
COPY . .

# Expose HTTPS port
EXPOSE 8443

# Start the app
CMD ["python", "sanitization_app.py", "--serve"]