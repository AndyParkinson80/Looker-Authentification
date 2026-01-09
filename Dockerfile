# Use the official Python image with the desired version
FROM python:3.12-slim-bookworm

# Set the working directory in the container to /app
WORKDIR /app

# Copy the contents of the current directory into /app in the container
COPY . /app

# Upgrade pip to the latest version
RUN pip install --upgrade pip

# Install any dependencies listed in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8080 to the outside world (adjust if necessary)
EXPOSE 8080

# Run the application
CMD ["python", "main.py", "--host=0.0.0.0", "--port=8080"]