# 
FROM python:3.11-slim-buster

# 
WORKDIR /code

# 
COPY ./requirements.txt .

# 
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# 
COPY . .

# 
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]