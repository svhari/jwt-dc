FROM python:3.11-slim-buster

#
WORKDIR /code

#
COPY ./requirements.txt .

#
RUN pip install --no-cache-dir --upgrade -r requirements.txt

#
COPY . .

RUN chmod +x /code/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/code/entrypoint.sh"]
#
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]