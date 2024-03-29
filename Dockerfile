FROM python:3.11-slim-buster

#ARG PORT=6000

# Set the environment variable for the application
#ENV PORT=$PORT

#
WORKDIR /code

#
COPY ./requirements.txt .

#
RUN pip install --no-cache-dir --upgrade -r requirements.txt

#
COPY . .

# entrypoint.sh for the write file version
RUN chmod +x /code/wf_entrypoint.sh

#EXPOSE $PORT
EXPOSE 5000

ENTRYPOINT ["/code/wf_entrypoint.sh"]
#
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", $PORT]