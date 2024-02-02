## App Name : fastapi-jwt-dc (write file Version)

### This is a demo of jwt (Jason Web tokens) using Fast API & Uvicorn with logging

###  Venv Name : venv311-jwt

Build command for docker image : docker build -t jwt-dcfw5k .

Run Command to run without Docker : uvicorn --port 9000 main:app --reload
VS Code Run Command for docker : docker run -p 8000:8000  
Run docker in background mode : docker run -d -p 8000:8000 jwt-dcfw5k  

Run command from windows CMD : uvicorn main:app --port 9000 --reload

Run command with mount volume instruction : ( Required for logging)

docker run -v C:\\Users\\haris\\python\\docker-write:/code -p 5000:5000  jwt-dcwf5k

This command mounts the C:\Users\haris\python\ddocker-write directory on the host system to the /path/in/container directory in the container.
