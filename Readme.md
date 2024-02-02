## App Name : fastapi-jwt-native

### This is a demo of jwt (Jason Web toakens) using Fast API & Uvicorn

###  Venv Name : venv311-jwn

Build command for docker image : docker build -t jwt-dcn .

Run Command to run without Docker : uvicorn --port 9000 main:app --reload
Run Command for docker : docker run -p 8000:8000  
Run docker in background mode : docker run -d -p 8000:8000 jwt-dcn  

Run command from windows CMD : uvicorn main:app --port 9000 --reload

Run command with mount volume instruction :

docker run -v C:\\Users\\haris\\python\\docker-write:/code -p 5000:5000  jwt-dcwf5k

This command mounts the C:\Users\haris\python\ddocker-write directory on the host system to the /path/in/container directory in the container.