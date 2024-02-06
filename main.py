# main.py
# 2 Feb 2024
# Added file logging using loguru

# https://samedwardes.com/2022/04/14/fastapi-webapp-with-auth/
# venv : venv311jww - jwt - WebApp Running on Docker writing a file.
#
# status : Working with & without docker

# Run Command to run without Docker : uvicorn --port 9000 main:app --reload
# Run Command for docker : docker run -p 6000:6000  
# Run docker in background mode : docker run -d -p 6000:6000 jwt-dcn

# Run command from windows CMD : uvicorn main:app --port 9000 --reload


# Run command with mount volume instruction :

# docker run -v C:\\Users\\haris\\python\\docker-write:/code -p 5000:5000  jwt-dcwf5k

# This command mounts the C:\Users\haris\python\ddocker-write directory on the host system to the /path/in/container directory in the container.
#


#import logging
import os
import datetime as dt
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.handlers.sha2_crypt import sha512_crypt as crypto
from pydantic import BaseModel
from rich import inspect, print
from rich.console import Console
from loguru import logger
import qnu

QNU = True   # Get seed from Qnu

# A sample disk file written on the host
access_log = "jwt_access.log"
error_log  = "jwt_error.log"
user1_log = "./user1/jwt_user1.log"
user2_log = "./user2/jwt_user2.log"
#user3_log = "./user3/jwt_user3.log"


# Get the UID/username and GID of the current user
if os.name == 'nt':
    username = os.getlogin()
    uid = None
    gid = None
else:
    import pwd
    username = pwd.getpwuid(os.getuid()).pw_name
    uid = os.getuid()
    gid = os.getgid()


console = Console()
# Create a logger object
logger.add(access_log, rotation="2 MB", level="INFO")
logger.add(error_log, rotation="2 MB", level="ERROR")
logger.add(user1_log, rotation="2 MB", level="INFO")
logger.add(user2_log, rotation="2 MB", level="INFO")

"""
# Configure logging for cust_1.log
logging.basicConfig(filename=user1_log, level=logging.INFO)
logger1 = logging.getLogger('cust_1')
logger1.info('This is a message for cust_1.log')

# Configure logging for cust_2.log
logging.basicConfig(filename=user2_log, level=logging.INFO)
logger2 = logging.getLogger('cust_2')
logger2.info('This is a message for cust_2.log')

# Configure logging for cust_3.log
logging.basicConfig(filename=user3_log, level=logging.INFO)
logger3 = logging.getLogger('cust_3')
logger3.info('This is a message for cust_3.log')

"""
# Configure logging for cust_1.log using loguru
logger1 = logger.bind(log_file=user1_log)
logger1.info('This is a message for cust_1.log')

# Configure logging for cust_2.log using loguru
logger2 = logger.bind(log_file=user2_log)
logger2.info('This is a message for cust_2.log')

"""

# Create a file handler
#handler = logging.FileHandler(log_file)

#handler.setLevel(logging.ERROR)
# Get the file permissions
access_log_permissions = oct(os.stat(access_log).st_mode)[-3:]
error_log_permissions = oct(os.stat(error_log).st_mode)[-3:]
user1_log_permissions = oct(os.stat(user1_log).st_mode)[-3:]
user2_log_permissions = oct(os.stat(user2_log).st_mode)[-3:]

# print(f"File permissions: {permissions}")
# Change the file permissions
# 0o644 permission allows read access to all users and write access only to the owner of the file.
os.chmod(access_log, 0o644)
os.chmod(error_log, 0o644)
os.chmod(user1_log, 0o644)
os.chmod(user2_log, 0o644)

# Create a formatter
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)

# Add the handler to the logger
#logger.addHandler(handler)
"""
# --------------------------------------------------------------------------
# Models and Data
# --------------------------------------------------------------------------
class User(BaseModel):
    username: str
    hashed_password: str

# Create a "database" to hold your data. This is just for example purposes. In
# a real world scenario you would likely connect to a SQL or NoSQL database.
class DataBase(BaseModel):
    user: List[User]

DB = DataBase(
    user=[
        User(username="user1@gmail.com", hashed_password=crypto.hash("12345")),
        User(username="user2@gmail.com", hashed_password=crypto.hash("12345")),
    ]
)

def get_username_from_user(user: User) -> str:
    """
    Returns the username for the given User object.

    Args:
        user (User): User object containing username and hashed_password.

    Returns:
        str: Username corresponding to the User object, or "User not found" if not found.
    """
    if user and user.username:
        for db_user in DB.user:
            if db_user.username == user.username:
                return db_user.username
    return "User not found"

def get_user(username: str) -> User:
    user = [user for user in DB.user if user.username == username]
    if user:
        return user[0]
    return None

# --------------------------------------------------------------------------
# Setup FastAPI
# --------------------------------------------------------------------------
class Settings:
    SECRET_KEY: str = "secret-key"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 5  # in mins
    COOKIE_NAME = "access_token"


app = FastAPI()
templates = Jinja2Templates(directory="templates")
settings = Settings()


# --------------------------------------------------------------------------
# Authentication logic
# --------------------------------------------------------------------------
class OAuth2PasswordBearerWithCookie(OAuth2):
    """
    This class is taken directly from FastAPI:
    https://github.com/tiangolo/fastapi/blob/26f725d259c5dbe3654f221e608b14412c6b40da/fastapi/security/oauth2.py#L140-L171
    
    The only change made is that authentication is taken from a cookie
    instead of from the header!
    """
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        # IMPORTANT: this is the line that differs from FastAPI. Here we use 
        # `request.cookies.get(settings.COOKIE_NAME)` instead of 
        # `request.headers.get("Authorization")`
        authorization: str = request.cookies.get(settings.COOKIE_NAME) 
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token")


def create_access_token(data: Dict) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def authenticate_user(username: str, plain_password: str) -> User:
    user = get_user(username)
    if not user:
        return False
    if not crypto.verify(plain_password, user.hashed_password):
        return False
    return user


def decode_token(token: str) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials."
    )
    token = token.removeprefix("Bearer").strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        print(e)
        raise credentials_exception
    
    user = get_user(username)
    return user


def get_current_user_from_token(token: str = Depends(oauth2_scheme)) -> User:
    
    """
    Get the current user from the cookies in a request.

    Use this function when you want to lock down a route so that only 
    authenticated users can see access the route.
    """
    user = decode_token(token)
    return user


def get_current_user_from_cookie(request: Request) -> User:
    """
    Get the current user from the cookies in a request.
    
    Use this function from inside other routes to get the current user. Good
    for views that should work for both logged in, and not logged in users.
    """
    token = request.cookies.get(settings.COOKIE_NAME)
    user = decode_token(token)
    return user

def get_current_token_from_cookie(request: Request):
    """
    Get the current user from the cookies in a request.
    
    Use this function from inside other routes to get the current user. Good
    for views that should work for both logged in, and not logged in users.
    """
    token = request.cookies.get(settings.COOKIE_NAME)
    user = decode_token(token)
    return token


@app.post("token")
def login_for_access_token(
    response: Response, 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Dict[str, str]:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"username": user.username})
    
    # Set an HttpOnly cookie in the response. `httponly=True` prevents 
    # JavaScript from reading the cookie.
    response.set_cookie(
        key=settings.COOKIE_NAME, 
        value=f"Bearer {access_token}", 
        httponly=True
    )  
    return {settings.COOKIE_NAME: access_token, "token_type": "bearer"}


# --------------------------------------------------------------------------
# Home Page
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    console.log("[green]About to write on log file")
    #console.print(f'{access_log} permissions: {access_log_permissions}')
    #console.print(f'{error_log} permissions: {error_log_permissions}')
    # Display the file ownership info based on the OS
    if os.name == 'nt':
        console.print(f'OS: {os.name} File ownership: {username}')
    else:
        # Change the ownership of the file
        os.chown(access_log, uid, gid)
        os.chown(error_log, uid, gid)
        console.print(f'OS: {os.name} File ownership:uid {uid} gid: {gid}')
    
    
    try:
        user = get_current_user_from_cookie(request)
    except:
        user = None
    context = {
        "user": user,
        "request": request,
    }

   
   
    return templates.TemplateResponse("index.html", context)


# --------------------------------------------------------------------------
# Private Page
# --------------------------------------------------------------------------
# A private page that only logged in users can access.
# The method writes in text file, reads the same and displays a message

@app.get("/private", response_class=HTMLResponse)


def index(request: Request, user: User = Depends(get_current_user_from_token)):

    """
    try:
        with open(disk_file, "w") as f:
            f.write("This is an example text file created within a FastAPI app deployed with Docker.")
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")

    
    #------------------------------------------------------------
    try:
        with open(disk_file, "r") as f:
            message = f.read()
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        message = ""
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
        message = ""
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        message = ""
    """

    user_name = get_username_from_user(user)
    log_user = None
    message = f'User {user_name} logged into Private Page.'
    
    context = {
        "user": user,
        "request": request,
        "message": message, 
    }
    
    token_used = get_current_token_from_cookie (request)
    console.print(f'jwt token_used by {user_name} -> [{token_used}]\n')

    if 'user1' in  user_name:
        log_user = 'user1'
        logger1.info(f'User {log_user} accessed Private Page.')
        logger1.info(f'jwt token_used by {user_name} -> {token_used}')
        console.print(f'User {log_user} accessed Private Page.')
        if QNU:
            console.print(f'User {log_user}: About to fetch QNU Seed...')
            qnu_data = qnu.randHex()
            console.print(f'QNU Data-> {qnu_data}')
            logger1.info(f'QNU Data-> {qnu_data}')
            
    elif 'user2' in  user_name:
        log_user ='user2'
        logger2.info(f'User {log_user} accessed Private Page.')
 
        console.print(f'User {log_user} accessed Private Page.')
    else:
        log_user = 'user'
        #logger3.info(f'User {log_user} type [{type(user)}] accessed Home Page.')
        console.print(f'User {log_user} accessed Private Page.')


    # Log an info message
    #logger.info(message)
    return templates.TemplateResponse("private.html", context)

# --------------------------------------------------------------------------
# Login - GET
# --------------------------------------------------------------------------
@app.get("/auth/login", response_class=HTMLResponse)
def login_get(request: Request):
    context = {
        "request": request,
    }
    return templates.TemplateResponse("login.html", context)


# --------------------------------------------------------------------------
# Login - POST
# --------------------------------------------------------------------------
class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.username = form.get("username")
        self.password = form.get("password")

    async def is_valid(self):
        if not self.username or not (self.username.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or not len(self.password) >= 4:
            self.errors.append("A valid password is required")
        if not self.errors:
            return True
        return False


@app.post("/auth/login", response_class=HTMLResponse)
async def login_post(request: Request):
    form = LoginForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            response = RedirectResponse("/", status.HTTP_302_FOUND)
            login_for_access_token(response=response, form_data=form)
            form.__dict__.update(msg="Login Successful!")
            console.log("[green]Login successful!!!!")
            return response
        except HTTPException:
            form.__dict__.update(msg="")
            form.__dict__.get("errors").append("Incorrect Email or Password")
            return templates.TemplateResponse("login.html", form.__dict__)
    return templates.TemplateResponse("login.html", form.__dict__)


# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------
@app.get("/auth/logout", response_class=HTMLResponse)
def login_get():
    response = RedirectResponse(url="/")
    response.delete_cookie(settings.COOKIE_NAME)
    return response