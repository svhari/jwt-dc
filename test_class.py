#test_class.py

from pydantic import BaseModel
from typing import Dict, List, Optional
from passlib.handlers.sha2_crypt import sha512_crypt as crypto

from loguru import logger
import copy
from rich.console import Console
import os
import sys

import subprocess
import qnu

# A sample disk file written on the host
access_log = "jwt_access.log"
error_log  = "jwt_error.log"
user1_log = "./user1/user1.log"
user2_log = "./user2/user2.log"

# Specify absolute paths for log files
##user1_log = os.path.abspath("C:Users/haris/python/fastapi-jwtapp-dc/user1/jwt_user10.log")
#user2_log = os.path.abspath("C:Users/haris/python/fastapi-jwtapp-dc/user1/jwt_user10.log")

# Run the icacls command to grant permissions to Everyone - F for Full control
#subprocess.run(["icacls", user1_log, "/grant", "Everyone:F"], check=True)
#subprocess.run(["icacls", user2_log, "/grant", "Everyone:F"], check=True)

# Set permissions (full control) for everyone
#os.chmod(user1_log, 0o777)  # Use 0o777 for Python 3
#os.chmod(user2_log, 0o777)  # Use 0o777 for Python 3

# Initialize the default logger
logger.remove()  # Remove any default sinks (handlers)
logger_template = copy.deepcopy(logger)
logger.add(sys.stderr)


@logger.catch
def main():

    username = os.getlogin()
    print(f"Current username: {username}")

    # Your main code here
    # Create directories if they don't exist
    for log_file in [user1_log, user2_log]:
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)


    console = Console()
    # Create a logger object
    #logger.add(access_log, rotation="2 MB", level="INFO")
    #logger.add(error_log, rotation="2 MB", level="ERROR")

    # Create a deep copy of the logger for user1
    user1_logger = copy.deepcopy(logger_template)
    user1_logger.add(user1_log)  # Add a sink (handler) for user1's log file

    # Create a deep copy of the logger for user2
    user2_logger = copy.deepcopy(logger_template)
    user2_logger.add(user2_log)  # Add a sink (handler) for user2's log file

    """
    # Configure logging for cust_1.log using loguru
    logger1 = logger.bind(log_file=user1_log)
    logger1.info('This is a message for cust_1.log')

    # Configure logging for cust_2.log using loguru
    logger2 = logger.bind(log_file=user2_log)
    logger2.info('This is a message for cust_2.log')

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

    user = User(username="user1@gmail.com", hashed_password="hashed_password_here")
    #user = User(username="user2@gmail.com", hashed_password="hashed_password_here")
    user_name = get_username_from_user(user)
    console.print(f"Username for user '{user_name}': {user_name}")

    if 'user1' in  user_name:
        log_user = 'user1'
        user1_logger.info(f'User {log_user} accessed Private Page.')
        console.print (f'User {log_user} accessed Private Page.')
        qnu.randHex()
    elif 'user2' in  user_name:
        log_user ='user2'
        user1_logger.info(f'User {log_user} accessed Private Page.')
        console.print (f'User {log_user} accessed Private Page.')
    else:
        log_user = 'user'
        logger.info(f'User {log_user} type [{type(user_name)}] accessed Home Page.')
        console.print (f'User {log_user} accessed Home Page.')
    
    
if __name__ == "__main__":
    main()
