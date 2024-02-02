# loguru_test.py
# Windows Command : uvicorn main:app --host 0.0.0.0 --port 80 --workers 4 --log-level info
"""
It is possible that the Windows CMD hangs after Ctrl C is pressed if the app was started 
with the --workers 4 option because of a bug in the Uvicorn server. 
This bug causes the server to hang when it receives a Ctrl C signal while 
running with multiple worker processes1.

To work around this issue, you can try using the --reload option instead 
of the --workers option. The --reload option will automatically reload the server 
whenever changes are made to the code, which can help prevent the server 
uvfrom hanging
"""


from fastapi import FastAPI
from loguru import logger

app = FastAPI()

logger.add("loguru_access.log", rotation="10 MB", level="INFO")
logger.add("loguru_error.log", rotation="10 MB", level="ERROR")

@app.get("/")
async def root():
    logger.info("Hello, world from loguru_test!")
    return {"message": "Hello, world from loguru_test!"}
