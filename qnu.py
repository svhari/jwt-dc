# qnu.py
import hashlib
import json
import requests
import numpy as np
from time import time,sleep
from rich.console import Console

import warnings
warnings.filterwarnings('ignore')


console = Console()
def randHex():
    #randLen = input("Enter the length of rand bytes: ")
    randLen = 64
    url = "https://eaas.qnulabs.com/api/v1/randbin"
    result = hashlib.sha512((str("6b176526-0f09-ca60-a91f-3ace64af256d")+str("|")+str("0")+str("|")+str(randLen)+str("|")+str("$2a$04$YmVTAOYxEeGIK9s6FV72QeniQ0G1nDurg0S0p2ln5VPaew.Y/AKpW")).encode())
    console.print(f'result->{result}')
    data= {
            'API_Key'     : '6b176526-0f09-ca60-a91f-3ace64af256d',
            'APISalt'     : '$2a$04$YmVTAOYxEeGIK9s6FV72QeniQ0G1nDurg0S0p2ln5VPaew.Y/AKpW',
            'Rand_type'   : int(0),
            'Length'      : int(randLen),
            'Hash'        : result.hexdigest()
            }
    console.print(f'data->{data}\n')
    response = -1
    while response < 0:
        try :
            # print("Inside try\n")
            r = requests.post(url, data=json.dumps(data),verify=False,timeout=1)
            if r.status_code == 200 :
                response = 1
                console.print("200 OK")
                #_ = input("Press any key to continue...")
            #_ = input("About to try again...Press any key to continue...")
        except Exception as error:
            print("An exception occurred:", error) # An exception occurred
            continue
    result = r.content.decode("utf-8").split(',')
    randNum = result[0].split('"')
    console.print(f'randNum -> {randNum[3]}')
    # print(type(randNum[3]))
    #with open('my_file.txt', 'w') as f:
    #    f.write(result)
    return data

if __name__ == "__main__":
    randHex()
