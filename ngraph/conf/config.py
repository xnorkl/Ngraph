from os import environ, path
from dotenv import load_dotenv, set_key

# Get .env file
basedir = path.abspath(path.dirname(__file__))
dot_env = path.join(basedir, '.env')
load_dotenv(dot_env)

# Database State
CUR_DB  = environ.get('DATABASE')
CUR_COL = environ.get('COLLECTION')

def update(k, v):
    set_key(dot_env, k, v)

# ArangoDB Config
AR_SERV = '192.168.88.251'
AR_PORT = '8529'
AR_USER = environ.get('ARANGO_USER')
AR_PASS = environ.get('ARANGO_PASS')