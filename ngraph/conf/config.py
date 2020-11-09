from os import environ, path
from dotenv import load_dotenv, set_key

# Get .env file
basedir = path.abspath(path.dirname(__file__))
dot_env = path.join(basedir, '.env')
load_dotenv(dot_env)

def update(k, v):
    set_key(dot_env, k, v)

# Database State
CUR_DB  = environ.get('DATABASE')
CUR_COL = environ.get('COLLECTION')

# ArangoDB Config
AR_SERV = environ.get('SERVER')
AR_PORT = environ.get('PORT')
AR_USER = environ.get('ARANGO_USER')
AR_PASS = environ.get('ARANGO_PASS')
