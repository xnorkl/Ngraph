#!/usr/bin/python3

import argparse
import json
import os
import re
import requests
import subprocess as sp
import sys
from pprint import pprint
from pyArango.connection import *
from pyArango.collection import *
from pyArango.query import *

## TODO Create a proper python app file structure.
## TODO Create a DOT ENV for storing secrets.
## TODO Create a Conf file and reduce arguments parsers.

## Scanning

def vuln_scan(r, arg='', mode=0):
    ''' Run Vuln Scan and filter output on all IPs in a list. '''

    def inv_nmap(payload):
        ''' Call Nmap as a sub process. '''
        # TODO Would this be better with py nmap module?

        return sp.check_output(["/usr/bin/nmap"] + payload)

    def hosts(r):
        ''' Use Nmap to find all UP hosts in range. '''

        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        return ip_pattern.findall(inv_nmap(["-sn", r]).decode())

    def scan(ip, p=["-sC", "-sV"]):
        '''Call nmap vuln script. '''

        if type(p) is str:
            p = p.split()
        print(p)
        payload = p + [ip]

        return inv_nmap(payload)

    def build(scan):
        '''Pattern match scan output and append to dictionary. '''

        # Create a list of nmap output.
        l = scan.decode().split('\n')
        replace = ['|','_','/']
        for ch in replace:
            l = [s.replace(ch, '') for s in l if s]
        print(l)
        # Define Regex Patterns.
        # TODO CVEs, MAC and OS patterns need work.
        pattern={}
        pattern["Services"] = re.compile(r'(\d+)\w+\s+open(.+)')
        pattern["CVEs"] = re.compile(r'(CVE-\d+-\d+)')
        pattern["MAC"] = re.compile(r'MAC Address:(.+)')
        pattern["OS"] = re.compile(r'OS details:(.+)')
        pattern["ServiceInfo"] = re.compile(r'Service Info:(.+)')

        # Map patterns to output for each networked device.
        sub_dict = {}
        sub_dict["raw"] = l

        #TODO: Clean this up. Either single dict-comprehension or none at all.
        for sub in pattern.keys():
            if sub == "Services":
                sub_dict[sub] = {m.group(1):" ".join(m.group(2).split())
                    for m in (pattern[sub].match(s) for s in l) if m}
            else:
                for s in l:
                    m = pattern[sub].match(s)
                    if m:
                        sub_dict[sub] = m.group(1)

        return sub_dict
    # End of build()

    # Modes: 0 = read cidr, 1 = read list of IPs
    if mode == 0:
        ip_list = hosts(r)
    elif mode == 1:
        with open(r) as file:
            ip_list = file.read().splitlines()

    # If no arguments were given, scan will use default -sC -sV
    # TODO this would be better as a Mode.
    if arg == '':
        for ip in ip_list:
            push(ip, build(scan(ip)))
    else:
        for ip in ip_list:
            push(ip, build(scan(ip, p=arg)))

    # Try to add a Fulltext Index to 'raw' attributes in collection.
    # This will allow searching collection for text patterns without needing to aql.
    try:
        getdb(arg().db).ensureFulltextIndex(raw)
    except Exception as e:
        print(e)

    return getcoll(arg().collection).fetchAll()

## ArangoDB API

### Database Handling

def conn():
    # TODO best to dot environment + config to handle this.
    return Connection(
        arangoURL=f'http://{arg().server}:{arg().port}',
        username="CHANGEME",
        password="CHANGEME")

def hasdb(name):
    ''' Return Bool on Database Name. '''
    return conn().hasDatabase(name)

def getdb(name):
    ''' Return DB is exists. Create DB and return if not. '''
    if not hasdb(name):
        conn().createDatabase(name)
    return conn()[name]

def getcoll(name, check=False):
    ''' Return a Collection. If check is True, then only pass name if collection exists. '''

    db = getdb(arg().db)

    if db.hasCollection(name) and not check:
        ans = db[name]

    if not db.hasCollection(name) and not check:
        print(f'Creating Collection {name}')
        getdb(arg().db).createCollection(className='Collection', name=name)
        ans = db[name]

    elif db.hasCollection(name) and check:
        ans = name
    return ans

def push(key, obj):
    '''
    Create a Doc.
    If Collection and DB do not exist,
    create DB and Collection, then create doc.
    '''
    col = getcoll(arg().collection)
    doc = col.createDocument(obj)
    doc._key = key
    doc.save()
    print(doc)

### Queries

def get_aql(expression):
    ''' Helper for AQLQuery. '''
    return getdb(arg().db).AQLQuery(expression, rawResults=True)

def query(expression):
    ''' Takes an AQL expression and returns a list of responses. '''
    return [i for i in get_aql(expression)]

def find(expression, mode=0):
    ''' Takes a string and passes to various functions. '''

    # grab collection
    coll = getcoll(arg().collection, check=True)

    # sub-queries
    raw = '{"HOST":x._key,"SERVICES": x.Services,"SERVICEINFO": x.ServiceInfo}'
    key = 'x._key'

    if mode == 0:
        sub = key
    elif mode == 1:
        sub = raw

    if expression == 'ALL':
        filt = f'x'

    elif expression == 'HTTP':
        filt = 'x.Services["80"] != null || x.Services["443"] != null'
        filt += ' x.Services["8000"] != null || x.Services["8080"] != null'

    elif expression == 'NSF':
        filt = 'x.Services["111"] != null'

    elif expression == 'RPC':
        filt = 'x.Services["135"] != null'

    elif expression == 'SMB':
        filt = 'x.Services["445"] != null || x.Services["139"] != null'

    elif expression == 'SNMP':
        filt = 'x.Services["161"] != null'

    elif expression == 'SSH':
        filt = 'x.Services["22"] != null'

    aql = f'FOR x IN {coll} FILTER {filt} RETURN {sub}'

    # If Mode is 3 then evaluate aql from cli.
    if mode == 3:
        aql = f'FOR x IN FULLTEXT({coll},"raw","{expression}") RETURN {sub}'

    ans = [i for i in get_aql(aql)]

    return ans

def node(ip):
    return getcoll(arg().collection).fetchDocument(ip, rawResults=True)

## Argument Parser

def arg():
    ''' Argument parser with sub parsers. Returns arguments.'''
    # TODO Would be cleaner as a class.

    # Parent parser.
    parser = argparse.ArgumentParser(
        prog='nmapy',
        description='simple wrapper for nmap')

    parser.add_argument('-s',   '--server', dest='server', type=str, default='localhost')
    parser.add_argument('-p',   '--port', dest='port', type=str, default='8529')
    parser.add_argument('-db',  '--database', dest='db', type=str)
    parser.add_argument('-c',   '--collection', dest='collection', type=str)

    # Sub parsers.
    subparser = parser.add_subparsers(help='commands', dest='cmd')

    ## Scan parser.
    # TODO create built in scans
    # TODO if a protocol returns nill don't store
    scan_parser = subparser.add_parser('scan', aliases=['sc'])
    scan_parser.add_argument('nmap', type=str)
    scan_group = scan_parser.add_mutually_exclusive_group()
    scan_group.add_argument('-r','--range', dest='range', type=str)
    scan_group.add_argument('-l','--list', dest='list', type=str)
    scan_parser.add_argument('--vuln', dest='vuln', action='store_true')

    ## Query parser.
    query_parser = subparser.add_parser('query', aliases=['q'])
    query_parser.add_argument('expression', help='AQL expression.')

    ## Get command
    get_parser = subparser.add_parser('get', aliases=['g'])
    get_parser.add_argument('type',
                            choices=[
                                'ALL',
                                'HTTP',
                                'NSF',
                                'RPC',
                                'SMB',
                                'SNMP',
                                'SSH'
                            ],
                            help='Returns fields for all matching nodes.')
    get_parser.add_argument('-v', '--verbose', dest='raw', action='store_true')
    ## Find command
    find_parser = subparser.add_parser('find', aliases=['f'])
    find_parser.add_argument('string', type=str, help='Returns nodes with matching text')

    ## Node command
    node_parser = subparser.add_parser('node', aliases=['n'])
    node_parser.add_argument('key', help='Get node by IP address')
    node_parser.add_argument('--raw', dest='raw', action='store_true')

    return parser.parse_args()

def cmd(args):
    ## Control Flow

    # Scan
    if args.cmd == 'scan' or args.cmd == 'sc':
        if not args.nmap:
            resp = vuln_scan(args.range)
        elif args.nmap and args.range:
            resp = vuln_scan(args.range, args.nmap)
        elif args.nmap and args.list:
            resp = vuln_scan(args.list, args.nmap, mode=1)

    # Query
    elif args.cmd == 'query' or args.cmd == 'q':
        resp = query(args.expression)

    # Get
    elif args.cmd == 'get'or args.cmd == 'g':
        if not args.raw:
            resp = find(args.type, mode=0)
        else:
            resp = find(args.type, mode=1)

    # Find
    elif args.cmd == 'find' or args.cmd == 'f':
        resp = find(args.string)

    elif args.cmd == 'node' or args.cmd == 'n':
        resp = node(args.key)

    else:
        resp = "oops."

    return resp

def main():

    def p(obj):
        '''
        Check obj type. If string, dont' pprint.
        Return output.
        '''
        if type(obj) is str:
            out = print(obj)
        else:
            out = pprint(obj, indent=2, sort_dicts=False)
        return out

    args = cmd(arg())
    # TODO move control flow to p()
    if type(args) is dict:
        p(args)
    elif type (args) is list:
        for i in args:
            p(i)
    else:
        print(type(args))
        p(args)

if __name__ == '__main__':
    main()
