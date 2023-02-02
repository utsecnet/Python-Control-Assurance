#!/usr/bin/python3
# -*- coding: utf-8 -*-

''' Pull control assurance measures from Elasticsearch into MySQl DB

THIS IS NOT COMPLETE! It barely even authenticates yet!

API Documentation
Get Token
* https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-get-token.html

using the elasticsearch module
https://elasticsearch-py.readthedocs.io/en/v7.17.9/

'''

__file__ = "ca_jamfpro.py"
__authors__ = ["Rich Johnson", "Austin Pratt"]
__date__ = "2022-12-22"
__depricated__ = "False"
__maintainer__ = "Austin Pratt"
__status__ = "Production"
__version__ = "1.0"

# TODO: There are some extention atributes we may wish to pull down and place
#       into 3rd-normal-form tables so that we can do advanced corelation
#       between endpoints.

# Standard Python libraries
import base64
from calendar import weekheader
import ssl
import datetime
import logging
import json
import math

# Third party Python libraries
import requests
from requests.auth import HTTPBasicAuth 
import mysql.connector
from elasticsearch import Elasticsearch

# Custom libraries
from modules.secrets import SECRETS
from modules.dbConn import *

########################
# FUNCTIONS
########################

# Data retention - Delete data from tables older than X months
def data_retention():

    logging.debug("entered function: data_retention")

    # Delete data older than X months
    limit = 12

    sql = ("DELETE FROM sentinelone_rollup WHERE date <= CURDATE() - INTERVAL %s MONTH")

    data = (limit, )

    try:
        ret = db.doExec(sql,data)
        logging.info('Purged data older than %s months from table "%s".', limit, table_metrics_rollup)
    except mysql.connector.Error as err:
        logging.error(err)
	            
    # Close function data_retention

########################
# Global Variables
########################

# Valid log levels include:
# INFO
# WARNING
# ERROR
# CRITICAL
# DEBUG

# Logging options
#log_File = '/opt/scripts/logs/ca_jamfpro.log'
log_File = 'elasticsearch.txt'
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.DEBUG, filemode='w')

# Define the URL that we will use throughout this script
# And pull in the credentials from the secrets.json file
if 'elasticsearch' in SECRETS:
    
    # Build the base URL that will be passed into the API calls
    baseUrl = 'https://{0}'.format(SECRETS['elasticsearch']['host'])
    logging.debug('baseUrl: %s', baseUrl)

    # Credentials used to request the Token
    user = '{0}'.format(SECRETS['elasticsearch']['user'])
    password = '{0}'.format(SECRETS['elasticsearch']['password'])

    # Retreive the API token
    es = Elasticsearch([baseUrl],http_auth=(user,password))
    #url = '{0}/_security/oauth2/token'.format(baseUrl)
    request = requests.post(url, auth=HTTPBasicAuth(user, password), verify=False)
    response = request.json()

    print(response)
    token = response['token']
    token_string = "Bearer " + token

db = dbConn(
    '{0}'.format(SECRETS['mysql']['host']),
    '{0}'.format(SECRETS['mysql']['user']),
    '{0}'.format(SECRETS['mysql']['password']),
    '{0}'.format(SECRETS['mysql']['database'])
)

# Define the MySQL tables 
table_asset = "jamfpro_asset"
table_mdm = "jamfpro_mdm"
table_asset_tag = "jamfpro_asset_tag"
table_tag = "jamfpro_tag"
table_metrics_rollup = "jamfpro_rollup"

# Used to set the date in the date column of the MySQL tables
ymd = '%Y-%m-%d'

# Define the format of the date that SentinelOne presents via the API
# Some dates are formated with a %f, others are not - we need to accomodate both
iso = '%Y-%m-%dT%H:%M:%S.%fZ'
iso2 = '%Y-%m-%dT%H:%M:%SZ'

# We will take the date format from SentinelOnes's API and convert it to a
# format that we can then insert into MySQL
mysqliso = '%Y-%m-%d %H:%M:%S'

# Today's date e.g.: 2022-01-25
#today = datetime.datetime.strptime(datetime.datetime.strftime(datetime.date.today(), ymd), ymd).date()
today = datetime.datetime.strftime(datetime.datetime.today(), ymd)

# Timestamp e.g.: 2022-01-25 12:34:24
timestamp = datetime.datetime.strftime(datetime.datetime.now(), mysqliso)

# These tables will be purged of data older than X months from the 
# data_retention function
cleanUp = [table_metrics_rollup]

# We pass this NULL value so MySQL can AUTO_INCREMENT the primary key
rowId = None

########################
# ACTION!
########################



# # Run this last
# data_retention()