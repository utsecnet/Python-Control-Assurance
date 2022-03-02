#!/usr/bin/python3

# Standard Python libraries
from calendar import weekheader
import ssl
import datetime
import logging
import json

# Third party Python libraries
import requests
import mysql.connector

# Custom libraries
from modules.secrets import SECRETS
from modules.dbConn import *

########################
# FUNCTIONS
########################

# Generate the API headers
def api_headers():
    
    header = {
        'Accept': 'application/json',
        'Accept-Encoding': 'deflate, gzip',
        'Accept-Language': 'en-us',
    }

    logging.debug('API headers: %s', str(header))

    return header
    # Close function api_headers

# Get the details of the scan engines and write to database
def ivm_get_scan_engines (): 

    # The full URL including the API endpoint
    url = '{0}/scan_engines'.format(baseUrl)
    
    response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
    response_json = response.json()

	# Scan engines we dont care about and don't want to insert into the database 
    blacklist_scan_engines = ['Rapid7 Hosted Scan Engine','Rapid7 Hosted','Default Engine Pool','Local scan engine']
    
	# Process each object in the JSON, saving the data to variables, and 
	# ultimatly writing it to our MySQL database

    logging.debug('response: %s', response)

    for i in response_json['resources']:

        if i['name'] not in blacklist_scan_engines:
            
            # Name of the scan engine - example: Insightscan
            name = i['name']
            logging.debug('name: %s', name)
            
            # Address of the scan engine, could be FQDN or IP Address
            address = i['address']
            logging.debug('address: %s', address)

            #Scan engine status - we want to see "Active"!
            status = i['status']
            logging.debug('status: %s', address)

            # Rapid7's scan engine id
            scan_engine_id = i['id']
            logging.debug('scan_engine_id: %s', scan_engine_id)

            # Date the scan engine last checked into the core server
            # We want this to be within 3 hours
            last_refreshed_date = datetime.datetime.strftime(datetime.datetime.strptime(i['lastRefreshedDate'], iso), mysqliso)
            logging.debug('last_refreshed_date: %s', last_refreshed_date)

            # Last time the scan engine received updates
            last_updated_date = datetime.datetime.strftime(datetime.datetime.strptime(i['lastUpdatedDate'], iso), mysqliso)
            logging.debug('last_updated_date: %s', last_updated_date)
            
            # Content version - contains the vulnerabilty check updates
            content_version = i['contentVersion']
            logging.debug('content_version: %s', content_version)
            
            # Date of the last content update
            content_version_date = content_version[content_version.find(char1)+1 : content_version.find(char2)]
            logging.debug('content_version_date: %s', content_version_date)

            # Product version - contains new feature updates.
            # Updates less frequesntly than content.
            product_version = i['productVersion']
            logging.debug('product_version: %s', address)

            #Date of the last product update
            product_version_date = product_version[product_version.find(char1)+1 : product_version.find(char2)]
            logging.debug('product_version_date: %s', address)

            sql = "INSERT INTO " + str(table_scan_engines) + " (\
                    id, \
                    date, \
                    name, \
                    address, \
                    scan_engine_id, \
                    status, \
                    last_refreshed_date, \
                    last_updated_date, \
                    content_version, \
                    content_version_date, \
                    product_version, \
                    product_version_date \
                ) VALUES (\
                    NULL, \
                    '" + str(today) + "', \
                    '" + str(name) + "', \
                    '" + str(address) + "', \
                    '" + str(scan_engine_id) + "', \
                    '" + str(status) + "', \
                    '" + str(last_refreshed_date) + "', \
                    '" + str(last_updated_date) + "', \
                    '" + str(content_version) + "', \
                    '" + str(content_version_date) + "', \
                    '" + str(product_version) + "', \
                    '" + str(product_version_date) + "'\
                )"

            try:
                ret = db.doExec(sql)
                logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s.', table_scan_engines, today, name, address, scan_engine_id, status, last_refreshed_date, last_updated_date, content_version, content_version_date, product_version, product_version_date)
            except mysql.connector.Error as err:
                logging.error(err)
                
    # Close function api_scan_engines_update_status

# Check that sites have been recently scanned
def ivm_get_sites():

    # The full URL including the API endpoint
    url = '{0}/sites?size=100'.format(baseUrl)
    logging.debug('get sites url: %s', url)
    
    # Hit the API and save the result to a JSON object
    response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
    response_json = response.json()

	# Sites we dont care about start with... 
    blacklist = ['_TEST','Compliance', 'Rapid7 Insight Agents']

	# Process each site that we care about (skip those that start
	# with an item in the blacklist)
    for site in response_json['resources']:
        name = str(site['name'])
        logging.debug('name: %s', name)

        for i in blacklist:
            skip = "no"
            if name.startswith(i):
                skip = "yes"
                break
        if skip is "no":
	        
            # Last time the site was scanned
            last_scan_time = datetime.datetime.strftime(datetime.datetime.strptime(site['lastScanTime'], iso), mysqliso)
            logging.debug('last_scan_time: %s', last_scan_time)

            sql = "INSERT INTO " + str(table_site_scan) + " (\
                id, \
                date, \
                name, \
                last_scan_time\
            ) VALUES (\
                NULL, \
                '" + str(today) + "', \
                '" + str(name) + "', \
                '" + str(last_scan_time) + "' \
            )"

            try:
                ret = db.doExec(sql)
                logging.info('Successfully INSERTed into table "%s": %s, %s, %s.', table_site_scan, today, name, last_scan_time)
            except mysql.connector.Error as err:
                logging.error(err)
	            
    # Close function api_sites_scan_status

# Get all assets being scanned 
def ivm_get_assets():

    # Create an empty list to store IDs later
    asset_ids = []
    
    # Iterate through upto 10 pages and build the list of asset IDs
    i = 0
    while i < 10:
        
        # The full URL including the API endpoint
        url = '{0}/assets?page={1}&size=500'.format(baseUrl, i)
        
        # Hit the API and save the result to a JSON object
        response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
        response_json = response.json()

        for asset in response_json['resources']:
            
            if "id" in asset:
                id = int(asset['id'])
                asset_ids.append(id)
            else:
                break

        i += 1
    
    # Get asset information and write it to the database
    for i in asset_ids:
        
        # The URL for the asset
        url = '{0}/assets/{1}'.format(baseUrl, i)

        # Hit the API and save the result to a JSON object
        response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
        response_json = response.json()

        # I could compare two dictionaries, but I'm lazy and just wanna get this done...
        if "hostName" in response_json:
            hostname = str(response_json['hostName'])
        else:
            hostname = ''
        logging.debug('hostname: %s', hostname)

        if "ip" in response_json:
            ip = str(response_json['ip'])
        else:
            ip = ''
        logging.debug('ip: %s', ip)

        if "mac" in response_json:
            mac = str(response_json['mac'])
        else:
            mac = ''
        logging.debug('mac: %s', mac)
        
        if "riskScore" in response_json:
            risk_score = str(round((response_json['riskScore']), 2))
        else:
            risk_score = ''
        logging.debug('risk_score: %s', risk_score)

        try:
            for software in response_json['software']:
                if software['product'] == "Rapid7 Insight Agent":
                    agent_version = software['version']
                    break
                else:
                    agent_version = ''
        except KeyError:
            agent_version = ''
        logging.debug('Agent version: %s', agent_version)

        if "assessedForVulnerabilities" in response_json:
            assessed_for_vulnerabilities = str(response_json['assessedForVulnerabilities'])
        else:
            assessed_for_vulnerabilities = ''
        logging.debug('assessed_for_vulnerabilities: %s', assessed_for_vulnerabilities)

        if "assessedForPolicies" in response_json:
            assessed_for_policies = str(response_json['assessedForPolicies'])
        else:
            assessed_for_policies = ''
        logging.debug('assessed_for_policies: %s', assessed_for_policies)

        if "critical" in response_json['vulnerabilities']:
            critical_vulnerabilities = str(response_json['vulnerabilities']['critical'])
        else:
            critical_vulnerabilities = ''
        logging.debug('critical_vulnerabilities: %s', critical_vulnerabilities)

        if "severe" in response_json['vulnerabilities']:
            severe_vulnerabilities = str(response_json['vulnerabilities']['severe'])
        else:
            severe_vulnerabilities = ''
        logging.debug('severe_vulnerabilities: %s', severe_vulnerabilities)

        if "moderate" in response_json['vulnerabilities']:
            moderate_vulnerabilities = str(response_json['vulnerabilities']['moderate'])
        else:
            moderate_vulnerabilities = ''
        logging.debug('moderate_vulnerabilities: %s', moderate_vulnerabilities)

        if "exploits" in response_json['vulnerabilities']:
            exploits = str(response_json['vulnerabilities']['exploits'])
        else:
            exploits = ''
        logging.debug('exploits: %s', exploits)

        if "malwareKits" in response_json['vulnerabilities']:
            malware_kits = str(response_json['vulnerabilities']['malwareKits'])
        else:
            malware_kits = ''
        logging.debug('malware_kits: %s', malware_kits)

        if "total" in response_json['vulnerabilities']:
            total_vulnerabilities = str(response_json['vulnerabilities']['total'])
        else:
            total_vulnerabilities = ''
        logging.debug('total_vulnerabilities: %s', total_vulnerabilities)

        sql = "INSERT INTO " + str(table_asset) + " (\
                asset_id, \
                hostname, \
                ip, \
                mac, \
                risk_score, \
                agent_version, \
                assessed_for_vulnerabilities, \
                assessed_for_policies, \
                critical_vulnerabilities, \
                severe_vulnerabilities, \
                moderate_vulnerabilities, \
                exploits, \
                malware_kits, \
                total_vulnerabilities\
            ) VALUES (\
                '" + str(i) + "', \
                '" + str(hostname) + "', \
                '" + str(ip) + "', \
                '" + str(mac) + "', \
                '" + str(risk_score) + "', \
                '" + str(agent_version) + "', \
                '" + str(assessed_for_vulnerabilities) + "', \
                '" + str(assessed_for_policies) + "', \
                '" + str(critical_vulnerabilities) + "', \
                '" + str(severe_vulnerabilities) + "', \
                '" + str(moderate_vulnerabilities) + "',\
                '" + str(exploits) + "', \
                '" + str(malware_kits) + "', \
                '" + str(total_vulnerabilities) + "'\
            )"
            
        try:
            ret = db.doExec(sql)
            logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s.', table_asset, i, hostname, ip, mac, risk_score, agent_version, assessed_for_vulnerabilities, assessed_for_policies, critical_vulnerabilities, severe_vulnerabilities, moderate_vulnerabilities, exploits, malware_kits, total_vulnerabilities)
        except mysql.connector.Error as err:
            logging.error(err)
        
        # Get the asset tag IDs from the tags endpoint
        url = '{0}/assets/{1}/tags'.format(baseUrl, i)
        response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
        response_json = response.json()

        # Save the tag name as a variable
        for tag in response_json['resources']:
            tag_id = int(tag['id'])

            sql = "INSERT INTO " + str(table_asset_tag) + " (\
                asset_id, \
                tag_id \
            ) VALUES (\
                '" + str(i) + "', \
                '" + str(tag_id) + "' \
            )"

            try:
                ret = db.doExec(sql)
                logging.info('Successfully INSERTed into table "%s": %s, %s.', table_asset_tag, i, tag_id)
            except mysql.connector.Error as err:
                logging.error(err)

    # Close function api_assets

# Get asset tag data
def ivm_get_tags ():

    # Clear the current entries in the r7_asset_tag, r7_asset, and r7_tag table
    # Alternativly, find a way to keep them in sync so we don't have to keep DELETEing

    sql = "DELETE FROM " + str(table_asset_tag)

    try:
        ret = db.doExec(sql)
        logging.info('Cleared table "%s".', table_asset_tag)
    except mysql.connector.Error as err:
        logging.error(err)

    #cursor.execute(sql)


    sql = "DELETE FROM " + str(table_asset)

    try:
        ret = db.doExec(sql)
        logging.info('Cleared table "%s".', table_asset)
    except mysql.connector.Error as err:
        logging.error(err)

    #cursor.execute(sql)
    sql = "DELETE FROM " + str(table_tag)

    try:
        ret = db.doExec(sql)
        logging.info('Cleared table "%s".', table_tag)
    except mysql.connector.Error as err:
        logging.error(err)

    #cursor.execute(sql)

    # The full URL including the API endpoint
    url = '{0}/tags?size=500'.format(baseUrl)
    
    # Hit the API and save the result to a JSON object
    response = requests.get(url, auth=auth, headers=api_headers(), verify=False)
    response_json = response.json()
        
    for i in response_json['resources']:
        
        tag_id = int(i['id'])
        name = str(i['name'])
        source = str(i['source'])
        type = str(i['type'])

        if "riskModifier" in i:
            risk_modifier = float(i['riskModifier'])
        else:
            risk_modifier = 0

        sql = "INSERT INTO " + str(table_tag) + " (\
            tag_id, \
            tag_name, \
            source, \
            type, \
            risk_modifier \
        ) VALUES (\
            '" + str(tag_id) + "', \
            '" + str(name) + "', \
            '" + str(source) + "', \
            '" + str(type) + "', \
            '" + str(risk_modifier) + "' \
        )"

        try:
            ret = db.doExec(sql)
            logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s, %s.', table_tag, tag_id, name, source, type, risk_modifier)
        except mysql.connector.Error as err:
            logging.error(err)

    # Close function ivm_get_assets

# Perform counts and other math to get rollup (data over time) information for metrics
def ivm_metrics_rollup():
    
    # Agent version - this returns the most updated version number of all currently installed agents
    sql = "select agent_version \
        from " + str(table_asset) + " \
        where agent_version not like '' and agent_version not like 'config' \
        order by agent_version desc \
        limit 1"

    try:
        ret = db.doSel(sql)
        version = ret[0][0]
        logging.info('version: %s', version)
    except mysql.connector.Error as err:
        logging.error(err)

    # site_scan - returns a number 1-100 indicating the health of sites being scanned
    sql = "select round(a.num / a.den * 100, 0)\
        from (\
            select\
                (select count(*) from " + str(table_site_scan) + " where date = curdate() and last_scan_time > date_sub(curdate(), interval 7 day)) as num,\
                (select count(*) from " + str(table_site_scan) + " where date = curdate()) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        site_scan = ret[0][0]
        logging.info('site_scan: %s', site_scan)
    except mysql.connector.Error as err:
        logging.error(err)

    # scan_engine - returns a number 1-100 indicating the health of scan engines
    sql = "select round(a.num / a.den * 100, 0)\
        from (\
            select\
                (select count(*) from " + str(table_scan_engines) + " where date = curdate() and status = 'active') as num,\
                (select count(*) from " + str(table_scan_engines) + " where date = curdate()) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        scan_engine = ret[0][0]
        logging.info('scan_engine: %s', scan_engine)
    except mysql.connector.Error as err:
        logging.error(err)    

    # product_updates - returns a date indicating the last date we received product updates
    sql = "select product_version_date from " + str(table_scan_engines) + " where date = curdate()"

    try:
        ret = db.doSel(sql)
        product_updates = abs((today - ret[0][0]).days)
        logging.info('product_updates: %s', product_updates)
    except mysql.connector.Error as err:
        logging.error(err)

    # content_updates - returns a date indicating the last date we received product updates
    sql = "select content_version_date from " + str(table_scan_engines) + " where date = curdate()"

    try:
        ret = db.doSel(sql)
        content_updates = abs((today - ret[0][0]).days)
        logging.info('content_updates: %s', content_updates)
    except mysql.connector.Error as err:
        logging.error(err)

    # assets_scanned - returns a number 1-100 indicating the health status of all assets being scanned
    sql = "select 0 -- Need to change this when we get CMDB: select round(a.num / a.den * 100, 0)\
        from (\
            select\
                (select count(*) from " + str(table_asset) + ") as num,\
                (select count(*) from " + str(table_asset) + ") as den -- change this table to the CMDB total scanned assets\
        ) a"

    try:
        ret = db.doSel(sql)
        assets_scanned = ret[0][0]
        logging.info('assets_scanned: %s', assets_scanned)
    except mysql.connector.Error as err:
        logging.error(err)

    # agent_installs - returns a number 1-100 indicating the coverage of agents on workstations (servers dont get agents)
    sql = "select round(a.num / a.den * 100, 0)\
        from (\
            select\
                (select count(*) from " + str(table_asset) + " \
                    join " + str(table_asset_tag) + " on " + str(table_asset) + ".asset_id=" + str(table_asset_tag) + ".asset_id\
                    join " + str(table_tag) + " on " + str(table_asset_tag) + ".tag_id=" + str(table_tag) + ".tag_id\
                where tag_name = 'Desktop Support Team'\
                and agent_version not like '') as num,\
                (select count(*) from " + str(table_asset) + " \
                    join " + str(table_asset_tag) + " on " + str(table_asset) + ".asset_id=" + str(table_asset_tag) + ".asset_id\
                    join " + str(table_tag) + " on " + str(table_asset_tag) + ".tag_id=" + str(table_tag) + ".tag_id\
                where tag_name = 'Desktop Support Team'\
                order by hostname) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        agent_installs = ret[0][0]
        logging.info('agent_installs: %s', agent_installs)
    except mysql.connector.Error as err:
        logging.error(err)

    # agent_version - returns a number 1-100 indicating the health status of all assets being scanned
    sql = "select round(a.num / a.den * 100, 0)\
        from (\
            select\
                (select count(*) from " + str(table_asset) + " where agent_version = '" + str(version) + "') as num,\
                (select count(*) from " + str(table_asset) + " where agent_version not like '' and agent_version not like 'config' order by agent_version desc limit 1) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        agent_version = ret[0][0]
        logging.info('agent_version: %s', agent_version)
    except mysql.connector.Error as err:
        logging.error(err)

    # Insert all of the above data into the table
    sql = "INSERT INTO " + table_metrics_rollup + " (\
            id, \
            date, \
            site_scan, \
            scan_engine, \
            product_updates, \
            content_updates, \
            assets_scanned, \
            agent_installs, \
            agent_version\
        ) VALUES (\
            NULL,\
            curdate(),\
            '" + str(site_scan) + "', \
            '" + str(scan_engine) + "', \
            '" + str(product_updates) + "', \
            '" + str(content_updates) + "', \
            '" + str(assets_scanned) + "', \
            '" + str(agent_installs) + "', \
            '" + str(agent_version) + "'\
        )"

    try:
        ret = db.doExec(sql)
        logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s, %s, %s, %s', table_metrics_rollup, site_scan, scan_engine, product_updates,content_updates, assets_scanned, agent_installs, agent_version)
    except mysql.connector.Error as err:
        logging.error(err)

    # daily_total = a daily rollup weighted average of the day's metrics
    # WARNING!!!
    # If you attempt to format this query on multi-lines, it will break!!
    sql = "select round((site_scan*1 + scan_engine*1 + agent_installs*1 + agent_version*1 + (CASE WHEN product_updates <= 7 THEN 100 ELSE 100+7 - product_updates*1.5 END)*1 + (CASE WHEN content_updates <= 7 THEN 100 ELSE 100+7 - content_updates*1.5 END)*1)/6, 0) from " + table_metrics_rollup + " where date = curdate()"

    try:
        ret = db.doSel(sql)
        daily_total = ret[0][0]
        logging.info('daily_total: %s', daily_total)
    except mysql.connector.Error as err:
        logging.error(err)

    # Insert the daily rollup into the table
    sql = "UPDATE " + table_metrics_rollup + " SET daily_total = '" + str(daily_total) + "' WHERE date = curdate()"

    try:
        ret = db.doExec(sql)
        logging.info('Successfully INSERTed into table "%s": %s', table_metrics_rollup, daily_total)
    except mysql.connector.Error as err:
        logging.error(err)

    # Close function ivm_metrics_rollup

# Data retention - Delete data from tables older than X months
def data_retention():

    # Delete data older than X months
    limit = 6

    # Loop through the array of table names and cleanup data in each
    for i in cleanUp: 

        sql = "DELETE FROM " + str(i) + " WHERE date <= CURDATE() - INTERVAL '" + str(limit) + "' MONTH"

    try:
        ret = db.doExec(sql)
        logging.info('Purged data older than %s months from table "%s".', limit, i)
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
log_File = '/usr/local/scripts/log/ca_insightvm.log'
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.INFO, filemode='w')

# Define the URL that we will use throughout this script
# And pull in the credentials from the secrets.json file
if 'insightvm' in SECRETS:
    
    # Build the base URL that will be passed into the API calls
    baseUrl = 'https://{0}:{1}/api/3'.format(SECRETS['insightvm']['host'], SECRETS['insightvm']['port'])

    # Create requests AUTH object
    auth = requests.auth.HTTPBasicAuth(SECRETS['insightvm']['username'], SECRETS['insightvm']['password'])

db = dbConn(
    '{0}'.format(SECRETS['mysql_ca']['host']),
    '{0}'.format(SECRETS['mysql_ca']['user']),
    '{0}'.format(SECRETS['mysql_ca']['password']),
    '{0}'.format(SECRETS['mysql_ca']['database'])
)

# Define the MySQL tables 
table_scan_engines = "r7_scan_engines"
table_site_scan = "r7_site_scan"
table_asset = "r7_asset"
table_asset_tag = "r7_asset_tag"
table_tag = "r7_tag"
table_metrics_rollup = "r7_metrics_rollup"

# Some objects in our JSON will include data between the () characters.
# We need to define the charactors to "read between".
char1 = '('
char2 = ')'
	        
# Used to set the date in the date column of the MySQL tables
ymd = '%Y-%m-%d'

# Define the format of the date that Rapid7 presents via the API
iso = '%Y-%m-%dT%H:%M:%S.%fZ'

# We will take the date format from Rapid7's API and convert it to a
# format that we can then insert into MySQL
mysqliso = '%Y-%m-%d %H:%M:%S'

# Today's date e.g.: 2022-01-25
today = datetime.datetime.strptime(datetime.datetime.strftime(datetime.date.today(), ymd), ymd).date()

# These tables will be purged of data older than X months from the 
# data_retention function
cleanUp = [table_scan_engines, table_site_scan, table_metrics_rollup]

########################
# ACTION!
########################

ivm_get_scan_engines()
ivm_get_sites()
ivm_get_tags()
ivm_get_assets()
ivm_metrics_rollup()

# Run this last
data_retention()
