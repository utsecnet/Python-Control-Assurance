#!/usr/bin/python3

# Standard Python libraries
from calendar import weekheader
import ssl
import datetime
import logging
import json
import urllib.request
import urllib.parse

# Third party Python libraries
import requests
import mysql.connector

# Custom libraries
from modules.secrets import SECRETS
from modules.dbConn import *

########################
# FUNCTIONS
########################

# python date objects only support upto 6 charactors in the %f position
# Defender sometimes has 7, so we gotta remove the last charactor before the 'Z'
def fix_datetime(firstSeen):

    try:
        new_datetime = datetime.datetime.strftime(datetime.datetime.strptime(firstSeen, iso), mysqliso)
    except ValueError as err:

        # Remove the 26th charactor
        
        n = 26
        first_part = firstSeen[0:n]
        second_part = firstSeen[n+1:]
        newFirstSeen = first_part+second_part

        new_datetime = datetime.datetime.strftime(datetime.datetime.strptime(newFirstSeen, iso), mysqliso)

    return new_datetime

    # Close function fix_datetime

# Get a list of all assets in Defnder
#####################################
def defender_get_machines():
    
    # Connect to the Defender API and get machines
    endpoint = "machines"
    url = 'https://api.securitycenter.microsoft.com/api/' + endpoint

    headers = { 
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + aadToken
    }

    response = requests.get(url, headers=headers)
    results = response.json()

    return results

    # Close function defender_get_machines

def defender_insert_asset(results):

    # Clear the current entries in the defender_asset, defender_tag tables
    # Alternativly, find a way to keep them in sync so we don't have to keep DELETEing
    sql = "truncate table " + str(table_asset)

    try:
        ret = db.doExec(sql)
        logging.info('Truncated table "%s".', table_asset)
    except mysql.connector.Error as err:
        logging.error(err)

    for i in results['value']:

        asset_id = i['id']
        logging.debug('asset_id: %s', asset_id)

        computerDnsName = i['computerDnsName']
        logging.debug('computerDnsName: %s', computerDnsName)

        firstSeen = fix_datetime(i['firstSeen'])
        logging.debug('firstSeen: %s', firstSeen)


        lastSeen = fix_datetime(i['lastSeen'])
        logging.debug('lastSeen: %s', lastSeen)

        # Set the Operating System
        osPlatform = i['osPlatform']
        logging.debug('osPlatform: %s', osPlatform)

        # Set the OS version
        osVersion = i['osVersion']
        logging.debug('osVersion: %s', osVersion)

        # Set the OS version
        osProcessor = i['osProcessor']
        logging.debug('osProcessor: %s', osProcessor)

        # Set the OS version
        version = i['version']
        logging.debug('version: %s', version)

        # Set the IP Address
        lastIpAddress = i['lastIpAddress']
        logging.debug('lastIpAddress: %s', lastIpAddress)

        # Set the IP Address
        lastExternalIpAddress = i['lastExternalIpAddress']
        logging.debug('lastExternalIpAddress: %s', lastExternalIpAddress)

        # Set the IP Address
        agentVersion = i['agentVersion']
        logging.debug('agentVersion: %s', agentVersion)

        # Set the IP Address
        osBuild = i['osBuild']
        logging.debug('osBuild: %s', osBuild)

        # Set the health status
        healthStatus = i['healthStatus']
        logging.debug('healthStatus: %s', healthStatus)

        # Set the risk score
        deviceValue = i['deviceValue']
        logging.debug('deviceValue: %s', deviceValue)

        # Set the RBAC group ID
        try:
            rbacGroupId = i['rbacGroupId']
        except KeyError:
            rbacGroupId = ''
        logging.debug('rbacGroupId: %s', rbacGroupId)

        # Set the RBAC group name
        rbacGroupName = i['rbacGroupName']
        logging.debug('rbacGroupName: %s', rbacGroupName)

       # Set the RBAC group name
        riskScore = i['riskScore']
        logging.debug('riskScore: %s', riskScore)

        # Set the risk score
        exposureLevel = i['exposureLevel']
        logging.debug('exposureLevel: %s', exposureLevel)

        # Set the risk score
        isAadJoined = i['isAadJoined']
        logging.debug('isAadJoined: %s', isAadJoined)

        # Set the risk score
        aadDeviceId = i['aadDeviceId']
        logging.debug('aadDeviceId: %s', aadDeviceId)

        # Set the risk score
        defenderAvStatus = i['defenderAvStatus']
        logging.debug('defenderAvStatus: %s', defenderAvStatus)

        # Set the risk score
        onboardingStatus = i['onboardingStatus']
        logging.debug('onboardingStatus: %s', onboardingStatus)

        # Set the risk score
        osArchitecture = i['osArchitecture']
        logging.debug('osArchitecture: %s', osArchitecture)

        # Set the risk score
        managedBy = i['managedBy']
        logging.debug('managedBy: %s', managedBy)

        # Set the risk score
        managedByStatus = i['managedByStatus']
        logging.debug('managedByStatus: %s', managedByStatus)

        sql = "INSERT INTO " + str(table_asset) + " (\
            id, \
            asset_id, \
            computerDnsName, \
            firstSeen, \
            lastSeen, \
            osPlatform, \
            osVersion, \
            osProcessor, \
            version, \
            lastIpAddress, \
            lastExternalIpAddress, \
            agentVersion, \
            osBuild, \
            healthStatus, \
            deviceValue, \
            rbacGroupId, \
            rbacGroupName, \
            riskScore, \
            exposureLevel, \
            isAadJoined, \
            aadDeviceId, \
            defenderAvStatus, \
            onboardingStatus, \
            osArchitecture, \
            managedBy, \
            managedByStatus\
        ) VALUES (\
            NULL,\
            '" + str(asset_id) + "', \
            '" + str(computerDnsName) + "', \
            '" + str(firstSeen) + "', \
            '" + str(lastSeen) + "', \
            '" + str(osPlatform) + "', \
            '" + str(osVersion) + "', \
            '" + str(osProcessor) + "', \
            '" + str(version) + "', \
            '" + str(lastIpAddress) + "', \
            '" + str(lastExternalIpAddress) + "', \
            '" + str(agentVersion) + "', \
            '" + str(osBuild) + "', \
            '" + str(healthStatus) + "', \
            '" + str(deviceValue) + "', \
            '" + str(rbacGroupId) + "', \
            '" + str(rbacGroupName) + "', \
            '" + str(riskScore) + "', \
            '" + str(exposureLevel) + "', \
            '" + str(isAadJoined) + "', \
            '" + str(aadDeviceId) + "', \
            '" + str(defenderAvStatus) + "', \
            '" + str(onboardingStatus) + "', \
            '" + str(osArchitecture) + "', \
            '" + str(managedBy) + "', \
            '" + str(managedByStatus) + "'\
        )"

        try:
            ret = db.doExec(sql)
            logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s', table_asset, asset_id, computerDnsName, firstSeen, lastSeen, osPlatform, osVersion, osProcessor, version, lastIpAddress, lastExternalIpAddress, agentVersion, osBuild, healthStatus, deviceValue, rbacGroupName, riskScore, exposureLevel, isAadJoined, aadDeviceId, defenderAvStatus, onboardingStatus, osArchitecture, managedBy, managedByStatus)
        except mysql.connector.Error as err:
            logging.error(err)

    # Close function defender_insert_machines

def defender_insert_tag(results):

    # Create an empty set for which we will store our tags
    # Use a set as we want each item in the set to be unique, which is not true of a list
    tags = []

    # Clear the defender_tag table - may not need to
    sql = "truncate table " + str(table_tag)

    try:
        ret = db.doExec(sql)
        logging.info('Truncated table "%s".', table_tag)
    except mysql.connector.Error as err:
        logging.error(err)

    for i in results['value']:

        # Set the machine tags
        for tag in i['machineTags']:
            tag_name = tag
            logging.info('tag: %s', tag)
            
            tags.append(tag_name)

    tags = list(dict.fromkeys(tags))
    logging.info('tags: %s', tags)

    # Add tags to the defender_tag table
    for tag in tags:

        sql = "INSERT INTO " + str(table_tag) + " (\
            tag_id, \
            tag_name \
        ) VALUES (\
            NULL, \
            '" + str(tag) + "' \
        )"

        try:
            ret = db.doExec(sql)
            logging.info('Successfully INSERTed into table "%s": %s.', table_tag, tag)
        except mysql.connector.Error as err:
            logging.error(err)

    # Close function defender_insert_tag
        
def defender_insert_asset_tag(results):

    # Clear the defender_asset_tag table - may not need to
    sql = "truncate table " + str(table_asset_tag)

    try:
        ret = db.doExec(sql)
        logging.info('Truncated table "%s".', table_asset_tag)
    except mysql.connector.Error as err:
        logging.error(err)

    for i in results['value']:

        # Set the asset_id and tags
        hash = i['id']
        computerDnsName = i['computerDnsName']
        machineTags = i['machineTags']
        
        # If the asset has a tag value...
        try:
            machineTags = i['machineTags'][0]
            logging.info('Asset %s has tags: %s', hash, i['machineTags'])

            # ...process each tag in the list
            for tag in i['machineTags']:

                # Lookup the tag_id from the defender_tag table
                sql = "select tag_id from " + str(table_tag) + " where tag_name = '" + str(tag) + "'"
                logging.debug("sql: %s", sql)

                try:
                    ret = db.doSel(sql)
                    tag_id = ret[0][0]
                    logging.debug('tag_id: %s', tag_id)
                except mysql.connector.Error as err:
                    logging.error(err)

                # Lookup the id from the defender_asset table
                sql = "select id from " + str(table_asset) + " where asset_id = '" + str(hash) + "'"
                logging.debug("sql: %s", sql)

                try:
                    ret = db.doSel(sql)
                    asset_id = ret[0][0]
                    logging.debug('tag_id: %s', asset_id)
                except mysql.connector.Error as err:
                    logging.error(err)

                # Add a row to the defender_asset_tag table
                sql = "INSERT INTO " + str(table_asset_tag) + " (\
                    asset_id, \
                    tag_id \
                ) VALUES (\
                    " + str(asset_id) + ", \
                    " + str(tag_id) + " \
                )"

                try:
                    ret = db.doExec(sql)
                    logging.info('Successfully INSERTed into table "%s": %s, %s.', table_asset_tag, asset_id, tag_id)
                except mysql.connector.Error as err:
                    logging.error(err)

        except IndexError:
            logging.debug('Asset %s does not have any tags.', computerDnsName)

    # Close function defender_insert_asset_tag

# Calcuate data and insert into the rollup table
def defender_metrics_rollup():

    # total agents - used for calculating a later query
    sql = "select count(*) from " + str(table_asset)

    try:
        ret = db.doSel(sql)
        total_agents = ret[0][0]
        logging.info('total_agents: %s', total_agents)
    except mysql.connector.Error as err:
        logging.error(err)

    # health status - returns a number 1-100 indicating a ratio of all active devices over total devices
    sql = "select round(a.num/a.den*100, 0) as health_status\
        from (\
            select\
                (select count(*) from " + str(table_asset) + " where healthStatus = 'Active') as num,\
                (select count(*) from " + str(table_asset) + ") as den\
        ) a"

    try:
        ret = db.doSel(sql)
        health_status = ret[0][0]
        logging.info('health_status: %s', health_status)
    except mysql.connector.Error as err:
        logging.error(err)

    # onboarded - returns a number 1-100 indicating the ratio of all onboarded devices over total onboardable devices
    sql = "select round(a.num/a.den*100, 0) as onboarded\
        from (\
            select\
                (select count(*) from " + str(table_asset) + " where onboardingStatus = 'Onboarded') as num,\
                (select count(*) from " + str(table_asset) + " where find_in_set(onboardingStatus, 'Onboarded,CanBeOnboarded')) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        onboarded = ret[0][0]
        logging.info('onboarded: %s', onboarded)
    except mysql.connector.Error as err:
        logging.error(err)

    # av status - returns a number 1-100 indicating the status of the Defender AV status of all assets
    sql = "select round(a.num/a.den*100, 0) as av_status\
        from (\
            select\
                (select count(*) from " + str(table_asset) + " where defenderAvStatus = 'Updated') as num,\
                (select count(*) from " + str(table_asset) + " where find_in_set(defenderAvStatus, 'Updated,Unknown,Disabled,NotUpdated')) as den\
        ) a"

    try:
        ret = db.doSel(sql)
        av_status = ret[0][0]
        logging.info('av_status: %s', av_status)
    except mysql.connector.Error as err:
        logging.error(err)

    # duplicates - counts up all assets that have duplicates based on the computerDnsName
    sql = "select sum(a.count) as duplicates\
        from (\
            select count(computerDnsName) as count\
            from " + str(table_asset) + "\
            where computerDnsName <> 'None'\
            group by computerDnsName\
            having count(computerDnsName) > 1\
        ) a"

    try:
        ret = db.doSel(sql)
        duplicates = ret[0][0]
        logging.info('duplicates: %s', duplicates)
    except mysql.connector.Error as err:
        logging.error(err)

    # TODO
    # version - returns a number 1-100 indicating the ratio of agents with current updates over all agents

    # TODO
    # engine_version - returns a number 1-100 indicating the ratio of agents with current engine updates over all agents

    # TODO
    # signature_last_updated - returns a number 1-100 indicating the ratio of agents that have updated the av signatures within an expected timeframe

    # TODO
    # last_scan - returns a number 1-100 indicating the ratio of agents that have been scanned within an expected timeframe

    # Insert all of the above data into the table
    # TODO - insert the above TODOs into the below sql
    sql = "INSERT INTO " + str(table_metrics_rollup) + " (\
            id, \
            date, \
            health_status, \
            onboarded, \
            av_status, \
            duplicates \
        ) VALUES (\
            NULL,\
            curdate(),\
            '" + str(health_status) + "', \
            '" + str(onboarded) + "', \
            '" + str(av_status) + "', \
            '" + str(duplicates) + "'\
        )"

    try:
        ret = db.doExec(sql)
        logging.info('Successfully INSERTed into table "%s": %s, %s, %s, %s', table_metrics_rollup, health_status, onboarded, av_status, duplicates)
    except mysql.connector.Error as err:
        logging.error(err)

    # daily_total = a daily rollup weighted average of the day's metrics
    sql = "select round(\
            (health_status*.9 +\
            onboarded*2.5 +\
            av_status*1.5 +\
            (" + str(total_agents) + " - duplicates)/" + str(total_agents) + " * 100 * .1\
        )/4, 0)\
        from " + str(table_metrics_rollup) + "\
        where date = curdate()"

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

    # Close function defender_metrics_rollup

    



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
log_File = '/usr/local/scripts/log/ca_defender.log'
logging.basicConfig(format='%(asctime)s %(levelname)s %(lineno)d %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.INFO, filemode='w')

# Windows Defender API Token
tenant_id = '{0}'.format(SECRETS['defender']['tenant_id'])
app_id = '{0}'.format(SECRETS['defender']['app_id'])
app_secret = '{0}'.format(SECRETS['defender']['app_secret'])
url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenant_id)
resource_app_id_uri = 'https://api.securitycenter.microsoft.com'

body = {
    'resource' : resource_app_id_uri,
    'client_id' : app_id,
    'client_secret' : app_secret,
    'grant_type' : 'client_credentials'
}

data = urllib.parse.urlencode(body).encode("utf-8")
req = urllib.request.Request(url, data)
response = urllib.request.urlopen(req)
jsonResponse = json.loads(response.read())
aadToken = jsonResponse["access_token"]

# MySQL connection info
db = dbConn(
    '{0}'.format(SECRETS['mysql_ca']['host']),
    '{0}'.format(SECRETS['mysql_ca']['user']),
    '{0}'.format(SECRETS['mysql_ca']['password']),
    '{0}'.format(SECRETS['mysql_ca']['database'])
)

# Define the MySQL tables 
table_asset = "defender_asset"
table_asset_tag = "defender_asset_tag"
table_tag = "defender_tag"
table_metrics_rollup = "defender_metrics_rollup"

# Define the format of the date that Defender presents via the API
iso = '%Y-%m-%dT%H:%M:%S.%fZ'

# We will take the date format from Defender's API and convert it to a
# format that we can then insert into MySQL
mysqliso = '%Y-%m-%d %H:%M:%S'

assets = defender_get_machines()
defender_insert_asset(assets)
defender_insert_tag(assets)
defender_insert_asset_tag(assets)
defender_metrics_rollup()