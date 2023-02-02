#!/usr/bin/python3
# -*- coding: utf-8 -*-

''' Pull control assurance measures from JamfPro into MySQl DB

We access several Jamf Pro API endpoints including:
* computers-inventory
* device-enrollments
* mobile-devices

After identifying which control assurance measures to pull from the API, we
ingest those into a MySQL database. The process follows these general steps:
1. Get asset details related to control assurance into an "asset" table.
2. Count up cetain measures and add to a "rollup" table
3. Calculate a daily_total value

The data may then be accessed and displayed using a dashboard frontend of
choice.

API Documentation
* https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory
* https://usu.jamfcloud.com/api/doc/#/

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
import mysql.connector

# Custom libraries
from modules.secrets import SECRETS
from modules.dbConn import *

########################
# FUNCTIONS
########################

def jamf_get_computers():

    logging.debug("entered function: jamf_get_computers")

    # Clears table before getting an updated dataset. 
    sql = "TRUNCATE TABLE " + str(table_asset) + ";"

    try:
        ret = db.doTrunc(sql)
        logging.info('Truncated table: "%s".', table_asset)
    except mysql.connector.Error as err:
        logging.error(err)

    # Process through each page of computers (pagination)
    total_consumed = 0
    current_page = 0
    page_size = 100
    stop_paging = False

    # Update the headers to include the token
    headers_update = {'Authorization': token_string}
    headers.update(headers_update)

    while not stop_paging:

        # Build the endpoint URL
        url = '{0}/api/v1/computers-inventory?page-size={1}&page={2}&section=GENERAL&section=HARDWARE&section=SECURITY&section=OPERATING_SYSTEM&section=USER_AND_LOCATION'.format(baseUrl,page_size,current_page)
        logging.debug('url: %s', url)

        # Get the response
        response = requests.get(url, headers=headers)
        results = response.json()

        # Count up the computer objects in the results
        total_computers = results["totalCount"]

        clients_raw = results['results']
        
        for computer in clients_raw:

            # asset_id
            try:
                asset_id = str(computer['id']) 
            except KeyError:
                asset_id = "" 

            # UDID
            try:
                udid = str(computer['udid']) 
            except KeyError:
                udid = ""

            #################
            # General Section
            #################

            # Host name
            try:
                name = str(computer['general']['name']) 
            except KeyError:
                name = ""

            # Last IP Address
            try:
                lastIpAddress = str(computer['general']['lastIpAddress']) 
            except KeyError:
                lastIpAddress = ""

             # Last Reported IP Address
            try:
                lastReportedIp = str(computer['general']['lastReportedIp']) 
            except KeyError:
                lastReportedIp = ""

            # jamf agent version
            try:
                jamfBinaryVersion = str(computer['general']['jamfBinaryVersion']) 
            except KeyError:
                jamfBinaryVersion = ""

            # type (OS) - The API propertie is "platform" but to keep things
            # consistant with the MDM table, we rename to "type"
            try:
                type = str(computer['general']['type']) 
            except KeyError:
                type = ""

            # assetTag
            try:
                assetTag = str(computer['general']['assetTag']) 
            except KeyError:
                assetTag = ""

            # If the device is remote managed or not - True/False
            try:
                managed = str(computer['general']['remoteManagement']['managed']) 
            except KeyError:
                managed = ""

            # If the device is supervised or not - True/False
            # Supervised means it went through the device enrollment program rather than web enrolment.
            try:
                supervised = str(computer['general']['supervised']) 
            except KeyError:
                supervised = ""

            # If the device is MDM capable or not - True/False
            try:
                mdmCapable = str(computer['general']['mdmCapable']['capable']) 
            except KeyError:
                mdmCapable = ""

            # reportDate - Last time the inventory was updated (default daily)
            try:
                reportDate = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['reportDate'], iso), mysqliso)
            except (KeyError):
                reportDate = ""
            except (ValueError):
                reportDate = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['reportDate'], iso2), mysqliso)

            # Last time agent checked in
            try:
                lastContactTime = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['lastContactTime'], iso), mysqliso)
            except (KeyError, TypeError):
                lastContactTime = ""
            except (ValueError):
                lastContactTime = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['lastContactTime'], iso2), mysqliso)

            # MDM profile expiration
            try:
                mdmProfileExpiration = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['mdmProfileExpiration'], iso), mysqliso)
            except (KeyError):
                mdmProfileExpiration = ""
            except (ValueError):
                mdmProfileExpiration = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['mdmProfileExpiration'], iso2), mysqliso)

            # site
            try:
                site = str(computer['general']['site']['name']) 
            except (KeyError):
                site = ""

            # User approved MDM
            try:
                userApprovedMdm = str(computer['general']['userApprovedMdm']) 
            except (KeyError):
                userApprovedMdm = ""

            ##################
            # Hardware Section
            ##################

            # Serial Number
            try:
                serialNumber = str(computer['hardware']['serialNumber']) 
            except KeyError:
                serialNumber = ""

            # Model
            try:
                model = str(computer['hardware']['model']) 
            except KeyError:
                model = ""

            ##################
            # Security Section
            ##################

            # sipStatus
            try:
                sipStatus = str(computer['security']['sipStatus']) 
            except KeyError:
                sipStatus = ""
            
            # Gatekeeper Status
            try:
                gatekeeperStatus = str(computer['security']['gatekeeperStatus']) 
            except KeyError:
                gatekeeperStatus = ""

            # xProtect Version
            try:
                xprotectVersion = str(computer['security']['xprotectVersion']) 
            except KeyError:
                xprotectVersion = ""

            # Auto login Disabled
            try:
                autoLoginDisabled = str(computer['security']['autoLoginDisabled']) 
            except KeyError:
                autoLoginDisabled = ""

            # Remote Desktop Enabled
            try:
                remoteDesktopEnabled = str(computer['security']['remoteDesktopEnabled']) 
            except KeyError:
                remoteDesktopEnabled = ""

            # Activation Lock Enabled
            try:
                activationLockEnabled = str(computer['security']['activationLockEnabled']) 
            except KeyError:
                activationLockEnabled = ""

            # Recovery Lock Enabled
            try:
                recoveryLockEnabled = str(computer['security']['recoveryLockEnabled']) 
            except KeyError:
                recoveryLockEnabled = ""

            # Firewall Enabled
            try:
                firewallEnabled = str(computer['security']['firewallEnabled']) 
            except KeyError:
                firewallEnabled = ""

            # Secure Boot Level
            try:
                secureBootLevel = str(computer['security']['secureBootLevel']) 
            except KeyError:
                secureBootLevel = ""

            # External BootLevel
            try:
                externalBootLevel = str(computer['security']['externalBootLevel']) 
            except KeyError:
                externalBootLevel = ""

            # Bootstrap Token Allowed
            try:
                bootstrapTokenAllowed = str(computer['security']['bootstrapTokenAllowed']) 
            except KeyError:
                bootstrapTokenAllowed = ""

            ##################
            # Operating System
            ##################

            # Bootstrap Token Allowed
            try:
                fileVault2Status = str(computer['operatingSystem']['fileVault2Status']) 
            except KeyError:
                fileVault2Status = ""

            ###################
            # User and Location
            ###################

            # Real Name
            try:
                realname = str(computer['userAndLocation']['realname']) 
            except KeyError:
                realname = ""

            logging.debug('Will attempt to insert computer: %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s', asset_id, udid, name, lastIpAddress, lastReportedIp, jamfBinaryVersion, type, assetTag, managed, supervised, mdmCapable, reportDate, lastContactTime, mdmProfileExpiration, userApprovedMdm, serialNumber, model, sipStatus, gatekeeperStatus, xprotectVersion, autoLoginDisabled, remoteDesktopEnabled, activationLockEnabled, recoveryLockEnabled, firewallEnabled, secureBootLevel, externalBootLevel, bootstrapTokenAllowed, fileVault2Status, realname)

            sql = ("INSERT INTO jamfpro_asset "
                  "(id, asset_id, udid, name, lastIpAddress, lastReportedIp, jamfBinaryVersion, type, assetTag, managed, supervised, mdmCapable, reportDate, lastContactTime, mdmProfileExpiration, site, userApprovedMdm, serialNumber, model, sipStatus, gatekeeperStatus, xprotectVersion, autoLoginDisabled, remoteDesktopEnabled, activationLockEnabled, recoveryLockEnabled, firewallEnabled, secureBootLevel, externalBootLevel, bootstrapTokenAllowed, fileVault2Status, realname) " 
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

            data = (rowId, asset_id, udid, name, lastIpAddress, lastReportedIp, jamfBinaryVersion, type, assetTag, managed, supervised, mdmCapable, reportDate, lastContactTime, mdmProfileExpiration, site, userApprovedMdm, serialNumber, model, sipStatus, gatekeeperStatus, xprotectVersion, autoLoginDisabled, remoteDesktopEnabled, activationLockEnabled, recoveryLockEnabled, firewallEnabled, secureBootLevel, externalBootLevel, bootstrapTokenAllowed, fileVault2Status, realname)

            try:
                ret = db.doExec(sql,data)
                logging.info('Successfully INSERTed into table "%s": %s.', table_asset, name)

            except mysql.connector.Error as err:
                logging.error(err)

        # Increase the page value and stop processing when on the last page
        current_page += 1
        logging.debug('current_page: %s', current_page)
        
        total_consumed += len(clients_raw)
        logging.info('total_consumed (total computers pulled from Jamf into the DB): %s', total_consumed)

        stop_paging = (total_computers == total_consumed)
        logging.debug('stop_paging: %s', stop_paging)

        # Close function jamf_get_computers

def jamf_get_mobile_devices():

    logging.debug("entered function: jamf_get_mobile_devices")

    # Clears table before getting an updated dataset. 
    sql = "TRUNCATE TABLE " + str(table_mdm) + ";"

    try:
        ret = db.doTrunc(sql)
        logging.info('Truncated table: "%s".', table_mdm)
    except mysql.connector.Error as err:
        logging.error(err)

    # Process through each page of computers (pagination)
    total_consumed = 0
    current_page = 0
    page_size = 100
    stop_paging = False

    # Update the headers to include the token
    headers_update = {'Authorization': token_string}
    headers.update(headers_update)

    while not stop_paging:

        # Build the endpoint URL
        url = '{0}/api/v2/mobile-devices?page-size={1}&page={2}'.format(baseUrl, page_size, current_page)
        logging.debug('url: %s', url)

        # Get the response
        response = requests.get(url, headers=headers)
        results = response.json()

        # Count up the computer objects in the results
        total_mdm = results["totalCount"]

        mdm_raw = results['results']

        # We don't get enough information from the mobile-devices endpoint. We get more info when we query for a specific ID.
        # So we loop through each device and then query a different endpoint for complete details.
        for device in mdm_raw:

            dev_id = device['id']
            
            # The endpoint that has complete device information
            url = url = '{0}/api/v2/mobile-devices/{1}/detail'.format(baseUrl,dev_id)
            logging.debug('url: %s', url)

            # Get the response
            response = requests.get(url, headers=headers)
            results = response.json()

            # Log the full device record
            logging.debug('Full device record for %s: %s', dev_id, results)

            # name
            try:
                name = str(results['name']) 
            except KeyError:
                name = ""

            # enforceName
            try:
                enforceName = str(results['enforceName']) 
            except KeyError:
                enforceName = ""
                
            # assetTag
            try:
                assetTag = str(results['assetTag']) 
            except KeyError:
                assetTag = ""

            # lastInventoryUpdateTimestamp
            try:
                lastInventoryUpdateTimestamp = datetime.datetime.strftime(datetime.datetime.strptime(results['lastInventoryUpdateTimestamp'], iso), mysqliso)
            except (KeyError):
                lastInventoryUpdateTimestamp = "1970-01-01 00:00:00"
            except (ValueError):
                lastInventoryUpdateTimestamp = datetime.datetime.strftime(datetime.datetime.strptime(results['lastInventoryUpdateTimestamp'], iso2), mysqliso)

            # serialNumber
            try:
                serialNumber = str(results['serialNumber']) 
            except KeyError:
                serialNumber = ""

            # udid
            try:
                udid = str(results['udid']) 
            except KeyError:
                udid = ""

            # ipAddress
            try:
                ipAddress = str(results['ipAddress']) 
            except KeyError:
                ipAddress = ""

            # managed
            try:
                managed = str(results['managed']) 
            except KeyError:
                managed = ""
            
            # timeZone
            try:
                timeZone = str(results['timeZone']) 
            except KeyError:
                timeZone = ""

            # mdmProfileExpirationTimestamp
            try:
                mdmProfileExpirationTimestamp = datetime.datetime.strftime(datetime.datetime.strptime(results['mdmProfileExpirationTimestamp'], iso), mysqliso)
            except (KeyError):
                mdmProfileExpirationTimestamp = "1970-01-01 00:00:00"
            except (ValueError):
                mdmProfileExpirationTimestamp = datetime.datetime.strftime(datetime.datetime.strptime(results['mdmProfileExpirationTimestamp'], iso2), mysqliso)

            # deviceOwnershipLevel
            try:
                deviceOwnershipLevel = str(results['deviceOwnershipLevel']) 
            except KeyError:
                deviceOwnershipLevel = ""

            # enrollmentMethod
            try:
                enrollmentMethod = str(results['enrollmentMethod']) 
            except KeyError:
                enrollmentMethod = ""

             # site
            try:
                site = str(results['site']['name']) 
            except (KeyError):
                site = ""

            # type
            try:
                type = str(results['type']) 
            except KeyError:
                type = ""

            #######################
            # location 
            #######################

            # realName
            try:
                realName = str(results['location']['realName']) 
            except KeyError:
                realName = ""

            #######################
            # ios 
            #######################

            # supervised
            try:
                supervised = str(results['ios']['supervised']) 
            except KeyError:
                supervised = ""

            # model
            try:
                model = str(results['ios']['model']) 
            except KeyError:
                model = ""

            #######################
            # ios > security
            #######################

            # dataProtected
            try:
                dataProtected = str(results['ios']['security']['dataProtected']) 
            except KeyError:
                dataProtected = ""

            # blockLevelEncryptionCapable
            try:
                blockLevelEncryptionCapable = str(results['ios']['security']['blockLevelEncryptionCapable']) 
            except KeyError:
                blockLevelEncryptionCapable = ""

            # fileLevelEncryptionCapable
            try:
                fileLevelEncryptionCapable = str(results['ios']['security']['fileLevelEncryptionCapable']) 
            except KeyError:
                fileLevelEncryptionCapable = ""

            # passcodePresent
            try:
                passcodePresent = str(results['ios']['security']['passcodePresent']) 
            except KeyError:
                passcodePresent = ""

            # passcodeCompliant
            try:
                passcodeCompliant = str(results['ios']['security']['passcodeCompliant']) 
            except KeyError:
                passcodeCompliant = ""

            # passcodeCompliantWithProfile
            try:
                passcodeCompliantWithProfile = str(results['ios']['security']['passcodeCompliantWithProfile']) 
            except KeyError:
                passcodeCompliantWithProfile = ""

            # hardwareEncryption
            try:
                hardwareEncryption = str(results['ios']['security']['hardwareEncryption']) 
            except KeyError:
                hardwareEncryption = ""

            # activationLockEnabled
            try:
                activationLockEnabled = str(results['ios']['security']['activationLockEnabled']) 
            except KeyError:
                activationLockEnabled = ""

            # jailBreakDetected
            try:
                jailBreakDetected = str(results['ios']['security']['jailBreakDetected']) 
            except KeyError:
                jailBreakDetected = ""

            # dataProtected
            try:
                dataProtected = str(results['ios']['security']['dataProtected']) 
            except KeyError:
                dataProtected = ""
            
            logging.debug('Will attempt to insert mobile device: %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s', name, enforceName, assetTag, lastInventoryUpdateTimestamp, serialNumber, udid, ipAddress, managed, timeZone, mdmProfileExpirationTimestamp, deviceOwnershipLevel, enrollmentMethod, type, realName, supervised, model, dataProtected, blockLevelEncryptionCapable, fileLevelEncryptionCapable, passcodePresent, passcodeCompliant, passcodeCompliantWithProfile, hardwareEncryption, activationLockEnabled, jailBreakDetected)

            sql = ("INSERT INTO jamfpro_mdm "
                    "(id, name, enforceName, assetTag, lastInventoryUpdateTimestamp, serialNumber, udid, ipAddress, managed, timeZone, mdmProfileExpirationTimestamp, deviceOwnershipLevel, enrollmentMethod, site, type, realName, supervised, model, dataProtected, blockLevelEncryptionCapable, fileLevelEncryptionCapable, passcodePresent, passcodeCompliant, passcodeCompliantWithProfile, hardwareEncryption, activationLockEnabled, jailBreakDetected) " 
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

            data = (rowId, name, enforceName, assetTag, lastInventoryUpdateTimestamp, serialNumber, udid, ipAddress, managed, timeZone, mdmProfileExpirationTimestamp, deviceOwnershipLevel, enrollmentMethod, site, type, realName, supervised, model, dataProtected, blockLevelEncryptionCapable, fileLevelEncryptionCapable, passcodePresent, passcodeCompliant, passcodeCompliantWithProfile, hardwareEncryption, activationLockEnabled, jailBreakDetected)

            try:
                ret = db.doExec(sql,data)
                logging.info('Successfully INSERTed into table "%s": %s.', table_mdm, name)

            except mysql.connector.Error as err:
                logging.error(err)

        # Increase the page value and stop processing when on the last page
        current_page += 1
        logging.debug('current_page: %s', current_page)
        
        total_consumed += len(mdm_raw)
        logging.info('total_consumed (total mobile devices pulled from Jamf into the DB): %s', total_consumed)

        stop_paging = (total_mdm == total_consumed)
        logging.debug('stop_paging: %s', stop_paging)

    # Close function jamf_get_mobile_devices

# Count the total number of computer and mobile devices that SHOULD be managed in Jamf
# These numbers will be the denominator in the metric "totalAssets" and "totalMdm"
def count_school_managed():

    logging.debug('Entered Fuction: jamf_rollup')

    # Build the endpoint URL
    url = '{0}/api/v1/device-enrollments/1/devices'.format(baseUrl)
    logging.debug('url: %s', url)

    # Update the headers to include the token
    headers_update = {'Authorization': token_string}
    headers.update(headers_update)

    # Get the response
    response = requests.get(url, headers=headers)
    results = response.json()
    #logging.debug('results: %s', results)

    # Count up the computer objects in the results
    totalCount = results["totalCount"]
    logging.debug('totalCount: %s', totalCount)
    logging.info('Total number of devices in Apple School Manager: %s', totalCount)

    # Computers
    comp = ['mac']
    global expectedComputers
    expectedComputers = 0

    # Mobile - this list is not used, but contains what I have found to be the shortest list of strings that could identify a mobile device if you wanted
    mobile = ['ipad','iphone','ipod','apple tv']
    global expectedMdm
    expectedMdm = 0

    # for each item in results, compare model with the above lists.
    for i in results['results']:

        # Get the model name and convert it to lower case (so we can compare to the above lists)
        try:
            model = i['model']
            model = model.lower()
        except KeyError:
            model = "ERROR NO MODEL"
            logging.error('No model!')

        # Count computer devices (entries that have the string "mac") = denominator
        # Then also search the database to see if they are inrolled in jamf = numerator
        if ([x for x in comp if(x in model)]):
            expectedComputers += 1
        else:
            expectedMdm += 1

    logging.debug('expectedMdm: %s', expectedComputers)
    logging.info('Total computers in Apple School Manager: %s', expectedComputers)
    logging.debug('expectedComputers: %s', expectedMdm)
    logging.info('Total mobile devices in Apple School Manager: %s', expectedComputers)
    
    if expectedMdm + expectedComputers == totalCount:
        logging.info('The sum of computers (%s) and devices (%s) equals the total count (%s).', expectedComputers, expectedMdm, totalCount)
    else:
        diff = expectedMdm + expectedComputers - totalCount
        logging.error('The sum of computers (%s) and devices (%s) does not equal the total count (%s). There is a difference of %s devices.', expectedComputers, expectedMdm, totalCount, diff)

    # Close function count_school_managed

def jamf_rollup():

    logging.debug("entered function: jamf_rollup")

    # expectedComputers - This value is calculated in the "count_school_managed" function
    
    # expectedMdm - This value is calculated in the "count_school_managed" function

    # comp_latestAgentVersion
    sql = "SELECT SUBSTRING_INDEX(jamfBinaryVersion,'-',1)\
           FROM jamfpro_asset\
           GROUP BY jamfBinaryVersion\
           ORDER BY jamfBinaryVersion DESC\
           LIMIT 1;"

    try:
        ret = db.doSel(sql)
        comp_latestAgentVersion = ret[0][0]
        logging.debug('comp_latestAgentVersion: %s', comp_latestAgentVersion)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_agentsInstalled
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_agentsInstalled\
           FROM (\
               SELECT\
                   (SELECT COUNT(*) FROM " + str(table_asset) + ") AS num,\
                   (SELECT " + str(expectedComputers) + ") AS den\
           ) a ;"
    try:
        ret = db.doSel(sql)
        comp_agentsInstalled = ret [0][0]
        logging.debug('comp_agentsInstalled: %s', comp_agentsInstalled)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_duplicates
    # Count how many duplicates exist in the db
    sql = "SELECT SUM(a.count) AS duplicates\
           FROM (\
              SELECT COUNT(name) as count\
              FROM " + str(table_asset) + "\
              GROUP BY name\
              HAVING COUNT(name) > 1\
           ) a;"

    try:
        ret = db.doSel(sql)
        duplicates = ret [0][0]
        logging.debug('duplicates: %s', duplicates)
    except mysql.connector.Error as err:
        logging.error(err)

    # Count total records in db
    sql = "SELECT COUNT(*) FROM " + str(table_asset) + ";"

    try:
        ret = db.doSel(sql)
        countComputers = ret [0][0]
        logging.debug('countComputers: %s', countComputers)
    except mysql.connector.Error as err:
        logging.error(err)

    comp_duplicates = math.trunc(((countComputers - duplicates) / countComputers) * 100)
    logging.debug('comp_duplicates: %s', comp_duplicates)

    # comp_agentsUpdated
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_agentsUpdated\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE jamfBinaryVersion LIKE '" + str(comp_latestAgentVersion) + "%') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a ;"

    try:
        ret = db.doSel(sql)
        comp_agentsUpdated = ret[0][0]
        logging.debug('comp_agentsUpdated: %s', comp_agentsUpdated)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_managed
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_managed\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE managed = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_managed = ret[0][0]
        logging.debug('comp_managed: %s', comp_managed)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_supervised
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_supervised\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE supervised = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_supervised = ret[0][0]
        logging.debug('comp_supervised: %s', comp_supervised)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_mdmCapable
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_mdmCapable\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE mdmCapable = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_mdmCapable = ret[0][0]
        logging.debug('comp_mdmCapable: %s', comp_mdmCapable)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_reportDate
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_reportDate\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE reportDate >= DATE(NOW()) - INTERVAL 14 DAY) AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_reportDate = ret[0][0]
        logging.debug('comp_reportDate: %s', comp_reportDate)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_lastContactTime
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_lastContactTime\
           FROM (\
               SELECT\
                   (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE lastContactTime >= DATE(NOW()) - INTERVAL 14 DAY) AS num,\
                   (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_lastContactTime = ret[0][0]
        logging.debug('comp_lastContactTime: %s', comp_lastContactTime)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_mdmProfileExpiration
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_mdmProfileExpiration\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE mdmProfileExpiration > DATE(NOW()) + INTERVAL 30 DAY) AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_mdmProfileExpiration = ret[0][0]
        logging.debug('comp_mdmProfileExpiration: %s', comp_mdmProfileExpiration)
    except mysql.connector.Error as err:
        logging.error(err)

    # comp_userApprovedMdm
    sql = "SELECT FLOOR(a.num/a.den*100) AS comp_userApprovedMdm\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE userApprovedMdm = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        comp_userApprovedMdm = ret[0][0]
        logging.debug('comp_userApprovedMdm: %s', comp_userApprovedMdm)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_agentsInstalled
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_agentsInstalled\
           FROM (\
               SELECT\
                   (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS num,\
                   (SELECT " + str(expectedComputers) + ") AS den\
           ) a ;"
    try:
        ret = db.doSel(sql)
        mdm_agentsInstalled = ret [0][0]
        logging.debug('mdm_agentsInstalled: %s', mdm_agentsInstalled)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_duplicates
    # Count how many duplicates exist in the db
    sql = "SELECT SUM(a.count) AS mdm_duplicates\
           FROM (\
              SELECT COUNT(name) as count\
              FROM " + str(table_mdm) + "\
              GROUP BY name\
              HAVING COUNT(name) > 1\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_duplicates = ret [0][0]
        logging.debug('mdm_duplicates: %s', mdm_duplicates)
    except mysql.connector.Error as err:
        logging.error(err)

    # Count total records in db
    sql = "SELECT COUNT(*) FROM " + str(table_mdm) + ";"

    try:
        ret = db.doSel(sql)
        countMdm = ret [0][0]
        logging.debug('countMdm: %s', countMdm)
    except mysql.connector.Error as err:
        logging.error(err)

    comp_duplicates = math.trunc(((countMdm - duplicates) / countMdm) * 100)
    logging.debug('comp_duplicates: %s', comp_duplicates)

    # mdm_lastUpdate
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_lastUpdate\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE lastInventoryUpdateTimestamp >= DATE(NOW()) - INTERVAL 14 DAY) AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_lastUpdate = ret[0][0]
        logging.debug('mdm_lastUpdate: %s', mdm_lastUpdate)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_managed
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_managed\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE managed = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_managed = ret[0][0]
        logging.debug('mdm_managed: %s', mdm_managed)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_ProfileExpiration
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_ProfileExpiration\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE mdmProfileExpirationTimestamp > DATE(NOW()) + INTERVAL 30 DAY) AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_ProfileExpiration = ret[0][0]
        logging.debug('mdm_ProfileExpiration: %s', mdm_ProfileExpiration)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_deviceOwnershipLevel
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_deviceOwnershipLevel\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE deviceOwnershipLevel = 'Institutional') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_deviceOwnershipLevel = ret[0][0]
        logging.debug('mdm_deviceOwnershipLevel: %s', mdm_deviceOwnershipLevel)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_enrollmentMethod
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_enrollmentMethod\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE enrollmentMethod != 'None') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_enrollmentMethod = ret[0][0]
        logging.debug('mdm_enrollmentMethod: %s', mdm_enrollmentMethod)
    except mysql.connector.Error as err:
        logging.error(err)

    # mdm_supervised
    sql = "SELECT FLOOR(a.num/a.den*100) AS mdm_supervised\
           FROM (\
              SELECT\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + " WHERE SUPERVISED = 'True') AS num,\
                 (SELECT COUNT(*) FROM " + str(table_mdm) + ") AS den\
           ) a;"

    try:
        ret = db.doSel(sql)
        mdm_supervised = ret[0][0]
        logging.debug('mdm_supervised: %s', mdm_supervised)
    except mysql.connector.Error as err:
        logging.error(err)

    # Insert all of the above data into the rollup table
    # The rollup table is a daily rollup of metrics calculated from the asset & mdm tables
    sql = ("INSERT INTO jamfpro_rollup "
          "(id, date, expectedComputers, expectedMdm, comp_latestAgentVersion, comp_duplicates, comp_agentsInstalled, comp_agentsUpdated, comp_managed, comp_supervised, comp_mdmCapable, comp_reportDate, comp_lastContactTime, comp_mdmProfileExpiration, comp_userApprovedMdm, mdm_duplicates, mdm_agentsInstalled, mdm_lastUpdate, mdm_managed, mdm_ProfileExpiration, mdm_deviceOwnershipLevel, mdm_enrollmentMethod, mdm_supervised) "
          "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

    data = (rowId, timestamp, expectedComputers, expectedMdm, comp_latestAgentVersion, comp_duplicates, comp_agentsInstalled, comp_agentsUpdated, comp_managed, comp_supervised, comp_mdmCapable, comp_reportDate, comp_lastContactTime, comp_mdmProfileExpiration, comp_userApprovedMdm, mdm_duplicates, mdm_agentsInstalled, mdm_lastUpdate, mdm_managed, mdm_ProfileExpiration, mdm_deviceOwnershipLevel, mdm_enrollmentMethod, mdm_supervised)

    try:
        ret = db.doExec(sql,data)
        logging.info('Successfully INSERTed metrics for %s into table: "%s."', today, table_metrics_rollup)
    except mysql.connector.Error as err:
        logging.error(err)

    # daily_total = a daily rollup weighted average of the day's metrics
    # Assign a weight to each metric according to its importance, divide by the total sum of weights
    # sql = "SELECT FLOOR(\
    #           comp_duplicates * 5 + \
    #           comp_agentsInstalled * 25 + \
    #           comp_agentsUpdated * 10 + \
    #           comp_managed * 3 + \
    #           comp_supervised * 5 + \
    #           comp_mdmCapable * 1 + \
    #           comp_reportDate * 10 + \
    #           comp_lastContactTime * 10 + \
    #           comp_mdmProfileExpiration * 15 + \
    #           comp_userApprovedMdm * 2 + \
    #           mdm_duplicates * 5 + \
    #           mdm_agentsInstalled * 25 + \
    #           mdm_lastUpdate * 10 + \
    #           mdm_managed * 3 + \
    #           mdm_ProfileExpiration * 15 + \
    #           mdm_deviceOwnershipLevel * 2 + \
    #           mdm_enrollmentMethod * 3 + \
    #           mdm_supervised * 2 \
    #           ) / 151 \
    #        FROM " + str(table_metrics_rollup) + ";"

    # try:
    #     ret = db.doSel(sql)
    #     daily_total = ret[0][0]
    #     logging.debug('daily_total: %s', daily_total)
    # except mysql.connector.Error as err:
    #     logging.error(err)

    daily_total = round(((comp_duplicates * 5 +
                   comp_agentsInstalled * 25 +
                   comp_agentsUpdated * 10 +
                   comp_managed * 3 +
                   comp_supervised * 5 +
                   comp_mdmCapable * 1 +
                   comp_reportDate * 10 +
                   comp_lastContactTime * 10 +
                   comp_mdmProfileExpiration * 15 +
                   comp_userApprovedMdm * 2 +
                   mdm_duplicates * 5 +
                   mdm_agentsInstalled * 25 +
                   mdm_lastUpdate * 10 +
                   mdm_managed * 3 +
                   mdm_ProfileExpiration * 15 +
                   mdm_deviceOwnershipLevel * 2 +
                   mdm_enrollmentMethod * 3 +
                   mdm_supervised * 2)
                   / 151),0)
    logging.debug('daily_total: %s', daily_total)

    # Insert the daily rollup into the last row of the table
    sql = ("UPDATE jamfpro_rollup SET daily_total = %s WHERE date(date) = %s ORDER BY date DESC LIMIT 1")

    data = (daily_total, today)

    try:
        ret = db.doExec(sql,data)
        logging.info('Successfully INSERTed into table "%s": %s', table_metrics_rollup, daily_total)
    except mysql.connector.Error as err:
        logging.error(err)

    # Close function jamf_rollup

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
log_File = '/opt/scripts/logs/ca_jamfpro.log'
#log_File = 'jamf.txt'
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.INFO, filemode='w')

# Define the URL that we will use throughout this script
# And pull in the credentials from the secrets.json file
if 'jamfpro' in SECRETS:
    
    # Build the base URL that will be passed into the API calls
    baseUrl = 'https://{0}'.format(SECRETS['jamfpro']['host'])
    logging.debug('baseUrl: %s', baseUrl)

    # Credentials used to request the Token
    user = '{0}'.format(SECRETS['jamfpro']['user'])
    password = '{0}'.format(SECRETS['jamfpro']['password'])

    # generate authorization headers
    headers = {
        'Accept': 'application/json',
    }

    # Retreive the API token
    url = '{0}/api/v1/auth/token'.format(baseUrl)
    request = requests.post(url, headers=headers, auth=(user, password))
    response = request.json()
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


jamf_get_computers()
jamf_get_mobile_devices()
count_school_managed()
jamf_rollup()

# # Run this last
data_retention()