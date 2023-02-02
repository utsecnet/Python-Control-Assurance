#!/usr/bin/python3
# -*- coding: utf-8 -*-

''' Pull control assurance measures from SentinelOne (S1) into MySQl DB

We access a single S1 API endpoint:
* agents

After identifying which control assurance measures to pull from the API, we
ingest those into a MySQL database. The process follows these general steps:
1. Get asset details related to control assurance into an "asset" table.
2. Count up cetain measures and add to a "rollup" table
3. Calculate a daily_total value

The data may then be accessed and displayed using a dashboard frontend of
choice.

'''

__file__ = "ca_sentinel.py"
__authors__ = ["Rich Johnson", "Austin Pratt"]
__date__ = "2022-12-14"
__depricated__ = "False"
__maintainer__ = "Austin Pratt"
__status__ = "Production"
__version__ = "1.0"

# TODO: Modify the rollup table to include a column for Total number of assets
#       from CMDB.  We must have CMDB first. For now we take a best guess at
#       total number of assets
# TODO: add latestRangerVersion column to rollup. (onlu if we use Ranger).
# TODO: Eliminate ' marks from userActionsNeeded - This property is casuing
#       issues which are preventing us from gathering this data.
# TODO: Build a log rotation class or use the OS's log rotation capabilities.
# TODO: Get asset tags into the tags 3rd-normal-form tables

# Standard Python libraries
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

def sentinelone_get_agents ():

    logging.info("entered function: sentinelone_get_agents")

    # Clears table before getting an updated dataset. 
    sql = "TRUNCATE TABLE " + str(table_asset) + ";"

    try:
        ret = db.doTrunc(sql)
        logging.info('Truncated table: "%s".', table_asset)
    except mysql.connector.Error as err:
        logging.error(err)

    # Define the first URL for getting agents in SentinelOne. Every URL after 
    # this will require a "cursor" parameter
    # Cursor is like a page number according to SentinelOne's API documentation
    url = '{0}/agents?limit=100'.format(baseUrl)

     # Get the response and save it to JSON
    response = requests.get(url, headers=header)
    results = response.json()

    # Set cursor (i.e., the next page)
    cursor = results["pagination"]["nextCursor"]
    
    # Loop through all pages of results
    while cursor != "None":

        # Loop through all agent results and get the values we consider
        # important to Control Assurance
        for i in results['data']:

            # asset_id
            try:
                asset_id = str(i['id']) 
            except KeyError:
                asset_id = ""

            # computerName
            try:
                computerName = str(i["computerName"]) 
            except KeyError:
                computerName = ""

            # activeThreats
            try:
                activeThreats = str(i['activeThreats']) 
            except KeyError:
                activeThreats = ""

            # agentVersion
            try:
                agentVersion = str(i['agentVersion']) 
            except KeyError:
                agentVersion = ""

            # allowRemoteShell boolean
            try:
                allowRemoteShell = str(i['allowRemoteShell']) 
            except KeyError:
                allowRemoteShell = ""

            # appsVulnerabilityStatus
            try:
                appsVulnerabilityStatus = str(i['appsVulnerabilityStatus']) 
            except KeyError:
                appsVulnerabilityStatus = ""
            
            # consoleMigrationStatus
            try:
                consoleMigrationStatus = str(i['consoleMigrationStatus']) 
            except KeyError:
                consoleMigrationStatus = ""
            
            # detectionState
            try:
                detectionState = str(i['detectionState']) 
            except KeyError:
                detectionState = ""

            # encryptedApplications boolean
            try:
                encryptedApplications = str(i['encryptedApplications']) 
            except KeyError:
                encryptedApplications = ""
            
            # detectionState boolean
            try:
                firewallEnabled = str(i['firewallEnabled']) 
            except KeyError:
                firewallEnabled = ""
            
            # groupName
            try:
                groupName = str(i['groupName']) 
            except KeyError:
                groupName = ""
            
            # inRemoteShellSession boolean
            try:
                inRemoteShellSession = str(i['inRemoteShellSession']) 
            except KeyError:
                inRemoteShellSession = ""
            
            # infected boolean
            try:
                infected = str(i['infected']) 
            except KeyError:
                infected = ""
            
            # isActive boolean
            try:
                isActive = str(i['isActive']) 
            except KeyError:
                isActive = ""
            
            # isDecommissioned boolean
            try:
                isDecommissioned = str(i['isDecommissioned']) 
            except KeyError:
                isDecommissioned = ""
            
            # isPendingUninstall boolean
            try:
                isPendingUninstall = str(i['isPendingUninstall']) 
            except KeyError:
                isPendingUninstall = ""
            
            # isUninstalled boolean
            try:
                isUninstalled = str(i['isUninstalled']) 
            except KeyError:
                isUninstalled = ""
            
            # isUpToDate boolean
            try:
                isUpToDate = str(i['isUpToDate']) 
            except KeyError:
                isUpToDate = ""
            
            # lastActiveDate datetime
            try:
                lastActiveDate = datetime.datetime.strftime(datetime.datetime.strptime(i['lastActiveDate'], iso), mysqliso) 
            except KeyError:
                lastActiveDate = "1970-01-01 00:00:00"
            
            # lastLoggedInUserName
            try:
                lastLoggedInUserName = str(i['lastLoggedInUserName']) 
            except KeyError:
                lastLoggedInUserName = ""
            
            # licenseKey
            try:
                licenseKey = str(i['licenseKey']) 
            except KeyError:
                licenseKey = ""
            
            # machineType
            try:
                machineType = str(i['machineType']) 
            except KeyError:
                machineType = ""
            
            # mitigationMode
            try:
                mitigationMode = str(i['mitigationMode']) 
            except KeyError:
                mitigationMode = ""
            
            # mitigationModeSuspicious
            try:
                mitigationModeSuspicious = str(i['mitigationModeSuspicious']) 
            except KeyError:
                mitigationModeSuspicious = ""
            
            # modelName
            try:
                modelName = str(i['modelName']) 
            except KeyError:
                modelName = ""
            
            # networkQuarantineEnabled boolean
            try:
                networkQuarantineEnabled = str(i['networkQuarantineEnabled']) 
            except KeyError:
                networkQuarantineEnabled = ""
            
            # networkStatus 
            try:
                networkStatus = str(i['networkStatus']) 
            except KeyError:
                networkStatus = ""
            
            # operationalState 
            try:
                operationalState = str(i['operationalState']) 
            except KeyError:
                operationalState = ""
            
            # operationalStateExpiration 
            try:
                operationalStateExpiration = str(i['operationalStateExpiration']) 
            except KeyError:
                operationalStateExpiration = ""
            
            # osType 
            try:
                osType = str(i['osType']) 
            except KeyError:
                osType = ""
            
            # osName 
            try:
                osName = str(i['osName']) 
            except KeyError:
                osName = ""
            
            # rangerStatus 
            try:
                rangerStatus = str(i['rangerStatus']) 
            except KeyError:
                rangerStatus = ""
            
            # rangerVersion 
            try:
                rangerVersion = str(i['rangerVersion']) 
            except KeyError:
                rangerVersion = ""
            
            # registeredAt datetime
            try:
                registeredAt = datetime.datetime.strftime(datetime.datetime.strptime(i['registeredAt'], iso), mysqliso)
            except KeyError:
                registeredAt = "1970-01-01 00:00:00"
            
            # remoteProfilingState 
            try:
                remoteProfilingState = str(i['remoteProfilingState']) 
            except KeyError:
                remoteProfilingState = ""

            # remoteProfilingStateExpiration 
            try:
                remoteProfilingStateExpiration = str(i['remoteProfilingStateExpiration']) 
            except KeyError:
                remoteProfilingStateExpiration = ""
            
            # scanFinishedAt datetime
            try:
                scanFinishedAt = datetime.datetime.strftime(datetime.datetime.strptime(i['scanFinishedAt'], iso), mysqliso)
            except TypeError:
                scanFinishedAt = "1970-01-01 00:00:00"

            # siteName 
            try:
                siteName = str(i['siteName']) 
            except KeyError:
                siteName = ""
            
            # threatRebootRequired boolean
            try:
                threatRebootRequired = str(i['threatRebootRequired']) 
            except KeyError:
                threatRebootRequired = ""
            
            # updatedAt 
            try:
                updatedAt = datetime.datetime.strftime(datetime.datetime.strptime(i['updatedAt'], iso), mysqliso) 
            except KeyError:
                updatedAt = ""

            for tag in i['tags']:
                tag_id = ""

                tag_name = ""
            
            # userActionsNeeded 
            # try:
            #     userActionsNeeded = str(i['userActionsNeeded']) 
            # except KeyError:
            #     userActionsNeeded = "" 
            userActionsNeeded = ""

            sql = ("INSERT INTO sentinelone_asset "
                  "(id, asset_id, activeThreats, agentVersion, allowRemoteShell, appsVulnerabilityStatus, computerName, consoleMigrationStatus, detectionState, encryptedApplications, firewallEnabled, groupName, inRemoteShellSession, infected, isActive, isDecommissioned, isPendingUninstall, isUninstalled, isUpToDate, lastActiveDate, lastLoggedInUserName, licenseKey, machineType, mitigationMode, mitigationModeSuspicious, modelName, networkQuarantineEnabled, networkStatus, operationalState, operationalStateExpiration, osType, osName, rangerStatus, rangerVersion, registeredAt, remoteProfilingState, remoteProfilingStateExpiration, scanFinishedAt, siteName, threatRebootRequired, updatedAt, userActionsNeeded) " 
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

            data = (rowId, asset_id, activeThreats, agentVersion, allowRemoteShell, appsVulnerabilityStatus, computerName, consoleMigrationStatus, detectionState, encryptedApplications, firewallEnabled, groupName, inRemoteShellSession, infected, isActive, isDecommissioned, isPendingUninstall, isUninstalled, isUpToDate, lastActiveDate, lastLoggedInUserName, licenseKey, machineType, mitigationMode, mitigationModeSuspicious, modelName, networkQuarantineEnabled, networkStatus, operationalState, operationalStateExpiration, osType, osName, rangerStatus, rangerVersion, registeredAt, remoteProfilingState, remoteProfilingStateExpiration, scanFinishedAt, siteName, threatRebootRequired, updatedAt, userActionsNeeded)

            try:
                ret = db.doExec(sql,data)
                logging.info('Successfully INSERTed into table "%s": %s.', table_asset, computerName)

            except mysql.connector.Error as err:
                logging.error(err)

        # Define the next URL using cursor
        url = '{0}/agents?limit=100&cursor={1}'.format(baseUrl,cursor)

        # Get the response and save it to JSON
        response = requests.get(url, headers=header)
        results = response.json()

        # Set cursor
        try:
            cursor = results["pagination"]["nextCursor"]
        except KeyError:
            cursor = "None"
# Close function sentinelone_get_agents

def qtcircle(dups,agentsInstalled):
    logging.info('Entered Fuction: qtcircle')
    
    unmodifiedScore = 100 - (dups/agentsInstalled*100)
    logging.debug('unmodifiedScore: %s', unmodifiedScore)
    
    modifiedScore = math.floor(100 - math.sqrt(abs(100**2 - unmodifiedScore**2)))
    logging.debug('modifiedScore: %s', modifiedScore)
    
    return modifiedScore
    # End Function qtcircle

# Define the value that is expected for each of the below measures. 
# Count how many instances of agents on which that value is true (numerator)
# Then count total number of agents (denominator).
# Calculate and save that metric to the appropriate column.
#
# CAUTION!!!! Some of these measures you may only expect to see configured on a 
# small scope of agents. Calculate accordingly!
#
def sentinelone_rollup():

    logging.info("entered function: sentinelone_rollup")

    # totalAssets
    # total number of assets from CMDB TODO
    totalAssets = 9001
    logging.debug('totalAssets: %s', totalAssets)

    # totalAgents 
    sql = "(SELECT COUNT(*) FROM " + str(table_asset) + ")"
    try:
        ret = db.doSel(sql)
        totalAgents = ret [0][0]
        logging.debug('totalAgents: %s', totalAgents)
    except mysql.connector.Error as err:
        logging.error(err)

    # duplicates
    # Calculates the total number of duplicates based on computerName from the 
    # sentinelone_asset table then divides it by the totalAssets from the CMDB.
    sql = "SELECT SUM(a.count) AS duplicates\
        FROM (\
            SELECT COUNT(computerName) AS count\
            FROM " + str(table_asset) + "\
            WHERE computerName <> 'None'\
            GROUP BY computerName\
            HAVING COUNT(computerName) > 1\
        ) a;"
    
    try:
        ret = db.doSel(sql)
        duplicates = ret [0][0]
        # get modified, quarter circle function score as percentage
        duplicates = qtcircle(duplicates,totalAssets)
        logging.debug('duplicates: %s', duplicates)
    except mysql.connector.Error as err:
        logging.error(err)
    
    # gets inverse percentage of duplicates for rollup score if not using qt
    # circle function.
    # duplicates = abs((duplicates/totalAssets)-1)*100

    # latestAgentVersion ------- prereq for updatedAgents
    # Get the highest agent sub-version (X.X.X) installed across all endpoints 
    # and call that the "Latest Version". We will compare all other agent 
    # versions to this version. Anything not like this value is not compliant
    sql = "SELECT SUBSTRING_INDEX(agentVersion,'.',3) \
            FROM " + str(table_asset) + "\
            WHERE agentVersion LIKE '2%' \
            GROUP BY agentVersion \
            ORDER BY agentVersion DESC \
            LIMIT 1;"

    try:
        ret = db.doSel(sql)
        latestAgentVersion = ret[0][0]
        logging.debug('latestAgentVersion: %s', latestAgentVersion)
    except mysql.connector.Error as err:
        logging.error(err)
        
    # latestRangerVersion ------- prereq for rangerVersion -------
    # Get the highest agent version installed across all endpoints and call that
    # the "Latest Version". We will compare all other agent versions to this 
    # version. Anything not equal to this value is not compiant
    #
    # NOTE: May not need this if we don't use ranger.
    # sql = "SELECT rangerVersion \
    #        FROM " + str(table_asset) + "\
    #        WHERE rangerVersion LIKE '2%' \
    #        GROUP BY rangerVersion \
    #        ORDER BY rangerVersion DESC LIMIT 1;"
    # try:
    #     ret = db.doSel(sql)
    #     latestRangerVersion = ret[0][0]
    #     logging.debug('latestRangerVersion: %s', latestRangerVersion)
    # except mysql.connector.Error as err:
    #     logging.error(err)

    # updatedAgents
    # Counts agents whose version is equal to latestAgentVersion (up to date) 
    # over total number of agents. We expect al agents to update to the latest
    # version, and expect to investigate when it becomes several version behind.
    sql = "SELECT FLOOR(a.num/a.den*100) AS updatedAgents\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE agentVersion LIKE '" + str(latestAgentVersion) + "%') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        updatedAgents = ret[0][0]
        logging.debug('updatedAgents: %s', updatedAgents)
    except mysql.connector.Error as err:
        logging.error(err)

    # agentsInstalled ------- count table?
    # Gets a count of all endpoints within the S1 console. 
    # NOTE: The API has a dedicated endpoint from which you can retrieve this
    # value. This value is differernt than the count of endpoints! We'll need to
    # see why they are different values.
    # /web/api/v2.1/agents/count - will return a single int value of the number
    # of agents in the console that match a given filter (default no filter)
    sql = "SELECT FLOOR(a.num/a.den*100) AS agentsInstalled\
            FROM (\
                SELECT\
                    (SELECT " + str(totalAgents) + ") AS num,\
                    (SELECT " + str(totalAssets) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        agentsInstalled = ret [0][0]
        logging.debug('agentsInstalled: %s', agentsInstalled)
    except mysql.connector.Error as err:
        logging.error(err)

    # lastActiveDate
    # S1 deletes an endpoint after 21 days. Our goal is to investigate endpoints
    # that havnt checked-in with the console before they get deleted. Starting 
    # with 14 days, we will tune later. Counts all endpoints that have checked-
    # in with the console within 14 days over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS lastActiveDate\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE lastActiveDate >= DATE(NOW()) - INTERVAL 14 DAY) AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        lastActiveDate = ret[0][0]
        logging.debug('lastActiveDate: %s', lastActiveDate)
    except mysql.connector.Error as err:
        logging.error(err)

    # operationalState
    # The operational state of the agent, since this can be disabled by the user
    # or admin of the agent. Counts all endpoints that have operationalState 
    # not = "na" over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS operationalState\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE operationalState = 'na') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        operationalState = ret[0][0]
        logging.debug('operationalState: %s', operationalState)
    except mysql.connector.Error as err:
        logging.error(err)

    # mitigationModeSuspicious
    # We expect mitigationModeSuspicious to be "detect" on each endpoint, though
    # "protect" is fine as well, it's just above and beyond. It could be that we
    # want "sensitive data environments" be "protect" rather than the default 
    # "detect", in which case this metric may become more valueable in those 
    # instances
    # sql = "SELECT FLOOR(a.num/a.den*100) AS mitigationModeSuspicious\
    #         FROM (\
    #             SELECT\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE mitigationModeSuspicious = 'detect/protect') AS num,\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
    #         ) a ;"
    # try:
    #     ret = db.doSel(sql)
    #     mitigationModeSuspicious = ret[0][0]
    #     logging.debug('mitigationModeSuspicious: %s', mitigationModeSuspicious)
    # except mysql.connector.Error as err:
    #     logging.error(err)
    mitigationModeSuspicious = 100
    logging.debug('mitigationModeSuspicious: %s', mitigationModeSuspicious)

    # mitigationMode
    # We expect all agents to be in "protect" mode. 
    # Counts all endpoints that are in protect mode over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS mitigationMode\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE mitigationMode = 'protect') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        mitigationMode = ret[0][0]
        logging.debug('mitigationMode: %s', mitigationMode)
    except mysql.connector.Error as err:
        logging.error(err)
        
    # remoteProfilingState 
    # When enabled, it turns on advanced logging and potential access to S1 
    # support on a given endpoint. We expect all agents to be "disabled".
    # Counts all endpoints whose remoteProfilingState is "disabled" over total 
    # number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS remoteProfilingState\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE remoteProfilingState = 'disabled') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        remoteProfilingState = ret[0][0]
        logging.debug('remoteProfilingState: %s', remoteProfilingState)
    except mysql.connector.Error as err:
        logging.error(err)

    # allowRemoteShell
    # Remote shells help admins troubleshoot agent issues. They also are a 
    # backdoor to an endpoint. As such, we expect everything to show "false" 
    # except when an admin is using it. Counts all endpoints whose 
    # allowRemoteShell is "false" over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS allowRemoteShell\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE allowRemoteShell = 'False') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        allowRemoteShell = ret[0][0]
        logging.debug('allowRemoteShell: %s', allowRemoteShell)
    except mysql.connector.Error as err:
        logging.error(err)

    # appsVulnerabilityStatus
    # Identifies which endpoints may require application updates (could point to
    # a patching problem). Counts all endpoints whose applications are 
    # up-to-date over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS appsVulnerabilityStatus\
            FROM (\
                SELECT\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE appsVulnerabilityStatus = 'up_to_date') AS num,\
                    (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE appsVulnerabilityStatus != 'not_applicable') AS den\
            ) a ;"
    try:
        ret = db.doSel(sql)
        appsVulnerabilityStatus = ret[0][0]
        logging.debug('appsVulnerabilityStatus: %s', appsVulnerabilityStatus)
    except mysql.connector.Error as err:
        logging.error(err)

    # isActive
    # Looks like this is down-to-the-minute of a machine being online. This 
    # means it may only be important to see this metric on servers as 
    # worksations would be too eratic. Counts all endpoints which have checked 
    # in with the console within the last 4 minute poll over total number of 
    # agents
    # sql = "SELECT FLOOR(a.num/a.den*100) AS isActive\
    #         FROM (\
    #             SELECT\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE isActive = 'True') AS num,\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
    #         ) a ;"
    # try:
    #     ret = db.doSel(sql)
    #     isActive = ret[0][0]
    #     logging.debug('isActive: %s', isActive)
    # except mysql.connector.Error as err:
    #     logging.error(err)
    isActive = 0
    logging.debug('isActive: %s', isActive)

    # isDecommissioned
    # Helps us identify an endpoint that has explicitly been marked as decommed
    # within the console. Counts all endpoints that are not marked "true" over 
    # total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS isDecommissioned\
                FROM (\
                    SELECT\
                        (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE isDecommissioned = 'False') AS num,\
                        (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
                ) a ;"
    try:
        ret = db.doSel(sql)
        isDecommissioned = ret[0][0]
        logging.debug('isDecommissioned: %s', isDecommissioned)
    except mysql.connector.Error as err:
        logging.error(err)

    # isPendingUninstall
    # Helps us identify endpoints where the user or an S1 admin has triggered 
    # the S1 agent to uninstall. We should expect to investigate any 
    # unauthorized uninstallations. Counts all endpoints which are not marked 
    # for uninstall over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS isPendingUninstall\
                FROM (\
                    SELECT\
                        (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE isPendingUninstall = 'False') AS num,\
                        (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
                ) a ;"
    try:
        ret = db.doSel(sql)
        isPendingUninstall = ret[0][0]
        logging.debug('isPendingUninstall: %s', isPendingUninstall)
    except mysql.connector.Error as err:
        logging.error(err)

    # isUninstalled
    # When unisntalled via the console, it marks the agent as unisntalled. We 
    # should investigate any unauthorized uninstalls. Counts all endpoints that 
    # have not been marked for uninstall over total number of agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS isUninstalled\
                FROM (\
                    SELECT\
                        (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE isUninstalled = 'False') AS num,\
                        (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
                ) a ;"
    try:
        ret = db.doSel(sql)
        isUninstalled = ret[0][0]
        logging.debug('isUninstalled: %s', isUninstalled)
    except mysql.connector.Error as err:
        logging.error(err)

    # # rangerStatus
    # Disabled for now as we dont use Ranger
    # sql = "SELECT FLOOR(a.num/a.den*100) AS rangerStatus\
    #         FROM (\
    #             SELECT\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE rangerStatus = 'Enabled') AS num,\
    #                 (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE rangerStatus = 'Disabled' OR rangerStatus = 'Enabled') AS den\
    #         ) a ;"
    # try:
    #     ret = db.doSel(sql)
    #     rangerStatus = ret[0][0]
    #     logging.debug('rangerStatus: %s', rangerStatus)
    # except mysql.connector.Error as err:
    #     logging.error(err)
    rangerStatus = 0
    logging.debug('rangerStatus: %s', rangerStatus)

    # rangerVersion
    # Disabled for now as we dont use Ranger
    # sql = "SELECT FLOOR(a.num/a.den*100) AS rangerVersion\
    #        FROM (\
    #            SELECT\
    #                (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE rangerVersion = '" + str(latestRangerVersion) + "') AS num,\
    #                (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
    #        ) a ;"
    # try:
    #     ret = db.doSel(sql)
    #     rangerVersion = ret[0][0]
    #     logging.debug('rangerVersion: %s', rangerVersion)
    # except mysql.connector.Error as err:
    #     logging.error(err)
    rangerVersion = 0
    logging.debug('rangerVersion: %s', rangerVersion)

    # firewallEnabled
    # Counts devices where the local firewall is enabled over total number of 
    # agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS firewallEnabled\
                FROM (\
                    SELECT\
                        (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE firewallEnabled = 'True') AS num,\
                        (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
                ) a ;"
    try:
        ret = db.doSel(sql)
        firewallEnabled = ret[0][0]
        logging.debug('firewallEnabled: %s', firewallEnabled)
    except mysql.connector.Error as err:
        logging.error(err)

    # encryptedApplications
    # Counts devices where the local drive is encrypted over total number of 
    # agents
    sql = "SELECT FLOOR(a.num/a.den*100) AS encryptedApplications\
                FROM (\
                    SELECT\
                        (SELECT COUNT(*) FROM " + str(table_asset) + " WHERE encryptedApplications = 'True') AS num,\
                        (SELECT COUNT(*) FROM " + str(table_asset) + ") AS den\
                ) a ;"
    try:
        ret = db.doSel(sql)
        encryptedApplications = ret[0][0]
        logging.debug('encryptedApplications: %s', encryptedApplications)
    except mysql.connector.Error as err:
        logging.error(err)

    # Insert all of the above data into the rollup table
    # The rollup table is a daily rollup of metrics calculated from the asset 
    # table
    sql = ("INSERT INTO sentinelone_rollup "
          "(id, date, totalAssets, duplicates, latestAgentVersion, agentsInstalled, updatedAgents, operationalState, lastActiveDate, mitigationModeSuspicious, mitigationMode, remoteProfilingState, allowRemoteShell, appsVulnerabilityStatus, isActive, isDecommissioned, isPendingUninstall, isUninstalled, rangerStatus, rangerVersion, firewallEnabled, encryptedApplications) "
          "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

    data = (rowId, timestamp, totalAssets, duplicates, latestAgentVersion, agentsInstalled, updatedAgents, operationalState, lastActiveDate, mitigationModeSuspicious, mitigationMode, remoteProfilingState, allowRemoteShell, appsVulnerabilityStatus, isActive, isDecommissioned, isPendingUninstall, isUninstalled, rangerStatus, rangerVersion, firewallEnabled, encryptedApplications)

    try:
        ret = db.doExec(sql,data)
        logging.info('Successfully INSERTed metrics for %s into table: "%s."', today, table_metrics_rollup)
    except mysql.connector.Error as err:
        logging.error(err)
        
    # daily_total = a daily rollup weighted average of the day's metrics
    # (scanItem1 * weight1 + scanItem2 * weight2...)/sumOfWeights
    sql = "SELECT FLOOR((duplicates*5 + agentsInstalled*30 + updatedAgents*20 + operationalState*10 + lastActiveDate*5 + remoteProfilingState*1 + allowRemoteShell*2 + isDecommissioned*2 + isPendingUninstall*2 + isUninstalled*2)/79) FROM " + str(table_metrics_rollup) + ";"

    try:
        ret = db.doSel(sql)
        daily_total = ret[0][0]
        logging.debug('daily_total: %s', daily_total)
    except mysql.connector.Error as err:
        logging.error(err)

    # Insert the daily rollup into the last row of the table
    sql = ("UPDATE sentinelone_rollup SET daily_total = %s WHERE date(date) = %s ORDER BY date DESC LIMIT 1")

    data = (daily_total, today)

    try:
        ret = db.doExec(sql,data)
        logging.info('Successfully INSERTed into table "%s": %s', table_metrics_rollup, daily_total)
    except mysql.connector.Error as err:
        logging.error(err)
    # Close function sentinelone_rollup

# Data retention - Delete data from tables older than X months
def data_retention():

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
log_File = '/opt/scripts/logs/ca_sentinelone.log'
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.DEBUG, filemode='w')

# Define the URL that we will use throughout this script
# And pull in the credentials from the secrets.json file
if 'sentinelone' in SECRETS:
    
    # Build the base URL that will be passed into the API calls
    baseUrl = 'https://{0}/web/api/v2.1'.format(SECRETS['sentinelone']['host'])
    logging.debug('baseUrl: %s', baseUrl)

    # the api token
    api_token = '{0}'.format(SECRETS['sentinelone']['apikey'])

    # generate headers
    header = {
        'Accept': 'application/json',
        'Authorization': 'ApiToken ' + api_token
    }

db = dbConn(
    '{0}'.format(SECRETS['mysql']['host']),
    '{0}'.format(SECRETS['mysql']['user']),
    '{0}'.format(SECRETS['mysql']['password']),
    '{0}'.format(SECRETS['mysql']['database'])
)

# Define the MySQL tables 
table_asset = "sentinelone_asset"
table_asset_tag = "sentinelone_asset_tag"
table_tag = "sentinelone_tag"
table_metrics_rollup = "sentinelone_rollup"

# Used to set the date in the date column of the MySQL tables
ymd = '%Y-%m-%d'

# Define the format of the date that SentinelOne presents via the API
iso = '%Y-%m-%dT%H:%M:%S.%fZ'

# We will take the date format from SentinelOnes's API and convert it to a
# format that we can then insert into MySQL
mysqliso = '%Y-%m-%d %H:%M:%S'

# Today's date e.g.: 2022-01-25
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


sentinelone_get_agents()
sentinelone_rollup()
# ivm_get_tags()
# ivm_get_assets()
# ivm_metrics_rollup()

# Run this last
data_retention()