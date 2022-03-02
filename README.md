# Python - Control Assurance

## Why did I create these scripts?

My last organization had nearly 3 dozen security controls, each with their own web interfaces and reporting dashboards. Each seperate and un-integrated with each other (for the most part). I wanted a single interface to show me things like:

* Deployment status of agents across all endopoints
* Last time agent checked-in with its console
* Agent health status
* Agent version
* Platform definitions update status
* Total asset count of managed endpoints
* Total discovered unmanaged endpoints
* Authenticated scan status (success or fail) for controls that perform scans (e.g., vuln scanners)
* License status

## But what exactly do these scripts do?

Each script is a set of actions for an individual security control that reaches out to the control's API, gathers data relevant to the platform and each endpoint, and ingests that data into a centralized database from which reporting and dashboarding can be performed.  For example, the **ca_insightvm.py** script connects to Rapid7's Insight VM API (on-prem console server) and pulls all asset data.

## How do I use this repo?

There are a few pre-requisits in order to use this repo:

1. MySQL (or whatever flavor of SQL) database (Configuration is outside the scope of this repo)
2. I opt to run these scripts on the database server, but you can put them literally anywhere, so long as it has proper permissions to hit the APIs and connect to the MySQL server with proper GRANTS on all the right tables.
3. (Recommended but not required) each security control should have its own API user account, not associated to a single human user.
4. Python >= 3.7
5. Set good permission on the Keys/secrets.py file.  This holds all of your API credentials.

If you use any of these controls, you simply need to update the credentials within the **secrets.py** module. The scripts are well documented. Review each script to see what data is pulled from the API, and how it is ingested into the database.

## How often do these scripts run

I recommend daily, however it realy denpends on the number of endpoints managed by each control. Measure the length of time for them to all run and set your crontab according to what works best for your environement.
