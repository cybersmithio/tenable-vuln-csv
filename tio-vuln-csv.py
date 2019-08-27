#!/usr/bin/python
#
# Takes a Tenable.io vulnerability data and generates a CSV report.
# The output file is called tio-vuln-download.csv
#
# Example usage with environment variables:
# TIOACCESSKEY="********************"; export TIOACCESSKEY
# TIOSECRETKEY="********************"; export TIOSECRETKEY
# ./tio-asset-download.py
#
# This script requires the Tenable.io Python SDK to be installed.
# If this is not already done, then run pip install pytenable
#
# To add more fields, just update the fieldnames variable in the GenerateVulnCSV function.
#

import json
import os
import csv
import sys
from tenable.io import TenableIO
import argparse
import re



def GenerateVulnCSV(DEBUG,accesskey, secretkey, host, port,filename):
    #Create the connection to Tenable.io

    tio = TenableIO(accesskey, secretkey)

    #Gather the list of assets
    vulns = tio.exports.vulns()

    #Open the file that will become a CSV
    with open(filename,"w") as csvfile:
        #Create the header of the CSV file
        #The field names should be the same as what comes from the API.  For fields nested inside other fields (i.e. {'plugin': {'id': 19506}})
        # then separate the field names with a dot (.) (i.e. "plugin.id")
        fieldnames=['severity','plugin.cvss3_base_score','plugin.id','plugin.cve','plugin.name','first_found','last_found','plugin.publication_date','plugin.patch_publication_date','plugin.vpr.score','asset.ipv4','asset.agent_uuid','asset.hostname']

        #Create a CSV writer and associate with the file handle
        writer=csv.DictWriter(csvfile,fieldnames=fieldnames)
        #Write the CSV headers
        writer.writeheader()

        #Loop through all the downloaded assets and write them into the CSV file
        for i in vulns:
            if DEBUG:
                print("vuln:",i)
            rowdict={}
            for j in fieldnames:
                if DEBUG:
                    print("fieldname:",j)
                try:
                    y=i
                    for x in re.split(r'\.', j):
                        if DEBUG:
                            print("key:",x)
                        y=y[x]
                        if DEBUG:
                            print("y=:",y)
                    if DEBUG:
                        print("final y=",y)
                    rowdict[j]=y
                except:
                    rowdict[j]=None

            writer.writerow(rowdict)

    #Close the file
    csvfile.close()
    return(True)

################################################################
# Start of program 
################################################################
parser = argparse.ArgumentParser(description="Creates EKS environment to demonstration Tenable Container Security")
parser.add_argument('--debug',help="Display a **LOT** of information",action="store_true")
parser.add_argument('--accesskey', help="Tenable.io access key.",nargs=1,action="store",default=[None])
parser.add_argument('--secretkey', help="Teanble.io secret key.",nargs=1,action="store",default=[None])
args = parser.parse_args()

DEBUG=args.debug
host="cloud.tenable.com"
port="443"
# Pull as much information from the environment variables about the system to which to connect
# Where missing then initialize the variables with a blank or pull from command line.
if os.getenv('TIO_ACCESS_KEY') is None:
    # If there is an access key specified on the command line, this override anything else.
    try:
        if args.accesskey[0] != "":
            accesskey = args.accesskey[0]
    except:
        accesskey=""
else:
    accesskey = os.getenv('TIO_ACCESS_KEY')



if os.getenv('TIO_SECRET_KEY') is None:
    # If there is an  secret key specified on the command line, this override anything else.
    try:
        if args.secretkey[0] != "":
            secretkey = args.secretkey[0]
    except:
        secretkey = ""

else:
    secretkey = os.getenv('TIO_SECRET_KEY')


#Download the asset list into a CSV
GenerateVulnCSV(DEBUG,accesskey, secretkey, host, port,"tio-vuln-download.csv")


