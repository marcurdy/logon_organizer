#!/usr/bin/python3

import sys, subprocess, os, getopt, fnmatch, time, threading, itertools
import multiprocessing, json, re
import sqlite3 as lite

from subprocess import STDOUT

# Assumption is that path is set only for Linux
if os.name == "nt":
    PATHTZWORKS='C:\\Program Files\\tzworks\\'
    EVTWALK='evtwalk64.exe'
    SHELLOPT=True
    SEPARATOR='\\'
else:
    PATHTZWORKS=''
    EVTWALK='evtwalk'
    SHELLOPT=False
    SEPARATOR='/'

def usage():
    print ('')
    print ('Logon Organizer: Extreme Pro version - HP Enterprise, Digital Investigative Services')
    print ('logon_organizer.py [-d EVTX_DIR]')
    print ('  -d Directory containing the EVTX files')
    print ('Ex: python logon_organizer.py -d /data/project/eventlogs')
    print ('')

def cleanheader(filein):
    with open("output.txt", "wt") as o:
        with open(filein) as f:
            oldheader = f.readline().replace('#','').replace(' ','').replace('-','').lower()
            headerlist = oldheader.split(',')
            dups = set([x for x in headerlist if headerlist.count(x) > 1])
            for dup in dups:
                for index in range(len(headerlist)):
                    if headerlist[index] == dup:
                        headerlist[index] += "1"
                        break
            newheader = ','.join(headerlist)
            o.write(newheader)
            for line in f:
                o.write(line)
        f.close()
    o.close()
    os.remove(filein)
    os.rename("output.txt", filein)

def delfirstlines(numline, filein):
    with open("output.txt", "wt") as o:
        with open(filein) as f:
            for _ in range(numline):
                next(f)
            for line in f:
                o.write(line)
        f.close()
    o.close()
    os.remove(filein)
    os.rename("output.txt", filein)

def checkTableExists(dbcur, tablename):
    dbcur.execute("SELECT EXISTS(SELECT * FROM sqlite_master WHERE name = \'" + tablename + "')")
    if dbcur.fetchone() == (1,):
        return True
    return False

def printsqlresults (result):
    for row in result:
        print (str(row).replace('),(', "\n").replace('(','').replace(')','').replace('\'',''))

try:
    opts, args = getopt.getopt(sys.argv[1:],'hd:')
except getopt.GetoptError:
    usage()
    sys.exit(2)

DIR=""
for opt, arg in opts:
    if opt in '-d':
        DIR=arg+SEPARATOR

if (not DIR):
    usage()
    sys.exit(2)

EVENTIDS = []
EVENTIDS.append ([DIR+"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",\
                 [101,            103,                131],\
                 ["RD_Svc_Start","Wrong_perms_to_SSL","Conn_from_client"]])
EVENTIDS.append ([DIR+"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", \
                 [21],\
                 ["RD_Svc_avail"]])
EVENTIDS.append ([DIR+"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",\
                 [1149],\
                 ["Session_start"]])
EVENTIDS.append ([DIR+"Security.evtx",\
                 [4624,           4634,         4647,           4625,        4648,       4778,        4779],\
                 ["Logon_Success","Logoff_auto","Logoff_manual","Logon_Fail","Logon_Run","RDP_Recon","RDP_Discon"]])
EVENTIDS.append ([DIR+"System.evtx",\
                 [6005],\
                 ["System_Reboot"]])


for log in range(len(EVENTIDS)):
    filename=EVENTIDS[log][0]
    elementids=EVENTIDS[log][1]
    eventdescs=EVENTIDS[log][2]
    for id in range(len(elementids)):
        # Append the eventID to the input filename and ensure the output writes to currdir
        LOGFILE=str(elementids[id])+'.csv'

        # Run evtwalk for each eventID to have them easily parsed due to differing headers
        if os.path.isfile(LOGFILE):
            print (LOGFILE + " already exists. Skipping.")
        else:
            with open(LOGFILE, "w") as f:
                print ("Scanning " + filename + " for EventID " + str(elementids[id]))
                subprocess.call([PATHTZWORKS + EVTWALK, '-csv', '-no_whitespace', '-nodups', '-csv_separator', ',', 
                    '-eventid', str(elementids[id]), '-log', filename], stdout=f, shell=SHELLOPT, bufsize = 0)
                f.close()
                # Remove the lousy TZWorks headers
                delfirstlines(5, LOGFILE)

            if (os.stat(LOGFILE).st_size == 0):
                continue

            # Lousy process to get here leaves duplicate header titles that can't exist in sqlite
            cleanheader(LOGFILE)
    
        con = lite.connect('temporary.db')
        # In each file, parse the CSV header and make SQLite tables with those headers as text
        with open(LOGFILE, 'r') as f:
            header = f.readline().rstrip()
        f.close()
        headerARY = header.split(',')
        if len(headerARY) > 0:
            TABLE=''
            for field in headerARY:
                if (TABLE):
                    TABLE += ','
                TABLE += field + ' TEXT'
            TABLECREATE='CREATE TABLE ID' + str(elementids[id]) + '(' + TABLE + ')'
            with con:
                cur = con.cursor()    
                if not checkTableExists(cur, "ID" + str(elementids[id])):
                    cur.execute(TABLECREATE)
                    count = 0
                    with open(LOGFILE) as f:
                        for line in f:
                            lineaslist = line.split(',')
                            if count == 0:
                                count=len(lineaslist)
                            if count != len(lineaslist):
                                continue
                            cur.execute("INSERT INTO ID" + str(elementids[id]) + " VALUES (" + ",".join(count * ["?"])+ ")", lineaslist)
                    # Empty column element to use when selecting output to get per table columns in custom order
                    cur.execute('ALTER TABLE ID' + str(elementids[id]) + ' ADD COLUMN none TEXT')
                    cur.execute('UPDATE ID' + str(elementids[id]) + ' SET none=""')
                    # New row mapping eventid to an event description for readability
                    cur.execute('ALTER TABLE ID' + str(elementids[id]) + ' ADD COLUMN eventdesc TEXT')
                    cur.execute('UPDATE ID' + str(elementids[id]) + ' SET eventdesc="' + eventdescs[id] + '"')
                else:
                    print ("Table ID" + str(elementids[id]) + " already exists. Not reread back in") 
            f.close()

#############################################################
# Now begins the logic side of what we want output
#############################################################

if (not os.path.isfile('temporary.db') or os.stat('temporary.db').st_size == 0):
    print ("How did you get here with a bad sqlite DB? Aborting...")
    sys.exit(2)

con = lite.connect('temporary.db')
with con:
    cur = con.cursor()    

    print ("eventid,eventdesc,date,timeutc,computer,activityid,guid,processid,targetdomainname,logontype,targetusername,clientip,clientusername,subjectlogonid")
    if checkTableExists(cur, "ID4624"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid1,targetdomainname,\
                     logontype,targetusername,none,none,subjectlogonid FROM ID4624")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID4634"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid,targetdomainname,\
                     logontype,targetusername FROM ID4634")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID4647"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid,targetdomainname,\
                     none,targetusername FROM ID4647")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID4648"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid1,subjectdomainname,\
                     none,none,ipaddress,subjectusername,subjectlogonid FROM ID4648")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID4778"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid,accountdomain,none,\
                     accountname,clientaddress,clientname FROM ID4778")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID4779"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,guid,none,processid,accountdomain,none,\
                     accountname,clientaddress,clientname FROM ID4779")
        cur.fetchone() and printsqlresults (cur.fetchall())
                    
    #LOCAL
    if checkTableExists(cur, "ID21"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,none,none,none,none,none,none,none,user FROM ID21")
        cur.fetchone() and printsqlresults (cur.fetchall())
    #RDPCore
    if checkTableExists(cur, "ID131"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,none,activityid,processid,none,none,none,clientip FROM ID131")
        cur.fetchone() and printsqlresults (cur.fetchall())
    if checkTableExists(cur, "ID101"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,computer,none,activityid,processid,none,none,none,none FROM ID101")
        cur.fetchone() and printsqlresults (cur.fetchall())
    #REMOTE
    if checkTableExists(cur, "ID1149"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc,none,none,activityid,none,none,none,param1,none,computer FROM ID1149")
        cur.fetchone() and printsqlresults (cur.fetchall())
    #SYSTEM
    if checkTableExists(cur, "ID6005"):
        cur.execute("SELECT eventid,eventdesc,date,timeutc FROM ID6005")
        cur.fetchone() and printsqlresults (cur.fetchall())
