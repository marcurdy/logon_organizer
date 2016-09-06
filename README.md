# logon_organizer beta
Pulls login info from RemoteDesktop, TerminalServices, Security, and System (reboot) event logs  
  
Currently uses TZworks's evtwalk to parse evtx logs  
  
Many fields in the different event logs have different field names for the same/similar data.  Many fields have nothing in common.  Normal export utilities output each eventID with different headers thereby making mapping time consuming.  I've taken this approach.
  
1) Pull the CSV for each event id to its own CSV file  
2) Create an SQLite DB on-the-fly and input all eventid's each into their own table  
3) Alter the table and update for enrichment (event id to event desc mapping)  
4) Perform SELECT's to get the information I want  
5) Clearn the output so the CSV imports directly into Excel  
  
Once in Excel, I recommend sorting by date and time, adding the header dropdown filter, and adjusting the column width.  From there, you have the best chance of determining login/logoff times, getting source IP, source user, target user, and target resource.  
  
Pro tips:  
A reboot will clearly log out users, but it won't necessarily be seen as an event.  
Automatic logoffs (4634) occur at the system's discretion and may not reflect an accurate time that the user left.  
Only two sessions can exist simultaneously without the added terminal service license.  
Workstation users can kick off other users.  Server editions do not allow this.  
ActivityID maps from the RDPcoreTS to the RemoteConnectionManager and LocalSessionManager  
Nothing directly maps from Security to the TerminalServices event logs to my knowledge
