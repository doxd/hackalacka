### 1
Enumerate following for the dollarcorp domain:
 - Users
 - Computers
 - Domain Administrators
 - Enterprise Administrators
 - Shares 
### 2
Enumerate following for the dollarcorp domain:
 - List all the OUs
 - List all the computers in the StudentMachines OU.
 - List the GPOs
 - Enumerate GPO applied on the StudentMachines OU
### 3
Enumerate following for the dollarcorp domain:
 - ACL for the Users group
 - ACL for the Domain Admins group
 - All modify rights/permissions for the studentx
 ### 4
 - Enumerate all domains in the moneycorp.local forest.
 - Map the trusts of the dollarcorp.moneycorp.local domain.
 - Map External trusts in moneycorp.local forest.
 - Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?
### 5
 - Exploit a service on dcorp-studentx and elevate privileges to local administrator.
 - Identify a machine in the domain where studentx has local administrative access.
 - Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.
### 6
 - Setup BloodHound and identify a machine where studentx has local administrative access.
### 7
Domain user on one of the machines has access to a server where a domain admin is logged in. Identify:
 -  The domain user
 -  The server where the domain admin is logged in.
Escalate privileges to Domain Admin
 - Using the method above.
 - Using derivative local admin
### 8
 - Dump hashes on the domain controller of dollarcorp.moneycorp.local.
 - Using the NTLM hash of krbtgt account, create a Golden ticket.
 - Use the Golden ticket to (once again) get domain admin privile
 ges from a machine. 
### 9
Try to get command execution on the domain controller by creating silver ticket for:
 - HOST service
 - WMI
### 10
 - Use Domain Admin privileges obtained earlier to execute the Skeleton Key attack.
### 11
 - Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence
### 12
 -  Check if studentx has Replication (DCSync) rights. 
 -  If yes, execute the DCSync attack to pull hashes of the krbtgt user. 
 -  If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user. 
### 13
 -  Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access. 
 -  Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI.
### 14
 - Using the Kerberoast attack, crack password of a SQL server service account.
### 15
 -  Enumerate users that have Kerberos Preauth disabled. 
 -  Obtain the encrypted part of AS-REP for such an account. 
 -  Determine if studentx has permissions to set UserAccountControl flags for any user. 
 -  If yes, disable Kerberos Preauth on such a user and obtain encrypted part of AS-REP.
### 16
 -  Determine if studentx has permissions to set UserAccountControl flags for any user. 
 -  If yes, force set a SPN on the user and obtain a TGS for the user.
### 17
 -  Find a server in dcorp domain where Unconstrained Delegation is enabled. 
 -  Access that server, wait for a Domain Admin to connect to that server and get Domain Admin privileges. 
### 18
Enumerate users in the domain for whom Constrained Delegation is enabled.
 -  For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured.
 -  Pass the ticket and access the service as DA. 
Enumerate computer accounts in the domain for which Constrained Delegation is enabled.
 -  For such a user, request a TGT from the DC.
 -  Use the TGS for executing the DCSync attack. 
### 19
 - Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using the domain trust key.
### 20
 - Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using dollarcorp's krbtgt hash.
### 21
 - With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest
### 22
 - Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.
### 23
 - Use DCShadow to set a SPN for rootxuser.
 - Using DCShadow, set rootxuser's SIDHistory without using DA.
 - Modify the permissions of AdminSDHolder container using DCShadow and add Full Control permission for studentx.
