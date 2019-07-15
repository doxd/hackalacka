# Active Directory
* Identity
* Access
* Centralized Management
* Components:
  * Domain Services (DS)
  * Certificate Services (CS)
  * Federation Services (FS)
  * Rights Management Services (RMS)
  * Lightweight Directory Services (LDS)

## Domain Services (DS)
* **Users, Computers, Policies**
* Infrastructure for user and resource management
* both the directory information source and the service that makes the information usable.
* Provides:
  * Internal Accounts
  * Authentication - verifying a user's identity on a network
    * Interactive login - grants access to local computer
    * Network authentication - grants access to network resources
  * Authorization - process of verifying that an authenticated user has permission to perform an action
    * SIDs (security identifiers) are issued to security principals when account is created
      * For example: `S-1-5-21-3623811015-3361044348-30300820-1013`
      * `S` -> The string is a SID
      *	`1` -> The revision level (the version of the SID specification).
      *	`5` -> The identifier authority value. (5 is most common, =	NT AUTHORITY)
      * `21-3623811015-3361044348-30300820` -> Domain or local computer identifier. In principle, globally unique.
      * `1013` -> A Relative ID (RID). Any group or user that is not created by default will have a Relative ID of 1000 or greater. RID 500 is built-in default Administrator account
    * user accounts are issued *security tokens* during authentication that include user's SID and all related group SIDs
    * Shared resources on a network include ACL defining who can access the resource
    * Security token is compared against DACL on resource and access is granted or denied. 
    * DACL - defines what a given SID is allowed to do to the object (eg read/write/delete/etc)
    * SACL - defines what events will trigger an audit when performed by a given security principal
  * Security Descriptor Definition Language (SDDL) - format used to describe a security descriptor. Uses ACE strings for DACL and SACL:
    * ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid 
    * ACE for built-in admins for WMI namespaces: `A;CI;CCDCLCSWRPWPRCWD;;;BA`
* Protocol: LDAP
* Requires DNS. DC records must be registered in DNS to enable other DCs and clients to locate the DCs
* Physical Components
  * Data Store
    * contains db files and process that store and manage directory information for users, services, and applications
    * consists of the ntds.dit file
    * stored by default in the dir %SystemRoot%\NTDS on all DCs
    * accessible only through DC processes and protocols
  * Replication
    * Ensures all DCs have the same information
    * Uses a multimaster replication model
    * Can be managed by creating AD DS sites
    * replication topology is created automatically as new DCs are added to the domain
  * Domain Controllers
    * Host a copy of the AD DS directory store
    * Provide authentication and authorization services
    * Replicate updates to other DCs in the domain and forest
    * Allow administrative access to manage user accounts and network resources
  * Global Catalog Server
    * Is a DC that also stores a copy of the global catalog
    * Global Catalog
      * Contains a copy of all AD DS objects in a forest that includes only *some of the attributes* for each object in the forest
      * Improves efficiency of object searches by avoiding unnevessary referrals to DCs
      * Required for users to log on to a domain
  * Read-Only Domain Controller (RODC) 
    * a type of domain controller which holds a read-only copy of active directory database
    * Why? Security - can be used for authentication/authorization, but if compromised cannot compromise entire AD database. 
* Logical Components
  * Partitions
  * Schema
    * defines every type of object that can be stored in the directory
    * enforces rules regarding object creation and configuration
    * objects types
      * class object -> what objects can be created in the directory (ex User, Computer)
      * attribute object -> information that can be attached to an object (ex Display Name)      
  * Domains
    * used to group and manage objects in an organization
    * Can contain many OUs
    * an administrative boundary for applying policies to group of objects
    * a replication boundary for replicating data between domain controllers
    * an authentication and authorization boundary that provides a way to limit the scope of access to the resources
  * Domain Tree
    * a hierarchy of domains in AD DS
    * All domains in a tree:
      * share a contiguous namespace with the parent domain (ex contoso.com)
      * can have additional child domains (ex na.contoso.com, eur.contoso.com)
      * by default create a 2-way transitive trust with other domain
  * Forest
    * a collection of one or more domain trees
    * Forests:
      * share a common schema
      * share a common configuration partition
      * share a common global catalog to enable searching
      * enable trusts between all domains in the forest
      * share the Enterprise Admins and Schema Admins groups
  * Sites
    * an AD DS site represents a network segment where all DCs are connected by a fast and reliable connection
    * associated with IP subnets
    * used to manage: replication traffic, client logon traffic
    * used to assign GPOs to all users and computers in a company location
  * Organizational Units
    * AD containers that can contain users, groups, computers, and other OUs
    * represent organization hierarchically and/or logically
    * manage a collection of objects in a consistent way
    * delegate permissions to administer groups of objects
    * apply policies
  * Trusts
    * Provides a mechanism for users to gain access to resources in another domain
    * Types:
      * Directional -> The trust direction flows from trusting domain (where the resources are) to the trusted domain. The access direction flows from trusted domain to trusting domain.
      * Transitive -> The trust relationship is extended beyond a 2-domain trust to include other trusted domains. Trust flows in both directions.
      * All domains in a forest trust all other domains in the forest
      * Trusts can extend outside the forest
    * Can be:
      * automatic (parent-child, same forest, etc). Always 2-way transitive.
      * established (forest, external)
    * Trusted Domain Objects (TDOs) represent the trust relationships in a domain
    * Shortcut Trusts - reduce access times in complex trust scenarios

## Certificate Services (CS)
* **Service, Client, Server, and User identification**
* MS implementation of PKI *(PKI: set of hardware, software, people, policies, procedures needed to create, manage, distribute, use, store, and revoke digital certificates)*
* Provides: 
  * Identity
  * Non-repudiation
* Components:
  * Certification Authority (CA): an entity entrusted to issue certificates to individuals, computers, organizations, services
  * CA Hierarchy: one root CA and zero or more levels of subordinate CAs
* Can use internal private CA or external public CA. Internal CAs are less expensive and more flexible, but certs are not trusted by external clients
* Digital Certificate: a file with 2 parts
  * Base cert info - name, location, organization
  * Key
* Public and Private Keys
  * Public keys are distributed to all clients who request the key
  * Private keys are stored only on the computer from which the certificate was requested
* Cert Templates
  * define what certs can be issued by the CAs
  * define certs used for various purposes
  * define which security principals have permissions to read, enroll, and configure the cert template

## Federation Services (FS)
* **Resources access across traditional boundaries**
* Facilitates cross-organizational access of systems and applications
* simplified, secured identity federation and Web SSO capabilities
* enables distributed identification, authentication, authroization across organizational and platform boundaries
* Provides: Network Access for External Resources
* An identity federation:
  * requires: a truest relationship between two organizations or entities
  * allows organization to retain control of: resource access and their own user and group accounts
* A Federation Trust is directional like an AD trust. The *Resource Partner* trusts the *Account Partner*
* a web service allows for authentication and granting of tokens to permit access to resources


## Rights Management Services (RMS)
* **Maintain Security of Data**
* Prevent sensitive information from being printed, fowarded, or copied by unauthorized people
* Access and usage restrictions enforced no matter where the information is located
* Provides: Content Security and Control

## Lightweight Directory Services (LDS)
* **Copy of the Structure of DS (? - update def'n later)**
* Essentially AD DS in an empty shell template form
* both the directory information source and the service that makes the information usable (same as DS)
* LDAP - provides flexible support for directory-enabled applications without incurring overhead of domains and forests, without the dependencies and domain-related restrictions of AD DS
* LDS Schema defines the types of objects and data that can be stored in an AD LDS instance
  * Schema Partition - defines the object classes
  * Application Partition - stores instances of directory objects based on the object classes