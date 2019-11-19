# AWS Certified Solutions Architect Professional Course
> Linux Academy - Instructor: Adrian Cantrill

## 5 Domains
|Domain|% of Examination|
|---|:---:|
| 1. Design for Organizational Complexity| 12.5% |
| 2. Design for New Solutions | 31% |
| 3. Migration Planning| 15% |
| 4. Cost Control| 12.5% |
| 5. Continuous Improvment for Existing Solutions| 29% |
| __Total__| __100%__|

### Domain 1: Design for Organizational Complexity  
    1.1. Determine cross-account authentication and access strategy for complex organizations (for example, an organization with varying compliance requirements, multiple business units, and varying scalability requirements)

    1.2. Determine how to design networks for complex organizations (for example, an organization with varying compliance requirements, multiple business units, and varying scalability requirements)

    1.3. Determine how to design a multi-account AWS environment for complex organizations (for example, an organization with varying compliance requirements, multiple business units, and varying scalability requirements)
 
### Domain 2: Design for New Solutions  
    2.1. Determine security requirements and controls when designing and implementing a solution

    2.2. Determine a solution design and implementation strategy to meet reliability requirements

    2.3. Determine a solution design to ensure business continuity

    2.4. Determine a solution design to meet performance objectives

    2.5. Determine a deployment strategy to meet business requirements when designing and implementing a solution
 
### Domain 3: Migration Planning  
    3.1. Select existing workloads and processes for potential migration to the cloud
    
    3.2. Select migration tools and/or services for new and migrated solutions based on detailed AWS knowledge 
    
    3.3. Determine a new cloud architecture for an existing solution
    
    3.4. Determine a strategy for migrating existing on-premises workloads to the cloud
 
### Domain 4: Cost Control  
    4.1. Select a cost-effective pricing model for a solution
    
    4.2. Determine which controls to design and implement that will ensure cost optimization
    
    4.3. Identify opportunities to reduce cost in an existing solution
 
### Domain 5: Continuous Improvement for Existing Solutions  
    5.1. Troubleshoot solution architectures
    
    5.2. Determine a strategy to improve an existing solution for operational excellence
    
    5.3. Determine a strategy to improve the reliability of an existing solution
    
    5.4. Determine a strategy to improve the performance of an existing solution
    
    5.5. Determine a strategy to improve the security of an existing solution
    
    5.6. Determine how to improve the deployment of an existing solution

## AWS Accounts
* Principal &rightarrow; Identity that can authenticate on the account
* Authentication &rightarrow; Descrete service provided by IAM
* IAM &rightarrow; Provides Identity and permission store
* root &rightarrow; Has full and unlimited access and permissions
* IAM users have no permissions by default
* VPC has a lmited blast radius

## Regions, AZs, and Edge Infrastructure
* Region (e.g. US, Europe) &rightarrow; Availability Zone (e.g. US East, US West,etc)
* Regions are their own entities
* AZ provides fault isolation 
* AZ isolated yet physically close
* Region spread apart by 1000s of miles
* Regions provide GeoPolitical issues (data in the US / Europe)
* Edge Location have dataventers (e.g. Phx NAP in Phoenix)
* Edge has faster delivery as it's closer to the customer

## High Availability, Fault Tolerance, and Disaster Recovery
* HA &rightarrow; Offers the ability to recover from a failure
* HA &rightarrow; Can minimize the fault, still might assume outage
* HA &rightarrow; Could be autoscale and AWS will build new VM, short downtime until instance is rebuild
* FT &rightarrow; true FT systems have multiple redundanceies 
* FT &rightarrow; usually setup in active-active fashion
* FT &rightarrow; (e.g. online store) User token can not be on single server
* FT &rightarrow; needs LB with cash or different solution 
* FT &rightarrow; much more demanding and expensive to build
* DR &rightarrow; designed to happen if HA AND FT do not occur
* DR &rightarrow; (sample a parachute in an airplane)

## Disaster Recovery: RPO and RTO
* RPO ( Recovery Point Objective )
* RTO ( Recovery Time Objective )
* RPO &rightarrow; Time between disaster occures and the latest backup exists
* RPO &rightarrow; defines the acceptable dataloss (e.g. backup every 10 minutes, vs once a day etc.)
* RTO &rightarrow; Time between incident and full restore
* RTO &rightarrow; has many non technical values (e.g. needs someone available to do the job, needs the required hardware to fix, need someone to test, etc)
* RTO &rightarrow; hot standby or backup database, AWS offers many features for this

## Data Persistence
* Ephemeral (e.g. Instance Store Volume, Amazon ElasticCache)
    * Data that is generally local to a resource and is lost when that resource is powered down
* Transient (e.g. Queue)
    * Data that exists in a form while it's passed between sources
* Persistent (e.g. Amazon EBS, Amazon EFS)
    * Data that is durable and survives power events (start; stop; restart)*

## The OSI 7-Layer Networking Model
* 7 Application (HTTP)
* 6 Presentation (<-->)
* 5 Session (Port 443)
* 4 Transport (TCP/UDP - protocols)
    * TCP (Transmission Control Protocol) - reliable delivery
    * UDP (User Datagram Protocol) - fast but not reliable
* 3 Network (10.0.1.0 - IP address)
* 2 Data Link (ae:43:4f - MAC address)
* 1 Physical (0010010100 - binary)

e.g. ping/ICMP -> layer 3

>The OSI 7-layer networking model splits network communiction into isolated layers. The protocols at any given layer can be changed or updated without affecting any of the other layers. Communication can occur between hosts as long as both hosts are using the same protocol at the same layer

## IAM Overview
* IAM - Identity & Access Management Service
* there are several kinds of IAM entities
    * Users
    * Groups
    * Roles
    * IAM Policies
    * Authentication attributes (username, password,Access Keys, MFA etc)
* Allows you to maintain records of identity
* Provides Authentication
    * Username and Password (GUI)
    * Access Keys (for CLI and API)
* Access Key and Secret Access Key Pair
* Both are long term credentials (do not expire)
* SSH keys can be added
* IAM users are granted permissions via attached  policies
* You can attached a JSON file directly (Inline policy)
* A 'Group' is not a ___real___ identity
    * __Users__ and __Roles__ are __real__ identities
* Any new IAM users by default have no rights
* IAM is implicit deny, so there is no access
* DENY __ALWAYS__ overwrites any ALLOW
* IAM provides identity services by coordinating with STS (Security Token Service) to allow Identity Federation 
* IAM restricted to 5000 entities
* [Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html)
* Best Practise:
    * Delete your root access keys
    * Activate MFA on your root account
    * Create and use an IAM user with Admin privilages instead of the root account
    * create individual IAM users
    * User GROUPS to assign permissions
    * Follow the 'principle of least privilage'
    * Apply an IAM password policy 

## Identity and Resource Policies: Part 1
> https://github.com/linuxacademy/aws-csa-pro-2019/tree/master/01_accounts/IAM/Identity-and-resource-policies
* IAM policy is basically a JSON file
    * 3 elements
        * fact
        * action
        * resource
    * Simple policy:
    ``` json
    {
        "Version"  : "2012-10-17",
        "Statement": [
            {
                "Effect"  : "Allow",
                "Action"  : "s3:*",
                "Resource": "*"
            }
        ]
    }
    ```

## Identity and Resource Policies: Part 2
* (Identity) Policy Condition gives more flexability
* IAM policies can also use variables
* [Variable Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
* Additional condition Policy
* Resource Policy
    * Principal (mandatory for resources policy)
    * Used when you want to papply it to many identities

## IAM Roles and Temporary Security Credentials: Part 1
* Roles vs Users
    * Roles is not an identity you can log to
    * no user name or password or credentilas
* A role reporesents a certain function
* A role allowes a Lambda function to interact with AWS on your behalf
* A role assumes an existing identity
* A role exists of 2 components
    * trust policy - only used when assuming a role
    * permissions policy - what access is granted
* [Reference Metadata](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-instance-metadata.html)
* Role Credentials
    * do expire ( not long term)
    * you can renew them
    * dynamically generated and not associated with a specific identity
    * linked to role, but not assigned
    * can't invalidate permissions (but can revoke session)
    * principal has to be an AWS service
    * assume cross account role that exists through the root account

## IAM Roles and Temporary Security Credentials: Part 2
* AWS uses IAM to interact on behalve with IAM roles
* you can use cli and store the credentials
* roles are supposed to be assumed by multiple people
* permissions are checked on every authentication
* permissions can be revoked
* you can not log in as a role

## Cross-Account Access: Resource Permissions vs. Cross-Account Roles
* ACLs [legacy /  avoid of possible]
    * legacy access control
    * can be applied to buckets
    * ACL need to be used of you want control object access
* Bucket Policies
    * Bucket resource policy
    * can give 'putobject' permission but still will not see it because of permissions
* Cross account access (Using IAM roles) [prefered way]
    * objects are owned by the role
    * permissions are managed by IAM, not S3

#### Resources:
[Reference 1](https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html#example-bucket-policies-use-case-8)

[Reference 2](https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources/)

## AWS Accounts and AWS Organizations
* AWS Consolidated Billing 
    * Ability to link accounts
    * while completely seperate account, all billing goes through the 'billing' account
    * Master account is needed ( you can only have one per organisation)
* Consolidated Billing VS All Features mode
* Consolidated Billing -> Single  monthly bill
* Consolidated billing helps with volumne discounts
* All Features supportes SCP (service control policies)
    * can apply restrictions on a single account
* [Refences](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/useconsolidatedbilling-discounts.html)

## Service Control Policies
* JSON documents
* master accounts can be placed anywhere
* SCP applied to master don't do anything
* Avoid using the master account for any services
* master can be used for user and billing purposes
* SCP contains explicit ALLOW and DENY statements
* SCP does not set the permissions itself, it just enforces it

## AWS Account Limits
* [Service Limites Reference](https://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html)
* some of the limites can be changed
* to change it you have to open a ticket with AWS
* some might get approved, some don't

## AWS Support Tiers
* [Support Plans](https://aws.amazon.com/premiumsupport/plans/)
* Support Plans
    * Basic (everyone gets this)
    * Developer
        * only minimal more support over basic
        * Business Hours only
        * only one main contact
    * Business
        * comes with full set of checks for trusted advisor
        * 24/7 email and chat
        * unlimited cases and unlimited contacts
        * contextual guidance
        * AWS Support API
        * proactive programs extra
    * Enterprise
        * comes with full set of checks for trusted advisor
        *  24/7 email and chat
        * unlimited cases and unlimited contacts
        * consultive review
        * AWS Support API
        * proactive programs included
        * Dedicated Technical Account Manager (TAM)

## AWS Config
* Configuration Management System
* tracks configuration of resources over time
* why use it?
    * able to monitor configuration over time
    * able to check resources for compliances / baseline
* Configuration recorder tracks every change
    * enabled per region
    * will need required permissions 
    * needs associated IAM role
* AWS Resources
    * any supported resource that AWS config support
* configuration item
    * record of the state of an item
    * exist from the moment recorder was enabled
* no longer limited to single snapshot but can evaluate changes over time
* configuration stream
    * all configuration changes can be used with SNS to pipe into Lambda to react upon it
* Configuration Rules
    * you can design rules to ensure to ensure that config is compliant
    * analyze weather any additional ports have been added / changes were made
    * AWS config will provide FROM and TO change 
    *  Cloud Trail  (logging) integration is availalbe

## AWS Service Catalog
* Implemenet IT servive catalog
* allow to package services and provide them to the business
    * can be for internal or external for customers
* descibes all services and software you offer
* like an online store, offers product
* Portfolia contains product and template
* Service Catalog offers portal to enduser
* you can set permissions on the porfolia and for the product
* similar to Cloud formation / Stack roles
* templates can be restricted via JSON
    * e.g. on default setting such as instance size
* allows role separation ( does not have to give create rights to a service catalog end users)

## Resource Billing Modes: On-Demand, Reserved, and Spot
* On-Demand
    * default billing model
    * ideally for ADHOC (e.g. prrof of usage)
    * provides no discount, no suprises, per hour
    * does not provide any advantages or disavantages regarding startup
    * using when not sur eabout load or usage duration
* Reserved
    * 'all upfront, 'partial upfront', or 'no upfront'
    * you're not linking an EC2 instance, just to the compute resource
        * e.g. you purchase 12 hours for EC2
    * able to pull reservation to different accounts
    * good when you can predict longterm unchangable usage
    * can resrve by region or by availability zone
    * reserving capacity in AV zone
        * get a high priority startup (only in AVZ, not region)
    * mainly for steady, long term stay
    * bigest steady discount
* Spot
    * ideally suited to sporatic workload
    * ok if you can tolerate interruption
    * is not good for all scenarios
    * AWS is tracking spare capacity
    * resouce access assigned per spot price
    * sometimes spot price can go over on-demand price if low availability
    * its per availability zone and per instance type
    * track spot price and bitting
    * spotfleet to pool instances
    * [REFERENCE1](https://aws.amazon.com/blogs/compute/new-amazon-ec2-spot-pricing/)
    * [REFERENCE2](https://github.com/open-guides/og-aws#billing-and-cost-management)
    * [REFERENCE3](https://aws.amazon.com/blogs/aws/amazon-ec2-update-streamlined-access-to-spot-capacity-smooth-price-changes-instance-hibernation/)

## Identity Federation
* AWS accounts are separate
* if IAM account created in AccountA , AccountB would be a different IAuser
* with identity federation you can give both accounts
* create an external entity (3rd party) that is trusted that verifieaccess
* __AssumeRoleWithWebIdentity__ is an API call
* IAM Security Token Service (STS)
    * allows you to create a temporary security credentials
    * are short term and can time out
    * once expired that can no longer be used
    * when requested via STS API call returned object:
        * Session Token
        * Access Key ID
        * Secret Access Key
        * Expiration TimeStamp
* Web Application Federation PlayGround (demo from AWS)
    * Google Website (Google Federation)
    * Google is asking to verify that it is ok to provide info
    * Click allow
    * if already logged into google will forward the token
    * large number of users -> always needs federation
    * less admin overhead for IAM user management
    * no stored credentials
    * assumeroleWithWebIdeneity (can't access the console with that)
    * done with SAML, open standard
    * SAML flow a but different
    * __AssumeRoleWithSAML__

## IAM Permissions Boundaries
* Similar to Service Control Policy
* defines the max set of permissions an identity can have
* can be applied to IAM user or IAM role
* IAM -> Choose user -> Click 'set country' -> create boundry policy (JSON)
* common use case is to permit permissions delegation
    * give specific user to give permissions
    * give user full access to this 
    * set bounrty to only all them to do that
* [Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)

## Policy Evaluation Logic
* how to find which policies actually apply with multiple policies
1. Boundaries first
2. then AWS checks if you have chosen a subset of permissions for a STS:AssumeRole
3. Final effective permissions are a merge of dentity, resource and ACL
* __DENY -> ALLOW -> DENY__
* IAM Policy Evaluation
    1. Organization Boundaries
    2. User or Role Boundaries
    3. Role Polices
    4. Permissions

## VPC Basics
* Virtual Private Cloud (VPC)
* 3 Zones
    * Private Networking (VPC or on prem)
    * AWS Public Zone (AWS piblic services,[s3 bucket,DynamoDB,CWLogs])
        * seperate zone
    * Public Internet (everything that is not AWS)
* AWS Public Zone accessable both from within AWS and internet
* every account has it's own seperate VPC (completely isolated)
* you can not switch to a new VPC as default but you can create new VPCs
* Class A / 10.10.0.0/16 CIDR space
* you can also add IPv6 for the VPC
* DHCP optionset 
* if you want to change DHCP optionsets , you have to create a new one
* VPCs are added to subnets
* be familiar with subnets 
* each subnet uses 5 uses addresses
* no overlap between side ranges
* use different ranges for ever VPC
* each subnet can only have one Availability Zone

## AWS Resource Access Manager (RAM)
* You can create a subnet to share VPC resources
* you have to enable sharing in the organization
* all features should be enabled (removes admin overhead)
* While AZ have the same name, they might be pointing to different resources
* Availablitz Zone (AZ) ID is persistent resource IDs
* If subnet is shared (shared from [```owner```]) and shared with [```participant```]
* AZ names are diffrerent between accounts (use consitant AZ name)
* Billing
* Owner
    * is reposible for transfer charges
    * pays for VPC resources
* Participant
    * pay for what you create
* RAM not limited to the same org, but shared products (subnets are only allowed to be shared with the same org)
* subnets can't be shared in default vpc
* you can reference group ID but you can not launch resources as it's owned by the owner, not the participant account
* RAM is new and changes how VPCs are used
* changes a lot of the traditional architecture

## VPC Routing
```
IP addressing in VPC (assuming 10.0.0.0/24)
10.0.0.0   - Network Address
10.0.0.1   - VPC Router (network+1)
10.0.0.2   - DNS (network+2)
10.0.0.3   - Reserved for future use
10.0.0.255 - Broadcast
```

* VPC router
    * every VPC has a virtual router (operates per VPC)
    * IP is network+1 IP address
    * default gateway
    * provided as a service
    * configured via route tables
    * has a main route table
    * route table is associated with all subnets that don't have a custom route table
    * starts with single route (local route)
    * always has a CIDR IP by default to provide internal access
    * Route Priority
        * the higher the CIDR (/16) number is, the higher priority it is given
    * you can add static routes or add route propagation
* Security Groups
* Network ACLS

## Network Access Control Lists (NACLs)
* provide critical securitry functionality
* provide stateless security filtering
* every subnet can only have one (default) or custom NACLS
* they allow traffic through both ways (unless specifically configured)
    * AWS wants you to use Security Groups
* 2 Rule Sets
    * Inbound / Ingres (traffic originates outside and is destined for resources inside)
    * Outbound / Egrees (originates inside and destined outside ot Public AWS Zone)
* IP communication is a 2 way communication
* network ACLS treat replies as part of outgoing traffic
* stateless (can't distinguish between reply and new connection)
* has both advantages and disadvantages
* You have to take the return communication stream into account
    * On every network ACL where you are restricting traffic types, you need to add a rule
    * Use a custom TCP rule
    * Port Range 1024-65535 (ephemeral ports)
    * might want to add UDP rules
* NACL explicitly ALLOW or DENY
* NACL have an implicit DENY rule
* NACL are processed in order (after rule #)
* once rule is matched it stops processing
* keep processing order in mind
* for DDoS add low number deny rule
* NACLS are linked to a subnet (edge traffic when crossing subnet)
* traffic between subnets there are going to be 2 NACL (original outbound, destination incoming NACL) and vice verso on response traffic
* NACLs would not effect traffic between the same subnet 
* if you want to explicitly deny traffic you have to use NACLs
* Limitations
    * can only address IP or IP range or CIDR blocks
    * can't reference logical AWS resources
    * network level only
* certain services can not user Security groups and thus need to use NACLs

## Security Groups (SGs)
* Security filtering feature
* applied to __```network interfaces```__ (multiple or individual) within VPC
* Every VPC comes with a default SG
* Every SG has 2 rules (inbound / outbound)
* Security Groups are __stateful__
    * regards reply traffic as part of the connection
* don't have the ability to restrict return traffic
* there is no order, they are evaluated at the same time
* SG are not allowed to explicitly deny
* SG have a default hidden explicit deny
* SG can not explicitly deny traffic
* You could not have a rule allowing traffic, but to actually DENY the connection you'd need a NACL denying it
* you can reference other logical AWS resources
* less admin overhead because of that
* functional / role based security

## Public vs. Private Subnets, Internet Gateways, and IP Addressing: Part 1
* Gatewaytypes
    * Internet GW
    * NAT GW
    * Bastion Host 
    >An EC2 instance that sits in a public subnet (jumphost like)
    > 
    >A server whose purpose is to provide access to a private network from an external network, such as the Internet. Because of its exposure to potential attack, a bastion host must minimize the chances of penetration
* AWS does not per se distinguish between private and public subnet
* Subnet by default is private
* For public subnet
    * VPC subnet needs an Internet Gateway attached
    * needs a routetable with a default route pointing to the gateway
* [SSH with Putty Reference](https://linuxacademy.com/blog/linux/connect-to-amazon-ec2-using-putty-private-key-on-windows/)

## Public vs. Private Subnets, Internet Gateways, and IP Addressing: Part 2
* NAT Gateway
* (Internet Gateway is a NAT Gateway ,statiuc nap translateing form private address to public address) 
* Bastion has no public IP address, the internet gateway handles translation
* NAT gateways have a single public ipaddress for traffic going out
* NAT gateways translate every internal IP to a single public IP address
* NAT GW requires an elastic IP address (static ip address)
* You can also use your own IP address (if you own any)
* NAT GW are not completely HA
* If you want true HA for NAT GW you, you'll need one in each AZ
* NAT GW allow outgoing and return traffic, but not incoming traffic
    * NAT GW scale with load
    * if you want true HA you need one per AZ
* Create a route table and associate each with the correponding subnet
* Ensure all route tables are pointing the default route to the gateway for the subnet
    * e.g. Subnet A, needs route table default route to gateway  on NAT GW A
* default for custom created ACLs is DENY all

## Egress-Only Gateways
* Allows __outbound__ only 
* IPv6 (all addresses are public and public routable)
* you can't use NAT GWs with IPv6
* functions the same way as a internet gw
* any ec2 with ipv6 can talk out, but can't talk back
* basically provides 'private' addresses
* Adding IPv6
    * Add IPv6 CIDR to the VPC
    * then split network and add the subnet
    * need to do IPv6 subnetting
    * [IPv6 Subenetting](https://www.crucial.com.au/blog/2011/04/15/ipv6-subnet-cheat-sheet-and-ipv6-cheat-sheet-reference/)
    * [IPv6 Subenettingv2](https://community.cisco.com/t5/networking-documents/ipv6-subnetting-overview-and-case-study/ta-p/3125702)

## DNS in a VPC 
* DNS is network+2
* EC2 instances build to run as DNS replay (as workaround)
* AWS implemented ```Route53``` to address this
* Public DNS entry
* Private DNS entry
* Private DNS entry can overwrite Public entries
* Route53 can create Hosted Zones (public and private)
* Route53 Resolver (acts as a relay / managed DNS servers)
    * can be accessed to and from external networks
    * Endpoints can be used to talk to talk to and from external networks and ```non VPC``` networks
    * Inbound endpoint
        * Route53 Resolver allows on prem networks to resolve internal only DNS names 
        * e.g. handy for VPN
    * Outbound endpoint
    * can create fowarding rules
    * will use the outbound endpoint as the origination point for its DNS queries and forwards them through VPN or DirectConnect to the network
* [Route53 reference](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver.html)

## VPC Flow Logs
* Provides visibility in network traffic
* Contains traffic network metadata: 
    * version 
    * account-id
    * interface-id
    * source address
    * destination address
    * source port
    * destination port
    * protocol
    * packets
    * bytes
    * start time
    * end time
    * action (accept / reject)
    * log-status
* Does **not** actually log IP traffic, ```just metadata```
* Certain kinds of traffic is **not** logged:
    * DHCP 
    * AWS DNS
    * metadata queries
    * License Activation Requests
* Places monitoring points at 3 different levels:
    * VPC level
    * At the subnet level
    * At the ENI level (TO/FROM) [Elastic Network Interface]
* Flow Logs are put into ```CloudWatch Logs``` or ```S3 Bucket```
    * S3 Bucket gives additional tooling advantage 
* To Enable -> VPC -> FlowLogs -> Create Flow Log 
* Filter can be set to:
    * Accept
    * Reject
    * All (this is generally prefered for troubleshooting)
* Flow Logs need an associated IAM Role to interact with the CloudWatch Logs
* **Not** real time
* Could have multiple Reject/Accept entries depending on the NACL and SG settings</br>   (e.g. NACL allows but there is no matching SG to allow it)

## Using VPC Endpoints
* VPCEndEndpoints allow access to the AWS Public Zone
* There are 2 kinds of Endpoint Gateways
    * Gateway Endpoint
        * logical GW entity (don't exist in the subnet)
        * are referencable in route tables
        * specific to service and region to service
        * you can restrict resources to only be accessable form certain VPC endpoints
        * instead of traffic going to an internet gateway, traffic is going via the gateway endpoint and thus no internet access is needed
        * NAT gateway is needed for ineternet access
        * Highly Available
        * vpc based gw objects
        * use IAM policies to restrict
        * SQS hostname by default applications use hostnames that resolve to the public gateway name
        * support S3 and Dynamo DB
        * GW Endpoints have be **WITHIN** the VPC to be utilized
    * Interface Endpoint
        * does not use routing tables
        * puts a physical entity in the subnet
        * do occupy a specific AZ
        * uses private link (carry traffic to 3rd party)
        * needs security groups
        * provided with several DNS name
        * resolves to internet endpoints 
        * has unique DNS names with one that is just for the region
        * elastic endpoints
        * are accessible outside of the VPC
* you can add Route53 to resolve external interface names to internal IP
* Endpoints support about 10 gpbs throughput (can be raised)

## Peering VPCs: Part 1
* VPC peers connect VPCs
* provide high performance, resilient and easy to implement solution to link VPCs on a network level
1. Create VPC Peer Object
2. Logical Gateway resource
3. configure the route table on both ends to allow communications
4. ssh -A (ssh passthrough)

* Every VPC Peers gets a unique ID
* edit the route table on both VPCs
* As long as in the same region, you can reference another security group (logical referenceD)

## Peering VPCs: Part 2
* Routing is not transitive
* AWS Transit gateway to make connectivity easier
* You can allow DNS resolving spanning the VPC
* can't have overlapping VPC

## AWS Site-to-Site VPN
* AWS VPN (Hardware VPN)
* VPN use pulic internet as transit path, fully encrypted
* works over IPv4
* VPN vs Direct Connect
* VPN Connection Components
    * Customer Gateway (represents a phyiscal hardware capable of IPSec)
    * Static Routing ( need to add VPC cider and need to provide home network range)
    * can use dynamic VPN via BGP ASN (can use private ASN)
    * VPG ( virtual private gateway) can only connect to a single VPC
    * can act as endpoint for multiple instances
    * VPN connection links the VPG and the cutomer gateway
        * single tunnel between the tunnel endpoints (no HA)
        * full resiliance with 2 tunnels in different AZ
        * full HA, create a VPN connections between 2 different Customers and have 2 tunnels foreach gateway
    * this does require BGP (border Gateway protocol)
* AWS Provides configuration file to download ( will proivde all the info you need to setup the VPN)
* VPN is fast and easy to setup, Direct Connect takes a long time to setup
* VPN is cheap especially for sporatic or low usage
* VPN does cost per hour and has egrees traffic charges (outgoing data)
* egress cost is higher than direct connect
* VPN performance is limited by the customer's router (both in CPU and bandwidth)
* VPN performance does vary as connection is dependent on the public internet
* local route always takes priority
* the higher the prefix / value has priority
* static routes take preference
* routes learning from BGP/direct connect
* static VPN
* Direct connect is prefered over VPN

## AWS Direct Connect Architecture
* physical connection technology
* Competitor to VPN
* Direct Connect is more performant and no other routers in the way
* What speed is needed for DC
    * 1 Gbps
    * 10 Gbps
    * less than 1 Gpbs
* If 1 or 10 Gbps you can order that from AWS directly
* Phyiscal requirements:
    * needs to use single mode fibre
    * needs to be 1000 base Lx
    * or 10 GB based LR 
    * router that supports BGP and MD5 authentication and VLANs
* You get a network port assigned on the on prem location
* Once you get the port you can download a LOA-CFA (Letter of Autherization and Connecting Facility Assignment)
* you will need a router or you can pay someone (ISP) to connect to it
* you will get a cable between your on premises router and the DX AWS router
* if you need less than 1 Gbps, you can order via a partner
* Direct connect will not go through th epublic internet
* more stable than VPN because of the direct link
* Benefits:
    * reduced network cost ( since it's a direct connection you don't use your regular ISP public internet connection, which is more expensive )
    * billed differently (lower rate)
    * good for large datasets
    * take time to provision (from weeks to months)
    * increased consitancy
    * you can us epublic or private interfaces between you and AWs and thus you no longer need a Bastion host
* DX location is depending on the region physically in your area
* virtual interface is assinged to a VLAN ID
* you have to specify if public or private
* you have to specify the BGP ASN number [ASN - autonomous system number]
    * Public VIF (virtual interface)
        * used to allow access only in the same region access
        * now are capable of accessing public zone endpoints in other regions
        * only services in the public zone, no internet access
        * you can access the public zone workdwide, getting better speed  accessing data on the other side of the world compred to a VPN
    * Private VIF (virtual interface)
        * associated with a single VPG and thus a single VPC
        * limited to operating in the same region
* connections made via directconnect are **not encrypted**
    * any transit that is made from on prem to VIF it is unencrypted
    * Workaround, create a public VIF endpoint, create a VPN that runs on top of the VIF, that creates the high performance and encrypted communiction
    * private VIF is a single point connection, and one region only
    * Direct Connect Gateway  
        * new feature
        * global resources
        * create private vifs that are associated with the DCG
        * then you can associate the DCG with Virtual Private Gateways in any region
        * only have to maintain a single private VIF
        * not transitive
        * there is an hourly port charge if the port is active
        * charged for egress traffic
        * VPN can server as backup for Direct Connect
        * you can have multiple DX routers for resiliency

## AWS Transit Gateway
* Gateway Object that adds additional capability over the VPG and VPC Peers
* you can create a transit gateway and attach it to a VPC
* the TG can route in a transitive way, we can setup a hub and spoke architecture
* every spoke is allowed to communicate with any other spoke
* TG is compatable with RAM, thus it can be shared between AWS accounts
* TG support VPC and VPNs (Direct Connect is in planning for 2019)
* reduces network complexity a lot
* needs to be added on a per AZ basis
* It only works per region (global region eventually added)
* can not connect to VPCs in different regions
* can take a bit to create the TG (15 -20 minutes)
* any attachments made, it will propegate the route table without admin overhead
* for static VPNs, you have to add the route manually
* got better HA you can ceate an other Customer Gateway and then 2 VPN tunnels foreach
* you can not reference logical security groups between different attachemnts (VPS)
* supports 1.25 Gbps 
* you can aggregate by adding multiple VPNs
* max 50 Gbps burst per VPC connection
* max 5 transit gateways per account
    * 5 attachments per VPC
* 10.000 routes max
* max 5000 TG attachemnts 
* supports IPv6

## AWS Key Management Service (KMS): Part 1
* KMS is part of IAM
* KMS generates CMKs
* manages security keys in AWS
* helps to manage keys, encryption and decryption
* KMS helps to address seperation of admin responsibility
* CMK (Customer Master Key)
    * once created, capable of de/encrypting small amounts of data
    * up to 4 KB
    * a single CMK can have one or more backing keys
    * has an ARN (Amazon Resource Name) [unique indentifier]
* KMS is a regional service, so each region has its own implementation of KMS
* CMK **never leaves** the KMS service
* KMS manages the keys and they never leave the service
* KMS API operations access only
* stored on specific hardware
* CMK unique per region
* ```aws kms create-key --description 'SAPRO' --region us-east-1```
* Key aliases are regional based
* ```aws kms create-alias --target-key-id $Key_ID --alias-name "alias/sapprokey" --region us-east-1```
* Once a data encryption key is requeste from the CMK, it returns an *encrypted* and a plain text version of the key
* **Best Practise:**
    1. Encrypt data with the plain text version
    2. Discard the key
    3. Store the data along with the excrypted data key in the same place
    * So you always know which key to use to decrpt the data
    * **In return you can:**
    1. Pass CMK the encrypted data key
    2. Decrypt the key using a specific CMK
    3. KMS will return the plain text key you can use to decrypt the data
* KMS does not manage data encryption keys
* There is a link between the CMK and the DEK, but KMS does not maintain records, that's up to you, your service, or your application
* It is **not** best practise to store a copy of the plain text key
* KMS is BASE64 encoded

## AWS Key Management Service (KMS): Part 2
* Envelope Encryption
    * multilayer encryption
    * key is never stored in plain text and you always have to open another envelope to access the key
* KMS can also use your own provided key (not reccomended though)
* KMs comes in 2 variants:
    * AWS managed CMKs - rotated once every 3 years (enabled by default and you can't disable it)
    * Customer managed CMKs - rotated every year
* KMS - reEncrypt operation
    * you can pass KMS some encrypted data and give it a new CMK to use and it will return the data in a newly encrypted state using the new key
    * data is not seen in plain text using this process
    * you can grant those permissions to an IAM role and mever have them see the data
* KMS supports a wide range of permissions
    * 2 roles
        * People who 'admin' the keys
        * People who are using the keys
* Supports roles seperation
    * e.g. give them access to data on S3 but don't give them the rights to decrypt data
    * KMS can also be used with VPC endpoints and isolated VPCs
    * KMS supports full logging (e.g. with CloudTrail)
    * KMS supports the security standard FIPS 140-2 (TLS 1.3) at Level 2
    * You can only interact with KMS using the AWS API 
    * **Not** capable of using industry standard SDKs ( Software Development Kit )

## AWS CloudHSM
* HSM Hardware Security Modules
    * validated and audited piece of hardware which like KMS can generate keys and perform  cryptographic operations
    *  KMS is a managed service provided by AWS, under th ehood it uses HSM
    * There are additionally customer managed on-premises HSMs
        * You have to purchase those devices
        * You have to manage them
        * You have to deal with failures and issues
        * You have to manage physical capacities
        * It's basically EC2 vs Physical servers
        * Specific clients need to have this kind of security and need to provide those clout HSM services
* Applications can take advantage of the HSM services by using Industry Standard SDKs
    * PKCS#11, JAVA Cryptography Extensions (JCE) or Microsoft CryptoNG (CNG)
    * You can't use KMS as it does not support SKD
* On one end there is KMS, on the other there is traditional on premis HSMs
    * Cloud HSM lives in the middle, Cloud HSM injected into VPC, they are private
    * Any application that needs the service commutes via network interfaces and the SDK API
* If you want HA for the HSM you need multiple HSMs provided to multiple AZs
    * you are responsible for round robin between the HSMs
* FIPS 140-2 Level 3 --> Cloud HSM or On-Prem HSM
* FIPS 140-2 Level 2 --> KMS
* Cloud HSM just has an on-demand fee
* specialized and better performance than e.g. an EC2 instance

## AWS Certificate Manager (ACM)
* allows you to create x509 v3 SSL/TLS certificates
* [Refereces](https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html)
* allows you to generate and manage certificates
* native integration with ELB (elastic load balancer), CloudFront, AWS Elastic BeanStalk & API Gateway
* no cost associated with certificates - only the resources they are used with
* certificates automatically renew when actively used with supported services
* integrates with Route53 to perform DNS checks as part of certificate issuing process
* ACM is regional - certificates can be applied to services in the region
* KMS is used - certifcates are never stored unencrypted
* Valid for 30 months by default
* cou need to validate ownership of the domain either via email or DNS entry

## AWS Directory Service
* As actually a Group of Services
    * Amazon Cloud Directory (store of information, not great for indentities)
    * Amazon Cognito (for ID federation, can not be used for traditional directory services)
    * AD Connector (bridge between on prem AD and AWS services)
    * MSFT Active Directory (not great for large scale apps or federations, more expensice then 'simple ad')
    * Simple AD (Samba 4, does not support TRUSTs with MSFT AD, open source)
* AD Connector & MSFT Active Directory & Simple AD
    * -> enterprise style Active Directory or accessories

* Amazon cognito is for webscale applications and provides federation services
    * allows you to pool identity and expands beyond refular federation
    * only used for web and mobile apps
* Amazon Cloud Directory , graph based, amazon based grpah object store
    * used to sotre info and relationships (similar to graph databases)
* Join EC2 instances to the domain via Systems manager

## AWS WAF and Shield
* LOGIC: Internet -> Shield -> AWS WAF -> Edge Endpoint (e.g. API)
* WAF  (Web Application Firewall)
    * control traffic that reaches CloudFront, API Gateway or Elastic Load Balancer
    * traffic is filtered **before** is reaches the endpoint
    * creates a web ACL
    * isolated set of rules
    * conditins match traffic type
    * does it have a specific aspect to it?
    * you can combine them to rules
    * you can define as many rules as you need
    * you can define it globally or regional 
    * allow any request that don't match rules
    * original setpu can take a while to take affect
    * default , allow anything that does not match
    * once applied, WAF changes will be quick
    * geo matches
    * block cross site scripting
    * IP addresses
    * can block by string and regex matches
    * you can add actions to that
    * it's better to filter traffic before it gets to the services
    * matches specific conditions
    * not for large scale web protention
    * does not heuristic or DDoS protection
    * rules need to be specifically defined so lots of admin overhead
* AWS Shield
    * protects against DDoS
    * tcp / udp
    * trying to overload the servers 
    * comes in 2 versions
        * AWS Shield standard
            * 24/7
            * comes for everyone
            * sits at all ingress points
            * powerfull if intergrated with route53 and  cloudfront
        * AWS Shield Advanced
            * $3000 a month
            * wider range of protection
            * more DDoS protection
            * application layer attacks
            * gives you cost protection (if caused by ddos)
            * gives you access to DDoS response team
            * protects elastic IPs

## AWS GuardDuty
* can access data sources from accross AWS account
* logging aggregator
* continuously monitoring AWS account and provides reccomendations
* can create cloud Watch event which cna trigger other actions to mitigate the issue
* Accounts
    * in AWS you have to specify an account for GuardDuty
    * The account can not be the same master account as is used to the AWS console
    * You can have 1 master account and invite several guest accounts
    * an AWS can only a member if 1 GuardDuty master
    * DataSources are sources that feed data to GD
    * GD can ingest CloudTrail event and uses those to keep an eye on it
    * monitors VPC flow logs
    * can look at route 53 logs
    * ingest threat inteligence
    * findings are showin in the consolew
    * GD requires service roles accounts
    * Trusted IP list, it will be reported on
        * you can have a **single** trusted IP list per region per account
        * threatlist lets you define known bad IP addresses
        * 6 threatlists per region per account
        * you can define seperate lists for seperate member accounts
* findings are not in real time

## EC2 Concepts
* Elastic Compute Cloud
* IaaS 
* How to implement it and what is the best way
* every EC2 instance is created from an AMI (amazon machine image)
    * that image has a root volumen
    * 64 or 32
    * HVM
* Starting the process:
    1. select an AMI
    2. Select the storage (instances and EBS), most will have EBS volumnes
    3. Select quickstart
    4. Select an instance type
    5. Be aware what instances are good for which use case
    6. Perform initial configuration
        * spot instance ( be aware when you'd or wouldn't use it)
        * on demand
    7. is on a single AZ, single region, in a single VPC on a single host
    8. pick a subnet
    9. allocate AZ
    10. enable public ip address
    11. placement groups, physical control where the instance gets placed
    12. associate an IAM role (instance profile)
    13. enhanved monitoring (cloudwatch)
    14. Tenancy 
    15. Elastic Inference (deep learning stuff, hardware exceleration)
    16. T2/T3 Unlimited 
    17. Allocate Networking infrastructure
    18. add storage (epheremal storage, or EBS [network based storage] and EFS [elastic file storage])
    19. Add tags
    20. attach security groups ( attaching the group to the primary network instance)
    21. associate a key pair
    22. launch instance

## Creating and Using AMIs
* used to create EC2 instances
* multiple AMI sources (amazon, 3rd party, self maintained AMI)
* AMI Archictecture:
    * AMI is a object container with all the info needd to launch an instance
        * meta data (owner,launch permissions, public, AWS account access)
        * architecture and OS (32 / 64)
        * list of block device mapping for all the volumes
    * you can create an AMI
        * running a create image
        * creates an AMI logical object
        * creates volume snapshots of the EBS volume
        * AMI references those snapshots
        * contains details about the root device name arch, os, all extra block devuce mapping
        * AMI does not consume space, but the snapshots do.
        * AMI are regional based, but you can copy it to a different region
        * New instance can be launched in a new region
        * by default there are no permissions stored on an AMI
        * the creator is the owner of the AMI and has implicit access
        * you can make it public
        * you can give explicitly right
        * AMIs can be sold (marketplace)
            * cost is base EC2 cost + fee define by who shared it
* instance store EC2 that don't consume EBS storage
    * install AMI, you have to bundle a group of files on S3
    * create an AMI that is referencing the S3 bucket
    * take longer to prevision
    * non persistant storage

## Virtualization and EC2 Instance Type: Deep Dive
* AWS Nitro - near bare metal performance
* AWS offers bare metal
* AWS provides a wide range of instances
    * General
    * Compute
    * GPU
    * Memerory
    * Storage optimimized
* if no requirements -> general purpose
    * M type should be the default
    * T burstable CPUs, for low CPU usage, if you run out of credits tou might get charged, standard vs limited,
    * A type, ARM architecture, limited instances

* for compute optimized / CPU
    * C5
    * C5n (advanted networking) / e.g. datalakes 
    * C4
* memory optimized (some come with local storage)
    * R
    * X even higher memory
    *

* storage optmized
    * h high level disk throughput
    * i , large storage but fast I/O , not persistant storage
    * D,
* accelerate performance
    * comes with GPU attached
    * g3, graphics intense compute
    * P3, general, math, etc
    * F, field programmable , offer customizable hardware
* [References](https://aws.amazon.com/ec2/instance-types/)

## EC2 Storage and Snapshots: Part 1
* EBS and instanvce store volumes
    * suceptable to hardware failure
    * no resiliance (unless configured in the OS)
    * when selecting an instance type it will list the storage size and type
    * you can pick from SSD or HDD
* Each type of instance has 0 or more ephemeral storage volumes
    * you can use them singely
    * or you can create a RAID with different performance characteristics
    * are attached to the host
        * if you start and stop and it moves to a different host, the data is gone
            * restarting might keep the data, but it still might be lost
            * coog for caching, but assume you will lose that data
        * use this if you need the highest I/O
    * EBS optimization has always less I/O vs instance store volumes as they are local
    * HDD, SSD or NVME SSD (even faster)
    * can't use it as shared storage 
    * ephemeral storage
    * tied to the host, it's not elastic
* it's for **temp** storage or **high** I/O use cases
* EBS Storage:
    * EBS -> network storage product (runs over networking infratsructure)
    * EBS optimized instances run on dedicated storage networks
    * 4 types of EBS Storage Available:
        * General Purpose [GP2] (SSD) ```should be default```
            * 3 IOPS for every GiB
            * if you need more IOPS you cna burst and use the credits
            * Volume from 1GB to 16 TB
            * max 16k IOPS per volume
            * max throughput 250 MBps
        * Provisioned [io1] IOPS SSD
            * used for mission critical apps that need high iops [e.g. large database workloads]
            * volume size 4 GB to 16TB
            * can be provisioned up to 64k IOPS per volume
            * max throughput 1 GBps
        * Throughput Optimized (HDD)
            * low storage cost
            * use for frequent accessed and throughput intensive  workloads (streaming, big data)
            * cannot be a boot volumne
            * 500 Gb to 16TB
            * 500 MBps & 500 IOPS max
        * Cold HDD
            * lowest cost
            * infrequent accessed data
            * cannot be a boot volume
            * 500Gb to 16TB
            * 250 MBps & 250 IOPS
* EBS -> if persistance is required
* EBS are resistant to failure
* only in AZ 
    * of AZ fails, EBS might fail as well
* you can use snapshots with EBS (regional used)
* you can store them across regions and AZ
* Elasticity is scalable (both in iops and size)
* would NOT use EBS for temp storage
* would NOT use for static content (e.g. picture) [use S3]
* EBS are attached to a single instance
    * you can detach and attach it to another instance 
    * limited to a single one at a time
    * no shared storage between instances
    * EBS can provide high durability 
    * not resiliant across AZ
* snapshot is a backup of an EBS volumne stored on S3
    * 1st backup uses the same amount of storage as the EBS volume 
    * 2nd backup just uses the delta  (change between the snapshots)
* snapshots are point in time and crash consistant
* OS might not backup data to disk
* reccomended -> turn off the instance, snapshot it so there is no data in RAM

* max performance -> instance store volumes (with RAID)
    * fast but not resilient
* EBS has advanced performance characteristics
    * max are lower
* If high durability is needed use S3

## EC2 Instance Profiles and Roles
* Best practise to provide security credentials to the CLI or application that utilizes IAM roles
* any IAM identity can get temp security credentials via STS assume rule
* EC2 instance profile holds the rights 
* whenever you create an ec2 instance, it automatically creates an instance profile 
* it links the functionality of the IAM role with the functionality to the instance
* EC2 instances have metadat if you browse: 
    *  ```http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLENAME```
    * that's where you can get the temporary credentials
    * stored as JSON object
    * EC2 is working with STS in the background to constantly provide the latest credentials
    * you can change the IAM role, but you can not attach multiple
* if created from the console -> it happens automatically
* if created from the API/CLI -> the two steps are distinct and must be done explicitly
* Why associate IAM roles with instances?
    * Whenver you CAN use IAM roles, you should do so
    * IAM roles is prefered
    * All applications should be able to access the meta-data
    * if you want to block access, you need to use an internal instance firewall or some other traffic filtering technology
    * you can't restrict access to the meta data from an external perspective
* When to use AIM roles vs traditional credentials inside instances?
* IP endpoint is an HTTP point, so not encypted, you have to manage the security all the way to the application leve
* in case of an exploit you can reset the credentials by using the 'revoke session' feature

## HPC and Placement Groups
* HPC (High Performance Computing)
* You can launch EC2 instance into a new or existing groups
* only used when you need the MAX performance out of EC2
* Different types of placement groups
    * Cluster Placement Groups
        * logical grouping of instances in a single AZ
        * max performance
        * Can't span AZ
        * **Highest** troughput and **lowest** latency
        * no oversubscribed networking path
        * create placement group first -> then create instances in the group
            * you can't modify an instance group and you might run into capacity issues if you try to add another instance after the fact as there might not be enough resources available to fulfull the cluster need
        * better results if you profivion the same *type* of instances
        * not every instance type supports cluster group
        * are limited to a single AZ
        * but can span a VPC peer 
    * Partition Placement Groups
        * isolated blocks of infrastructure in a AZ
        * districbute instances across an even number of parttions
        * get a better level of resiliance
        * only needed when elevated performance and resiliance needed
        * can't select that via the concole, only via API or CLI
        * limited to 7 running partitions per AZ
        * number of limited by account limit
        * multiple AZ in the same region
    * Spread Placement Group
        * Can operate in multiple AZ
        * are designed for a smaller set of infrastructure
        * highest level of HA
        * ensure all instances are running on different hardware
        * you can add later as it seperates hardware on indpeendent fault domains
        * can only have 7 running instances per AZ per group
* Best Placement Group for Performance -> Cluster Placement Group
* Best Placement Group for Resiliance -> Spread Placement Groups
* 10 gig flow between isntances
* if flow between placement group and other instances limited to 5 GB

## Custom Logging to CloudWatch
* by default cloudwatch monitors a lot of AWS 
* external to the instnace
    * see things like disk, cpu, mem, network bandwidth etc
    * gathered from the EC2 host
    * you can not get the information from inside the instance
    * CloudWatch Agent does provide insight from inside the instance
* IAM Role needs permissions for to read/write CloudWatchLogs and and CloudWatch as well as the Systems Manager
* Manual Installation
    * connect to instance
    * download the latest version
    * install the package
    * create config file ```amazon-cloudwatch-agent.json``` 
        * can be used to deply config at scale
        * configure agent to send additional information to CF
    * import the JSON and start the agent
* Install it via Systems Manager
    * Services -> Systems Manager
    * run a command ```AWS-ConfigureAWSPackage```
        * Actions -> Install
        * Name -> AmazonCloudWatchAgent
        * Version -> latest
        * Select Instance
    * parameter store dto deply configureation to many endpoints
    * use the same JSON as the manual install
    * run command ```AmazonCloudWatch-ManagerAgent```
        * Actions -> Configure
        * Optional Configuration Source -> SSM
        * Optional Configuration Location -> Parameter
        * Optional restart-> yes
        * Select Instance
* After the agent is setup we can see the logs in CloudWatch
* This data can only get obtained from **inside** the instances
* the config is stored insyste systems manager

## Containers 101
* ECS ( Amazon Elastic Container Service)
* Containers
    * small isolated environment
    * designed to run an aplication within it
    * it contains the application together with any libraries and other dependencies
    * Best Practice is that it contains specific versions of those libraries and dependencies for stability
    * a container is consistant and aways has the same known working version of applicationa nd libraries
    * containers allow delevopers to write code that will always work in a given environment
    * it allows them to ship the environment in a known working state to be run at its destination
    * it enables true portability
    * it allows applications that require differernt versions to run on the same host without conflits because everything is isolated
    * similar to virtualization however with some critical differences
        * Virtualization
            * Infra -> HyperVisor -> VM -> OS -> Application
        * Containerization
            * Slightly less secure
            * Infra -> OS -> Application (Container)
            * no need for multiple OS
            * uses by far less resources
            * faster than VMs to start up
            * containers can start in seconds
            * kernel level assistance (e.g. Docker)
            * docker file 
            * Container image ( similar to a disk)
            * docker file specifies the base image (e.g. Ubuntu)
                * additional line, software installation creates a different file system
                * each only represents the configuration change
                * container layers can be re-used
            * container images are like a disk
            * take a container image and make a container
            * images are stored on container images
            * take an image and create a container 
            * containe can have mappings
            * container can access AWS services and other resources
            * container is a fully fledged entity
            * internal ports can be mapped to internal or external hosts
                * e.g. multiple apache containers using port 80
            * designed to be portable
            * can be deployed on any **compatable** container host

## ECS Architecture
* Elastic Container Service
    * Cluster -> collection of compute resources to host the containers as well as the definitions of the containers
    * Task defnition -> configuration file that specify what ECS should do
    * A task can cause a container to be initialized
        * 2 methods to launch a task:
            * EC2 -> traditional start
            * designed to operate a container
            * ECS agent communicates with the ECS service
        * FarGate
            * FarGate Launch type
            * managed service that will launch containers for you
            * each task is isolated
            * no need to manage the operations
            * AWS VPC networking mode only
* ECS Architecture
    * Cluster:</br>
    Are groupings of tasks and services inside ECS. They cna be managed EC2 instances, or AS managed via FarGate. Self-managed clusters can be scaled, can can use on-demand or spot pricing
    * Service:</br>
    Services allow additional an ECS admin to maintain a specific number of task instances whthin an ECS cluster. SErvices allow load balancing accorss tasks using a ELB and allow configuration of scaling and availability
    * Task definition:</br>
    Desfines the task, contains the container definition(s). configures how the container interacts within ECS. The name, network mode, the execution role, and the Launch type. Task definitions can contain multiple containers.
    * Container definition:</br>
    The part of a task definition which configured the capabilities of the container the task operates within the container image, the memory limits, any port mapping, storage, GPU attachemnts and such more
* [ECS DeepDive Course](https://linuxacademy.com/cp/modules/view/id/261)
* Networking modes:
    * nom -> no networking access
    * bridge -> internal networking (software defined)
    * host -> maps diretly to the host networking (fast but limited port per host)
    * AWS VPC -> maps network interface directly to the container (FarGate only)
* Windows types only supports NAT

## ECS Security
* DEMO
* uses security groups between container for AWS vpc network rule
* you can always use network ACLs, but traffic needs to be between subnets for thme to work
* provide permissions to container hosts as well containers
* fargate -> permissions given to tasks (tasks only)
* EC2 types -> tasks, contaer and container hosts
    * instance role gives ecs permissions (also to log to cloudwatch logs)
    * IAM role
    * self managed container hosts
    * AWS logs drivers (needs correct permissions via role attached to container instance)
    * role can be attached to task
        * via IAM role
        * you want to limit role only to permissions you need
        * task role
* you don't manage the conainer hosts with fargate
* [aws log driver](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html)
* [IAM Roles for Tasks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)


## Serverless and Event-Driven Architectures
* Serverless
    * event driven
    * capable of scaling
    * only consume resources when a specific event occurs
* Use products delivered as a service (e.g. S3) rather than servers
* more cost savings and scalable
* can react to changes
* event drive can be super automated
* Lambda can act uppon tasks
* only consumes resources when utilized
* e.g. dynamo db, SQS, lambda, APi gw, etc

## Lambda Architecture: Part 1
* Lambda is a function as a service
    * Lambda function (you or web interfaces packages it)
    * Lambda function is actual code
    * Lambda zip is 'compiled' code
    * Lambda should do one activity
    * Lambda  functions have time limits (15 minutes)
    * you can chain Lambda functions
    * 1 tasks, do it well.
    * if you want to execute a python function, you need the python runtime
    * Architecture
        * Lambda takes code
        * packages the runtime
        * installs it in a sandbox (created and destryed each time the function runs)
        * cold start (takes a bit longer to execute function)
        * sandbox is unique to the lambda function
        * warm sandbox / warm stat is quicker
        * lambda does not need to be aware of infrastructure

* Legacy VS New Arch
    * Legacy 
        * all resources are shared
        * guest OS is installed (e.g. EC2 instances)
        * guest os was dedicated to your account
        * sand boxes were installed and dedicated to each function
        * sandbox could only run a single function, not different functions
        * if the same function needed to be executed parallel, more sandboxes were needed
        * 3 tier (hardware, OS, hypervisor) was shared accross all customers
    * New Arch
        * based on firecracker
        * micro vm product
        * benefit: no longer 3 tier, reduced to 2 (hardware, hypervisor), no longer in between OS
        * micro vms are dedicated to functions
        * easier to manage and better deinsity for AWS
* Lambda is  invoke (manually or response to event source)
* obtains it's permissions via an IAM role
* you can specify environment varialbes (encrypted via KMS)
* capable of receveing event source data 
* work outside and inside of VCP so they may or may not be restriced by the VPC
* ENI attached to worker (might take a bit of time)
* remote now can use multiple ELI functions
* [aws lambda deepdive YT](https://www.youtube.com/watch?v=QdzV04T_kec)

## Lambda Architecture: Part 2
    * event driven and as close to real time as possible
    * inline policy that gives permissions to cheack the ACLs
    * log details to cloudwatch logs
    * given permissio via execution role
    * there is a temp folder, but that data might be lost (not persistant)
    * cold and warm start

## Lambda Layers
* new feature that adds flexibility
* you can load a zip file
* deployment packages need to be added if you use packages that are not default 
* any libraries and dependencies needed to be loaded
* you can add runtime support and packages via layers
* layers are immutable / static
* you can store commonly used packages in layers
* limited to 250 mb
* you can use up to 5 layers per lambda function
* layers are extracted into the /opt folder
* [Layer references](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path)

## API Gateway
* API - Application Programming Interfaces
    * way software components can talk to other software components
* REST API / WEBSOCKET API
    * rest - calling know URL, request insert data and gets respone 
    * websocket more interactive
* API needs to be published and run 24/7 
* good condidate for serverless architecture
* API can interact with backend services
* API is a regional service
* you can use edge locations
* API can be provisioned in VPC
* API has different versions / stages
* update API with a new stage
    * API URL
    * 
    * when clicking on URL you enter the root method
    * API is more about the DevOps certification
    * integration
        * mock intergration (used during dev but no backendfunctionality)
    * API GW can intergrate with Lambda
* [API in production](https://www.youtube.com/watch?v=tIfqpM3o55s)
* [API Caching](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html)
* [API with HTTP Integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-http-integrations.html)
* [API with AWS Integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-aws-proxy.html)
* Protection: you can use WAF (web application firewall)
* does fully log and monitor
* you can use it with w-ray (for debugging and tracing)
* how to update
* what can be integrated
* can be pushed to edge location
* waf can filter apis
* api has direct read and write
* used the web federation playground (?)
* sensitive data should be on the backend, not in the browser
* API can call another API that's in a VPC (extra layer of filtering)

## WS Service Resilience
* Things can be resiliant on the Global, Region or Az level
    * IAM
        * global product
        * not in a specific region
        * 
    * EC2
        * per hardware per AZ
        * EBS valumes are in AZ as well
        * AZ could be 1 or 3 datacenters
        * AZ is a single, isolated fault domain
        * limited to a single AZ
        * snapshot is on S3 and is replicated accross different AZ in a region
            * add global level resiliance
    * S3 resiliant on regional level
        * across 3 or more AZ in the region
        * namespace is global
        * actual data is stored in a particular region 
    * Route 53
        * resiliant accorss regions
        * uses edge locations
    * ELB [load balancer]
        * regional services 
        * created per AZ
    * VPC
        * regional service
        * can operate in all AZ
        * spans the entire region
        * subnets are linked to AZ
        * can create multi AZ architecture via subnets for better resiliance
    * NAT Gateway
        * not truley resiliant by design
        * provides hardware level resiliance
        * Can tolerate hardware failure, but if AZ fails, all are lost
        * put one NAT GW into each AZ
    * Auto Scaling Groups
        * can manage deployment of instances thorough a region
        * accross AZ
        * you can specify min and max
        * automatially done by default, resiliant per region
        *
    * VPN
        * VP Gateway
        * attached to VPC
        * resiliant through AZ

## Stateless Architectures
* Stateless ARchitecture
    * monolithic (unscalable)
        * all components are on one server
        * can't split up
        * can scale and load balance as well
        * limited on functionality
        * e.g. web server would have all, database, session info,web server, service and front end
    * Stateless
        * user ocnnection is tranparently moved to a new instance
        * higher level of resiliance
        * you want to aim to design stateless
        * works well with lambda
* Scaling an appliction
    * vertical
        * increse resources assigned to instance
        * issues -> max size limitation
        * all 'eggs in one basket'
        * can't scale on each component
    * horizontal
        * inceasing or decreating the number of instances
        * session state seperate from instances
        * each componant is individual
        * elasiticity
        * good performance price ration
        * scales up or down depending on demand

## Deciding between Spot and Reserved Instances
* Reserved
    * great savings in billing if you commit to longer term  term (12-36 months)
    * 3 payment options
        * all upfront
        * partial upfront
        * no upfront
    * can be used for EC2 instances, RDS instances, DynamoDB performance and other services
    * can reserve capacity, thus high startup priority
* On Demand
    * default billing model
    * you only pay for what you use
        * per hour
        * per GB
    * good for ad-hoc usage when unsure on the need
    * standard startup priority
* Spot instance
    * ideal for sporadic worloads that can tolerate interruption
    * can be way cheaper than on demand
    * not super reliable
    * can be actually more expensive if there is a high demand
    * lowest startup priority

## Implementing Auto Scaling Groups (ASGs): Part 1
* EC2 feature
* AutoScalingGroups provide HA
* works both ways (outbound and inbound)
* there are different methods to scale
    * AMI baking
        * setup the config needed
        * create an image of a pre-configured machine
        * use this to provision new instances
        * can be done at scale without additional config
        * the more baked in the less configuration options is available
        * not flexiable
        * fast
    * bootstrapping
        * ec2 feature / user data
        * passing in user data on instance build
        * inverse of AMI baking
        * config and setup is performed live
        * changing the user data is easy
        * new config adds processing time
        * more flexiable

## Implementing Auto Scaling Groups (ASGs): Part 2
* featureset provided by AWS
* allows the system automatically to adjust the amount of instances based on the given load
* autoscaling + launch template
* launch config (template) contains the config info of the EC2 instances
* auto scaling group governs where and when instances get deployed
* launch configuration -> configuraiton of the instance
* launch configuration includes info about billing ( on demand, spot.  IAM role,IP address, monitoring,storage, security groups etc.)
* once create a launch config it is immutable ( can't change it)
* if you want to change it you have to create a new one
* then change to launch config in the auto scaling group
* launch config is the legacy way ( not reccomended for new deployments)
* launch template
    * improve instance config
    * similar to launch config
    * need to specify AMI
    * pick instance type
    * select key pair
    * VPC or classic
    * security group
    * network, storage
    * set advanced details
    * launch templates can get edited (new version)
        * can be from scracth or use the existing template as starting point
* Auto Scaling Group
    * 3 different ceriterias for the number of instances
        * desired count
        * max count
        * min count
    * need to define subnets
        * select all subnets
    * need to define VPS / location
    * you can optionally setup loadbalancer
    * has build in health checks (afer 300 seconds / 5 minutes)
        * if you have a complicated bootstrapping this might need more time
    * can send notification to let you know if there is change

## Implementing Auto Scaling Groups (ASGs): Part 3
* self healing if setup right , without user interaction
* scaling policy with extreme lists
    * step scaling lets you fine adjust scaling
    * target tracking 
    * simple scaling 
    * scheduled actions
    * cooldown timers
    * [Referece Termination Policy](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html)
    * monitoring is provided to cloudwatch
    * group metric collection, need to be enable on a per autoscaling group basis
    * can suspend processes and settings in the Autoscaling group
    * you can detach or set an instance on stanby (e.g. for maintenance)

## Multi-AZ Implementations
* nominal cpapcity
* how well the app cna work in reduced capacity
* you can purchase reserved capabilty in the remaining AZ to tolerate failure
* over provision by going above 100% capacity
* spread instances across more AZ
* increasing AZ will decrease the amount of buffer
* if possible provision in at least 2 AZ
* production should be at least 3 for resiliance

## Elastic Load Balancers: Part 1 - Essentials
* accept connections form clients (e..g web browser) and distribute them between one and more backend server
* designed to intergrate with auto scaling groups
* elastic is a HA and and scalable LB
* you can use route53 , but ELB has it's own DNS server
* distributes incoming connections evenly
    * had issues as that is done per AZ, and there could be different resources per AZ
* allows cross zone LB
* Come in 3 forms
    * Classic lb (CLB)
        * cross zone Lb needs to be enabled
    * Application lb (ALB)
        * cross zone Lb enabled by default
        * target group
    * Network lb (NLB)
        * target group
* LB have heath checks build in

## Elastic Load Balancers: Part 2 - Classic Load Balancers
* listeners need to be set up (e.h. http listening)
* the LB has a  security group
* restrict access so the individual server can not be accessed
* index.php / health check
    * can set settings to wait for reposne or the number of fails before it gets marked
* (instances) resources are associated directly
* even distribution of services
* enable cross zone LB
* if the session needs to stick, you can enable stickyness
* session stickytness
    * disabled
    * set to LB generated cookies
    * enable application enabled cookie stickiness (stored on the client)
* listener can also use HTTPS
* you can use SSL offloading (cert is on the LB and connection to server is HTTP)
    * reduces ssl overhead
    * need to deply ssl certiifcate on LB
* you can only have a single listener on a single port
* can't do layer 7 requests
* no high level granularity
* not suggested to be used
* new platform should use application LB
* classic LBs have no public IPs
* do not use the IP, use the A recod name to interact with the LB

## Elastic Load Balancers: Part3 - Application Load Balancers
* 
