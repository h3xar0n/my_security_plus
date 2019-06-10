### Table of Contents
* [1.0 Threats, Attacks and Vulnerabilities](#10-threats-attacks-and-vulnerabilities)
* [2.0 Technologies and Tools](#20-technologies-and-tools)
* [3.0 Architecture and Design](#30-architecture-and-design)
* [4.0 Identity and Access Management](#40-identity-and-access-management)
* [5.0 Risk Management](#50-risk-management)
* [6.0 Cryptography and PKI](#60-cryptography-and-pki)
* [Protocols and Ports](#protocols-and-ports)
* [Acronyms](#acronyms)

## 1.0 Threats, Attacks and Vulnerabilities

### 1.1 Given a scenario, analyze indicators of compromise and determine the type of malware. 

#### Viruses
#### Crypto-malware
#### Ransomware
#### Worm
#### Trojan
#### Rootkit
* Scanners may detect a file containing a rootkit _before_ it's installed...
* Once installed, a rootkit is very difficult to detect.
* Removal is difficult and the best course of action is to reimage the machine from a known good baseline.
#### Keylogger
#### Adware
#### Spyware
* A common symptom of infection is that your homepage has changed, i.e. spyware has altered your browser settings.
#### Bots
#### RAT
#### Logic bomb
#### Backdoor

### 1.2 Compare and contrast types of attacks.

#### Social engineering
* Phishing
* Spear phishing
* Whaling
* Vishing
* Tailgating
* Impersonation
* Dumpster diving
* Shoulder surfing
* Hoax
* Watering hole attack
* Principles (reasons for effectiveness):
  - Authority
  - Intimidation
  - Consensus
  - Scarcity
  - Familiarity
  - Trust
  - Urgency
#### Application/service attacks:
* DoS
* DDoS
* Man-in-the-middle
* Buffer overflow
* Injection
  - Explain `' or '1'='1' --`
  - Prevented through [stored procedures](#secure-coding-techniques).
* Cross-site scripting
* Cross-site request forgery
* Privilege escalation
  - A domain controller or directory service (such as Active Directory in Windows and LDAP in Linux) is often targeted as part of the privilege escalation or lateral movement phases of an attack. These servers contain all the user accounts, computer accounts, and groups for a particular network. The creation and use of a Golden Ticket are often used as a form of privilege escalation inside a Windows network and exploit a vulnerability in the Kerberos ticketing system used by the Active Directory domain controller.
* ARP poisoning
* Amplification
* DNS poisoning
* Domain hijacking
* Man-in-the-browser
* Zero day
* Replay
* Pass the hash
* Hijacking and related attacks:
  - Clickjacking
  - Session hijacking
  - URL hijacking
  - Typo squatting
* Driver manipulation:
  - Shimming
  - Refactoring
* MAC spoofing
* IP spoofing
#### Wireless attacks:
* Replay
* IV
  - IV attacks can be associated with the WEP security protocol; WPA uses TKIP, and WPA2 uses AES, not IV.
* Evil twin
* Rogue AP
* Jamming
* WPS
* Bluejacking
* Bluesnarfing
* RFID
* NFC
* Disassociation
#### Cryptographic attacks:
* Birthday
* Known plain text/cipher text
* Rainbow tables
* Dictionary
* Brute force:
  - Online vs. offline
* Hybrid
  - Combining dictionary and brute force
  - For example, Jason’s password of `rover123` is made up of the dictionary word `rover` and the number `123`. It is likely that the cracker attempted to use a dictionary word (like `rover`) and the attempted variations on it using brute force (such as adding `000`, `001`, `002`, `…122`, `123`) to the end of the password until found `rover123`.
* Collision
* Downgrade
* Replay
* Weak implementations

### 1.3 Explain threat actor types and attributes.

#### Types of actors:
* Script kiddies
* Hacktivist
* Organized crime
* Nation states/APT
* Insiders
* Competitors
#### Attributes of actors:
* Internal/external
* Level of sophistication
* Resources/funding
* Intent/motivation
#### Use of open-source intelligence

### 1.4 Explain penetration testing concepts. 

#### Active reconnaissance
#### Passive reconnaissance
#### Pivot
#### Initial exploitation
#### Persistence
#### Escalation of privilege
#### Black box
#### White box
#### Gray box
#### Penetration testing vs. vulnerability scanning

### 1.5 Explain vulnerability scanning concepts. 

#### Passively test security controls
#### Identify vulnerability
#### Identify lack of security controls
#### Identify common misconfigurations
#### Intrusive vs. non-intrusive
#### Credentialed vs. non-credentialed
#### False positive

### 1.6 Explain the impact associated with types of vulnerabilities.

#### Race conditions
#### Vulnerabilities due to:
* End-of-life systems
* Embedded systems
* Lack of vendor support
#### Improper input handling
#### Improper error handling
#### Misconfiguration/weak configuration
#### Default configuration
#### Resource exhaustion
#### Untrained users
#### Improperly configured accounts
#### Vulnerable business processes
#### Weak cipher suites and implementations
#### Memory/buffer vulnerability:
* Memory leak
* Integer overflow
* Buffer overflow
* Pointer dereference
* DLL injection
#### System sprawl/undocumented assets
#### Architecture/design weaknesses
#### New threats/zero day
#### Improper certificate and key management

## 2.0 Technologies and Tools

### 2.1 Install and configure network components, both hardware and software-based, to support organizational security. 

#### Firewall:
* ACL
  - Format:
    `<Source_IP>, <Destination_IP>, <Port>, <Protocol>, <Condition>`
  - If a subnet mask is used for either `IP`, it includes a range, e.g., `192.168.0.0/24` includes `192.168.0.5`, `192.168.0.6`, and `192.168.0.7`.
  - If `Port` is not specified, e.g. `22` for `SSH`, `ANY` can be used to allow traffic to any port.
  - To easily deny anything that does not have a `Condition` set, use implicit deny (see below).
  - To allow VoIP, these 2 protocols must be allowed:
    * SIP: session initiation protocol, used to establish the call
    * RTP: real-time transport protocol, used to send the data. 
* Application-based vs. network-based
  - A WAF can provide load balancing, but stateful- and stateless cannot.
  - A host-based firewall provides protection for a single host.
* Stateful vs. stateless
  - A stateful firewall filters traffic based on the state of a packet within a session.
    * Can almost entirely eliminate IP spoofing since every packet will be inspected and compared to what it expected.
  - A stateless firewall filters traffic using an ACL.
* NAT filtering
  - Filters traffic based on the type of port being used, e.g. UDP, TCP
* Application-layer gateway
  - Layer 7 firewall
  - Conducts an in-depth inspection based upon the application being used.
  - Resource-intensive, but powerful.
* Circuit-level gateway
  - Operates at the session layer.
  - Only inspects the traffic during the establishment of the session.
* Implicit deny
  - Placed at the end of an ACL to on a _router_ to deny traffic that hasn't been explicitly allowed.
  - Doesn't affect physical ports differently, so [disabling unused ports](#operating-systems) is still important.
#### VPN concentrator:
* Remote access vs. site-to-site
* IPSec:
  - Tunnel mode
  - Transport mode
  - AH
  - ESP
  - Functions without a dependency of time synchronization, so would be unaffected by NTP breaking.
* Split tunnel vs. full tunnel
* TLS
  - Also used to encrypt mail traffic on protocols such as SMTP (SMTPS).
* Always-on VPN
#### NIPS/NIDS:
* Signature-based
* Heuristic/behavioral
* Anomaly
* Inline vs. passive
* In-band vs. out-of-band
* Rules
* Analytics:
  - False positive
  - False negative
#### Router:
* ACLs
* Antispoofing
#### Switch:
* Subject to three types of attacks:
  1. MAC flooding: If flooded, a switch begins to act like a hub, broadcasting data everywhere else in the network.
  2. MAC spoofing
  3. Physical tampering
* Port security
* Layer 2 vs. Layer 3
* Loop prevention
* Flood guard
#### Proxy:
* Forward and reverse proxy
* Transparent
* Application/multipurpose
#### Load balancer:
* Scheduling:
  - Affinity
  - Round-robin
* Active-passive
* Active-active
* Virtual IPs
  - Virtual IP load-balancing doesn’t take a load of each interface and assumes all loads are similar, so it is connection-based, not load-based.
#### Access point:
* SSID
* MAC filtering
* Signal strength
* Band selection/width
* Antenna types and placement
* Fat vs. thin
* Controller-based vs. standalone
#### SIEM:
* Aggregation
* Correlation
  - Correlating events from servers would be the most important issue to address in the case of an incident with multiple servers.
* Automated alerting and triggers
* Time synchronization
* Event deduplication
* Logs/WORM
#### DLP:
* USB blocking
* Cloud-based
  - A cloud-based DLP would best be used if your organization has a large cloud presence.
* Email
* A storage DLP is typically installed on a file server or in the data center to monitor the data at rest. 
* An endpoint DLP is installed on an individual computer to monitor data in use. 
* A network DLP would best be installed at the perimeter of the network and inspect the data in transit. 
#### NAC:
* Dissolvable vs. permanent
* Host health checks
  - Network access control (NAC) solutions inspect clients for health after they connect to a network.
* Agent vs. agentless
* By utilizing NAC, each machine connected to an open wireless network could be checked for compliance and determine if it is a 'known' machine that should be given access to the entire network, or if it is an unknown machine that should be placed into an internet-only network (which would have no access to, say, the HVAC control system). 
#### Mail gateway:
* Spam filter
  - Use whitelists and blacklists
* DLP
* Encryption
#### Bridge
#### SSL/TLS accelerators
#### SSL decryptors
#### Media gateway
#### Hardware security module

### 2.2 Given a scenario, use appropriate software tools to assess the security posture of an organization.

#### Protocol analyzer
#### Network scanners:
* Rogue system detection
* Network mapping
#### Wireless scanners/cracker
#### Password cracker
#### Vulnerability scanner
#### Configuration compliance scanner
#### Exploitation frameworks
#### Data sanitization tools
#### Steganography tools
#### Honeypot
#### Backup utilities
#### Banner grabbing
* Banner grabbing is conducted by actively connecting to the server using telnet or netcat and collecting the response from the web server. This banner usually contains the operating system being run by the server as well as the version number of the service (SSH) being run. This is the fastest and easiest way to determine the version of SSH being run on this web server. 
#### Passive vs. active
#### Command line tools:
* `ping`
* `netstat`
* `tracert` / `traceroute`
* `nslookup` / `dig`
* `arp`
* `ipconfig` / `ip` / `ifconfig`
* `tcpdump`
* `nmap`
* `netcat`
* `chroot`
  - Could be used to isolate an application within a sandbox on a Linux system.
* `chmod`
  - Used to change permissions on a Linux system.

### 2.3 Given a scenario, troubleshoot common security issues. 

#### Unencrypted credentials/clear text
#### Logs and events anomalies
#### Permission issues
#### Access violations
#### Certificate issues
#### Data exfiltration
#### Misconfigured devices:
* Firewall
* Content filter
* Access points
#### Weak security configurations
#### Personnel issues:
* Policy violation
* Insider threat
* Social engineering
* Social media
* Personal email
#### Unauthorized software
#### Baseline deviation
#### License compliance violation (availability/integrity)
#### Asset management
#### Authentication issues
#### Spam mitigation:
* Mail gateways
* To prevent email servers from being used to send spam, ensure they aren't configured as open mail relays or SMTP open relays.
* Remove email addresses from company website
* Train and educate users on where to submit emails

### 2.4 Given a scenario, analyze and interpret output from security technologies.

#### HIDS/HIPS
#### Antivirus
#### File integrity check
#### Host-based firewall
* The program iptables is used to configure the firewall on Linux servers. 
* Windows Firewall is only available on Windows servers and desktops. 
* PF and IPFW are available on FreeBSD and OS X.
#### Application whitelisting
* Application whitelisting will only allow a program to execute if it is specifically listed in the approved exception list. All other programs are blocked from running. This makes it the BEST mitigation again a zero-day virus.
#### Removable media control
#### Advanced malware tools
#### Patch management tools
* Patch management software will help roll out patches onto the network. 
* Automatic updates shouldn’t be used on corporate networks if they will interfere with productivity and network consistency, so patch management is a better solution. 
* Scanning all machines for patches every day will slow down production, whereas patch management is more optimized.
#### UTM
#### DLP
#### Data execution prevention
#### Web application firewall

### 2.5 Given a scenario, deploy mobile devices securely. 

#### Connection methods:
* Cellular
  - Benefit: By using cellular data, your users will be able to avoid connecting to WiFi networks for connectivity, mitigating threats such as MitM, evil twins, rogue APs.
* WiFi
* SATCOM
* Bluetooth
* NFC
* ANT
* Infrared
* USB
#### Mobile device management concepts:
* A mobile device management (MDM) program enables the administrators to remotely push software updates, security policies, and other security features to the device from a centralized server.
* Application management
* Content management
* Remote wipe
* Geofencing
* Geolocation
* Screen locks
* Push notification services
* Passwords and pins
* Biometrics
* Context-aware authentication
* Containerization
  - Containerization is a great resource to prevent employees’ personal device usage compromising company data since it establishes secure isolated connections to applications and isolates the rest of the phone. 
* Storage segmentation
* Full device encryption
  - Protects confidentiality, but does not segregate data
#### Enforcement and monitoring for:
* Third-party app stores
* Rooting/jailbreaking
* Sideloading
* Custom firmware
* Carrier unlocking
* Firmware OTA updates
* Camera use
* SMS/MMS
* External media
* USB OTG
* Recording microphone
* GPS tagging
* WiFi direct/ad hoc
* Tethering
* Payment methods
#### Deployment models:
* BYOD
  - With a BYOD policy, the employee is allowed to use their own device on the corporate network. This is a cheaper solution than a CYOD policy, since the company doesn’t have to furnish or pay for the device. Unfortunately, a BYOD policy is not good for security since the company has little control over the device and information can become comingled with an employee’s personal data on the device. Additionally, using a Mobile Device Management solution is more challenging with a BYOD policy, which can lead to difficulties in managing configurations and conducting any kind of patch management.
* COPE
  - With company-owned devices, you can still use the device for personal use and save your personal information on this device, therefore, your personal and private data is being exposed to your company. By storing your personal data on a company-owned device, the employee is giving up some of their privacy.
* CYOD
* Corp

### 2.6 Given a scenario, implement secure protocols.

#### Protocols:
* DNSSEC
  - Functions without a dependency of time synchronization, so would be unaffected by NTP breaking.
* SSH
  - Port 22
  - Operates over TCP
* S/MIME
* SRTP
* LDAPS
* FTPS
* SFTP
* SNMPv3
* SSL/TLS
* HTTPS
* Secure POP/IMAP
#### Use cases:
* Voice and video
* Time synchronization
* Email and web
* File transfer
* Directory services
* Remote access
* Domain name resolution
* Routing and switching
* Network address allocation
* Subscription services

## 3.0 Architecture and Design

### 3.1 Explain use cases and purpose for frameworks, best practices and secure configuration guides. 

#### Industry-standard frameworks and reference architectures:
* Regulatory
* Non-regulatory
* National vs. international
* Industry-specific frameworks
#### Benchmarks/secure configuration guides:
* Platform/vendor-specific guides:
  - Web server
  - Operating system
  - Application server
  - Network infrastructure devices
* General purpose guides
#### Defense-in-depth/layered security:
* Vendor diversity
* Control diversity:
  - Administrative
  - Technical
    * Layering various network appliances and configurations to create a more secure and defensible architecture. 
* User training

### 3.2 Given a scenario, implement secure network architecture concepts.

#### Zones/topologies:
* DMZ
* Extranet
* Intranet
* Wireless
* Guest
* Honeynets
* NAT
* Ad hoc
#### Segregation/segmentation/isolation:
* Physical
* Logical (VLAN)
  - A VLAN provides separation for traffic and can be configured to separate VoIP and data traffic.
  - While a VLAN is useful to segment out network traffic to various parts of the network, if data is still being routed to/from an HVAC VLAN then this won't stop someone from the open wireless network from being able to attempt to login to the HVAC controls. 
* Virtualization
* Air gaps
#### Tunneling/VPN:
* Site-to-site
* Remote access
#### Security device/technology placement:
* Sensors
* Collectors
* Correlation engines
* Filters
* Proxies
* Firewalls
* VPN concentrators
* SSL accelerators
* Load balancers
  - A WAF (web application firewall) can provide loadbalancing, but stateful and stateless firewalls can.
* DDoS mitigator
* Aggregation switches
* Taps and port mirror
#### SDN

### 3.3 Given a scenario, implement secure systems design.

#### Hardware/firmware security:
* FDE/SED
* TPM
  - Trusted Platform Module
  - Provides full drive encryption.
  - Included in many laptops.
* HSM
  - Hardware Security Module
  - A removable device that can generate and store RSA keys used with servers for data encryption.
* UEFI/
  - A BIOS password is the most fundamental integrity technique.
* Secure boot and attestation
* Supply chain
* Hardware root of trust
* EMI/EMP
  - If you use a CAT 5e STP cable for your network connection, you will minimize the risk of EMI and reduce data emanations.
#### Operating systems:
* Types:
  - Network
  - Server
  - Workstation
  - Appliance
  - Kiosk
  - Mobile OS
* Patch management
  1. Planning: Verify compatibility, testing, and deployment
  2. Testing: Test a patch prior to automating for deployment. Have a test network or at least a single machine, or in the worst case, test on a single machine that is the least critical before installing a patch on others.
  3. Implementing: Some use automated updates, but large orgs use central management system.
  4. Auditing: Verify the client status after patch deployment to ensure it was successful.
* Disabling unnecessary ports and services
  - Prevent unauthorized access by disabling unused physical ports on switches. This prevents the connection if someone plugs their computer into an unused port.
* Least functionality
* Secure configurations
* Trusted operating system
* Application whitelisting/blacklisting
* Disable default accounts/passwords
#### Peripherals:
* Wireless keyboards
* Wireless mice
* Displays
* WiFi-enabled MicroSD cards
* Printers/MFDs
* External storage devices
* Digital cameras

### 3.4 Explain the importance of secure staging deployment concepts.

#### Sandboxing
#### Environment:
* Development
* Test
* Staging
* Production
#### Secure baseline
#### Integrity measurement
* Kernel integrity system has a major benefit it provides in that it detects if files have been altered. It doesn’t detect malware, that’s the job of an antivirus software, and it doesn’t detect if rogue programs have been installed or if changes were made to user accounts.

### 3.5 Explain the security implications of embedded systems. 

#### SCADA/ICS
* Generators controlled within a SCADA system can be isolated within a VLAN to protect them from unauthorized access. 
#### Smart devices/IoT:
* Wearable technology
* Home automation
#### HVAC
#### SoC
#### RTOS
#### Printers/MFDs
#### Camera systems
#### Special purpose:
* Medical devices
* Vehicles
* Aircraft/UAV

### 3.6 Summarize secure application development and deployment concepts. 

#### Development life-cycle models:
* Waterfall vs. Agile
#### Secure DevOps:
* Security automation
* Continuous integration
* Baselining
* Immutable systems
  - An immutable server is a server that has a configuration that cannot be changed.
  - Useful in a case such as deploying and supporting a legacy application where the configuration for the application and the OS are very specific and cannot be changed.
* Infrastructure as code
#### Version control and change management
#### Provisioning and deprovisioning
#### Secure coding techniques:
* Proper error handling
* Proper input validation
* Normalization
* Stored procedures
  - an effective method of preventing [SQL injection attacks](#applicationservice-attacks)
* Code signing
* Encryption
* Obfuscation/camouflage
* Code reuse/dead code
* Server-side vs. client-side execution and validation
* Memory management
* Use of third-party libraries and SDKs
* Data exposure
#### Code quality and testing:
* Static code analyzers
* Dynamic analysis (e.g., fuzzing)
* Stress testing
* Sandboxing
* Model verification
#### Compiled vs. runtime code

### 3.7 Summarize cloud and virtualization concepts.

#### Hypervisor:
* Type I
  - A Type I (bare metal) hypervisor allows each virtual machine (VM) to have its own operating system (OS) without requiring the underlying physical server to have a full OS like Windows, OS X, or Linux. A Type I hypervisor is more efficient than a Type II hypervisor because a Type II requires a full desktop or server OS to be installed on the server AND in each of the VMs. 
* Type II
* Application cells/containers
  - An application container isolates applications from the host operating system. 
  - Could be used to run a legacy application that may have vulnerabilities to prevent it from affecting the host and thus the rest of the network.
  - Containerization is the most efficient of any of the options listed, but it doesn’t allow each VM to have its own OS since all containers share the same host OS.
#### VM sprawl avoidance
* Deactivate unused VMs, regularly audit/centrally manage usage.
#### VM escape protection
* If one virtual machine is compromised, the negative effects can be compartmentalized and not spread to the other virtual machines on the same server. The keyword here is “can”. Virtual machines on the same server can be compromised if the attacker performs a VM escape, or if the other virtual machines have the same type of vulnerability. Virtual machines can be hacked, just like physical servers. Each virtual machine has its own operating system and therefore must be patched.
* Privilege escalation to a hypervisor is possible.
* Keep patches up to date.
* Limit connectivity between the VM and the host.
* Remove any unnecessary pieces of virtual hardware from the VM.
#### VM live migrations
* If an attacker can intercept a VM moving from one physical server to another, they can implement a MitM attack capturing data between the two.
* This is why VM data should be encrypted and treated as data-in-transit during migration.
#### Data remnants
* When a VM is shut down, it may leave behind remnants of confidential data.
#### Cloud storage
#### Cloud deployment models:
* SaaS
  - Software as a Service is an application
* PaaS
  - Platform as a Service provides consumers with the infrastructure for hosted applications.
* IaaS
  - Infrastructure as a Service is a _network_ infrastructure
  - Provides an organization with the network, servers, load balancing, routing, and VM hosting required for a service. The organization can then choose their own operating system (usually Windows or Linux), install backend applications (like Apache or MySQL), and any custom-built applications they would like to install and utilize. With IaaS, you get the most control over the “as a service”, but you also have the most responsibility for its inner workings and design.
* CaaS
  - Cloud as a Service is cloud storage.
* Private
* Public
* Hybrid
* Community
#### On-premise vs. hosted vs. cloud
#### VDI/VDE
* Using VDEs would give an organization the opportunity to manage patches, configurations and software installations/updates/maintenance in a single location. 
#### Cloud access security broker
#### Security as a Service

### 3.8 Explain how resiliency and automation strategies reduce risk.

#### Automation/scripting:
* Automated courses of action
* Continuous monitoring
* Configuration validation
#### Templates
#### Master image
* An image for workstations is great for their original configurations, but it won’t assist with keeping patches up to date or preventing software from being installed. 
#### Non-persistence:
* Snapshots
* Revert to known state
* Rollback to known configuration
* Live boot media
#### Elasticity
#### Scalability
#### Distributive allocation
#### Redundancy
#### Fault tolerance
#### High availability
#### RAID

### 3.9 Explain the importance of physical security controls.

#### Lighting
#### Signs
#### Fencing/gate/cage
#### Security guards
#### Alarms
#### Safe
#### Secure cabinets/enclosures
#### Protected distribution/Protected cabling
#### Airgap
#### Mantrap
#### Faraday cage
#### Lock types
#### Biometrics
#### Barricades/bollards
#### Tokens/cards
* A hardware security token creates a one-time use password by presenting the user with a random string of numbers that changes every 30-60 seconds. When used by itself, it is considered a one-time password authentication method. 
#### Environmental controls:
* HVAC
* Hot and cold aisles
* Fire suppression
  - FM-200 is a fire extinguishing system that is commonly used in data centers and server rooms to protect the servers from fire.
#### Cable locks
#### Screen filters
#### Cameras
#### Motion detection
#### Logs
#### Infrared detection
#### Key management

## 4.0 Identity and Access Management

### 4.1 Compare and contrast identity and access management concepts

#### Identification, authentication, authorization and accounting (AAA)
#### Multifactor authentication:
* Something you are
* Something you have
* Something you know
* Somewhere you are
* Something you do
#### Federation
#### Single sign-on
#### Transitive trust
* The most significant disadvantage of federated identities is transitive trust. The security of federated identities is impacted by the security of others. 

### 4.2 Given a scenario, install and configure identity and access services.

#### LDAP
* LDAP is considered a directory or a phonebook of your network and if you make LDAP unavailable then the footprint of your network is not as easily obtained. 
#### Kerberos
* Kerberos is a key distribution center (KDC) and provides keys with certain time limits. 
* If the network time proctocol (NTP) is not working correctly, Kerberos will be affected. 
* Kerberos will not reduce the number of passwords that must be remembered.
#### TACACS+
#### CHAP
#### PAP
#### MSCHAP
#### RADIUS
* Functions without a dependency of time synchronization, so would be unaffected by NTP breaking.
#### SAML
#### OpenID Connect
#### OAUTH
#### Shibboleth
#### Secure token
#### NTLM

### 4.3 Given a scenario, implement identity and access management controls.

#### Access control models:
* MAC
* DAC
* ABAC
* Role-based access control
* Rule-based access control
#### Physical access control:
* Proximity cards
  - A "hands-free" solution, since they only need to be within close range to work. 
  - A person with a proximity card could be carrying heavy equipment and the lock would still open for them.
* Smart cards
#### Biometric factors:
* Fingerprint scanner
* Retinal scanner
* Iris scanner
* Voice recognition
* Facial recognition
* False acceptance rate
* False rejection rate
* Crossover error rate
#### Tokens:
* Hard
#### File system security
#### Database security

### 4.4 Given a scenario, differentiate common account management practices. 

#### Account types:
* User account
* Shared and generic accounts/credentials
* Guest accounts
* Service accounts
* Privileged accounts
#### General Concepts:
* Least privilege
* Onboarding/offboarding
* Permission auditing and review
* Usage auditing and review
* Time-of-day restrictions
* Recertification
  - The most important principle in managing account permissions is the account recertification. Periodically, this process verifies that permissions still need to be granted.
* Standard naming convention
* Account maintenance
* Group-based access control
  - Why use it? Assigning permissions to each user individually has a high administrative overhead. Waiting for users to ask will also increase administrative overhead. Although delegating authority to assign permissions might work, it doesn't provide the same level of security as centrally managed groups, and without groups, it will still have a high administrative overhead for someone.
* Location-based policies
#### Account policy enforcement: 
* Credential management
  - A password manager (e.g. 1Password) can reduce the number of passwords that need to be remembered.
* Group policy
* Password complexity
* Expiration
* Recovery
  - In case an account is deleted, a recovery agent (RA) can be used to decrypt files associated with the account.
* Disablement
  - If an employee is terminated, their account should be disabled (rather than deleted) during the exit interview so that user security keys (cryptographic keys) are retained. These keys can encrypt and decrypt files, and if the keys are deleted (i.e. with the user account), it might not be possible to access files that the user encrypted.
* Lockout
* Password history
* Password reuse
* Password length

### 5.0 Risk Management

### 5.1 Explain the importance of policies, plans and procedures related to organizational security. 

#### Standard operating procedure
#### Agreement types:
* BPA
* SLA
* ISA
* MOU/MOA
#### Personnel management:
* Mandatory vacations
* Job rotation
* Separation of duties
* Clean desk
* Background checks
* Exit interviews
* Role-based awareness training:
  - Data owner
  - System administrator
  - System owner
  - User
  - Privileged user
  - Executive user
* NDA
* Onboarding
* Continuing education
* Acceptable use policy/rules of behavior
* Adverse actions
  - Actions that are placed against employees when a wrongdoing has been found. 
  - Examples:
    * Placing someone on leave (other than "mandatory vacation")
    * Changing their computer account to suspended
    * Taking their prox card and building keys
#### General security policies:
* Social media networks/applications
* Personal email

### 5.2 Summarize business impact analysis concepts.

#### RTO/RPO
#### MTBF
#### MTTR
#### Mission-essential functions
#### Identification of critical systems
#### Single point of failure
#### Impact:
* Life
* Property
* Safety
* Finance
* Reputation
#### Privacy impact assessment
* PIA
* Measurement of the private information that belongs to the company while in the possession of a PII. 
#### Privacy threshold assessment

### 5.3 Explain risk management processes and concepts.

#### Threat assessment:
* Environmental
* Manmade
* Internal vs. external
#### Risk assessment:
* SLE
* ALE
* ARO
* Asset value
* Risk register
* Likelihood of occurrence
* Supply chain assessment
* Impact
* Quantitative
* Qualitative
* Testing:
  - Penetration testing authorization
  - Vulnerability testing authorization
* Risk response techniques:
  - Accept
  - Transfer
  - Avoid
  - Mitigate
#### Change management

### 5.4 Given a scenario, follow incident response procedures.

#### Incident response plan:
* Documented incident types/category definitions
* Roles and responsibilities
* Reporting requirements/escalation
* Cyber-incident response teams
* Exercise
#### Incident response process:
* Preparation
* Identification
* Containment
* Eradication
* Recovery
* Lessons learned

### 5.5 Summarize basic concepts of forensics.

#### Order of volatility
* Should [capture system image](#data-acquisition) before analysis.
* Example case:
  1. The **Processor Cache** is the most volatile and changes the most frequently.
  2. **Random Access Memory (RAM)** is temporary storage in a computer, can quickly change or overwritten, and the information stored in RAM is lost when power is removed from the computer.
  3. **Swap files** are temporary files on a hard disk that are used as virtual memory.
  4. The files on a **hard disk or USB drive** are the least volatile of the four options presented since it is used for long-term storage of data and is not lost when the computer loses power.
#### Chain of custody
#### Legal hold
#### Data acquisition:
* Capture system image
  - Do before analyzing a hard drive (and determining the [order of volatility](#order-of-volatility)).
* Network traffic and logs
* Capture video
* Record time offset
* Take hashes
* Screenshots
* Witness interviews
#### Preservation
#### Recovery
#### Strategic intelligence/counterintelligence gathering:
* Active logging
#### Track man-hours

### 5.6 Explain disaster recovery and continuity of operation concepts.

#### BCP
* A business continuity plan identifies critical systems and components that need to be protected. 
#### Recovery sites:
* Hot site
* Warm site
* Cold site
#### Order of restoration
#### Backup concepts:
* Differential
  - A full/differential strategy is best with one full backup on one day and differential backups on other days.
  - A restore would require only two backups, making it a quick option.
* Incremental
  - A full/incremental backup would typically require you to restore more than two backups, e.g. one full backup plus _x_ incremental backups for the number of days since the last full backup.
  - The incremental backup itself takes the shortest time.
* Snapshots
* Full
#### Geographic considerations:
* Off-site backups
  - Encryption of the backup data should be done prior to storing tapes off-site because if something happens to the tape physically, the data would still be okay
* Distance
* Location selection
* Legal implications
* Data sovereignty
#### Continuity of operation planning:
* Exercises/tabletop
* After-action reports
* Failover
* Alternate processing sites
* Alternate business practices

### 5.7 Compare and contrast various types of controls.

#### Deterrent
* e.g. CAPTCHA
#### Preventive
#### Detective
#### Corrective
#### Compensating
#### Technical
* Also called logical controls
#### Administrative
#### Physical

### 5.8 Given a scenario, carry out data security and privacy practices.

#### Data destruction and media sanitization:
* Burning
* Shredding
* Pulping
* Pulverizing
* Degaussing
* Purging
  - Purging removes data from hard drives that cannot be rebuilt, but keeps the hard drive intact. 
* Wiping
  - DoD standard 5220.22-M recommends 7 wipes to completely wipe data.
* Formatting
  - Formatting leaves traces of data that can be rebuilt.
#### Data sensitivity labeling and handling:
* Confidential
* Private
* Public
* Proprietary
* PII
* PHI
#### Data roles:
* Owner
* Steward/custodian
* Privacy officer
#### Data retention
#### Legal and compliance

## 6.0 Cryptography and PKI

### 6.1 Compare and contrast basic concepts of cryptography.

#### Symmetric algorithms
#### Modes of operation
#### Asymmetric algorithms
#### Hashing
#### Salt, IV, nonce
#### Elliptic curve
#### Weak/deprecated algorithms
#### Key exchange
#### Digital signatures
* Digital signatures require certificates and use of a PKI.
  - A digital signature is comprised of a hash digest of the original email that is then encrypted using the sender's private key. 
  - To verify the digital signature upon receipt, the receiver's email client will decrypt the signature file, hash the email itself, and compare the unencrypted signature file to the newly calculated hash. If they match, then the signature is considered authentic and the email is considered to have good integrity (it hasn't been changed in transit).
#### Diffusion
#### Confusion
#### Collision
#### Steganography
#### Obfuscation
#### Stream vs. block
* Stream ciphers work similar to one-time pads. They provide the same protection as OTP. 
#### Key strength
#### Session keys
#### Ephemeral key
#### Secret algorithm
#### Data-in-transit
* Data-in-transit is data that is moving.
* By comparison, data-over-the-network is not considered digital data.
#### Data-at-rest
* Data-at-rest is the data that is currently inactive but stored in digital form in places such as nonvolatile memory.
#### Data-in-use
* Data-in-use is data that is active and stored in volatile memory.
#### Random/pseudo-random number generation
#### Key stretching
#### Implementation vs. algorithm selection:
* Crypto service provider
* Crypto modules
#### Perfect forward secrecy
#### Security through obscurity
#### Common use cases:
* Low power devices
* Low latency
* High resiliency
* Supporting confidentiality
* Supporting integrity
* Supporting obfuscation
* Supporting authentication
* Supporting non-repudiation
* Resource vs. security constraints

### 6.2 Explain cryptography algorithms and their basic characteristics.

#### Symmetric algorithms:
* AES
* DES
* 3DES
  - Adds strength by repeating the encryption process with addtional keys. 
* RC4
* Blowfish/Twofish
#### Cipher modes:
* CBC
  - Cipher Block Chaining mode
  - Encrypts the first block with an IV.
  - Combines each subsequent block with the previous block using an XOR operation.
  - Does not provide data authenticity.
* GCM
  - Galois/Counter mode
  - Combines the Counter (CTR) mode with hashing techniques.
  - The only cipher mode that provides both confidentiality _and_ data authenticity
* ECB
  - Electronic Cookbook mode
  - Easily cracked because it encrypts blocks with the same key; do not use.
* CTR
  - Counter mode
  - Combines an IV with a counter to encrypt blocks.
  - Does not provide data authenticity.
* Stream vs. block
#### Asymmetric algorithms:
* RSA
* DSA
* Diffie-Hellman:
  - Groups
  - DHE
  - ECDHE
    * Allows entities to negotiate encryption keys securely over a public network. 
* Elliptic curve
* PGP/GPG
#### Hashing algorithms:
* MD5
* SHA
* HMAC
* RIPEMD
#### Key stretching algorithms:
* BCRYPT
* PBKDF2
#### Obfuscation:
* XOR
* ROT13
* Substitution ciphers

### 6.3 Given a scenario, install and configure wireless security settings.

#### Cryptographic protocols:
* WPA
  - WPA is the protocol that should be used to help provide him with the maximum level of security while still being compatible with legacy devices on his network.
* WPA2
  - Stronger than WPA, WEP, but wouldn't work with older cards.
* CCMP
  - Counter Mode Cipher Block Chaining Message Authentication
  - Strong, but uses PSK, i.e. no usernames.
* TKIP
#### Authentication protocols:
* EAP
* PEAP
* EAP-FAST
  - A lightweight version of EAP.
  - Is not used with WPS.
  - EAP-FAST exists in situations where password policy cannot be enforced. The three phases it consists of are:
    1. provisioning
    2. establishment of a tunnel 
    3. authentication. 
* EAP-TLS
* EAP-TTLS
  - Encrypts user credentials when users enter their usernames and passwords.
  - Implemented in Enterprise mode and uses an 802.1x server.
* IEEE 802.1x
  - An 802.1x server provides port-based authentication and can authenticate clients. 
  - In a situation where there is an internal network reserved for employees, clients that cannot authenticate can be redirected to a guest network that has Internet access, but not internal network access.
* RADIUS Federation
#### Methods:
* PSK vs. Enterprise vs. Open
  - PSK does not authenticate users based on their usernames.
* WPS
  - Wi-Fi Protected Setup
  - A standard designed to simplify the setup of a wireless network.
  - Does not implement usernames.
* Captive portals

### 6.4 Given a scenario, implement public key infrastructure.

#### Components:
* CA
* Intermediate CA
* CRL
  - Certification revocation list
  - Identifies revoked certificates
  - Cached: if a public CA is not reachable due to a connection outage or CA outage, the cached CRL can still be used as long as the cache time has not expired.
  - Allows verifying the validity of the certificate while ensuring that bandwidth isn’t being consumed
* OCSP
  - Online Certificate Status Protocol
  - Works in real time where the client queries the CA with the serial number of the certificate.
  - If the CA is unreachable, the certificate cannot be validated.
* CSR
  - Certificate Signing Request
  - Used to request a certificate for a web server.
* Certificate
* Public key
* Private key
* Object identifiers (OID)
#### Concepts:
* Online vs. offline CA
* Stapling
* Pinning
* Trust model
* Key escrow
  - Used for key storage; has nothing to do with certificates.
* Certificate chaining
#### Types of certificates:
* Wildcard
* SAN
* Code signing
* Self-signed
* Machine/computer
* Email
* User
* Root
* Domain validation
* Extended validation
#### Certificate formats:
* DER
* PEM
* PFX
* CER
* P12
* P7B

## Protocols and Ports

| Protocol                                                               | Port                      |
|------------------------------------------------------------------------|---------------------------|
| File Transport Protocol (FTP)                                          | TCP 20, 21                |
| Secure Shell (SSH)                                                     | TCP 22                    |
| Secure File Transport Protocol (SFTP)                                  | TCP 22                    |
| Secure Copy (SCP)                                                      | TCP 22                    |
| Telnet                                                                 | TCP 23                    |
| Simple Mail Transport Protocol (SMTP)                                  | TCP 25                    |
| TACACS+                                                                | TCP 49                    |
| Domain Name System (DNS)                                               | TCP/UDP 53                |
| Dynamic Host Configuration Protocol (DHCP)                             | UDP 67, UDP 68            |
| Trivial File Transport Protocol (TFTP)                                 | UDP 69                    |
| Hypertext Transfer Protocol (HTTP)                                     | TCP 80                    |
| Kerberos                                                               | TCP/UDP 88                |
| Post Office Protocol version 3 (POP3)                                  | TCP 110                   |
| Network News Transfer Protocol (NNTP)                                  | TCP 119                   |
| Network Time Protocol (NTP)                                            | UDP 123                   |
| NetBIOS                                                                | UDP 137, UDP 138, TCP 139 |
| Internet message access protocol version 4 (IMAP4)                     | TCP 143                   |
| Simple Network Management Protocol (SNMP)                              | UDP 161                   |
| SNMP trap                                                              | TCP/UDP 162               |
| Lightweight Directory Access Protocol (LDAP)                           | TCP/UDP 389               |
| File Transport Protocol Secure (FTPS)                                  | TCP 443                   |
| Hypertext Transfer Protocol Secure (HTTPS)                             | TCP 443                   |
| Secure Sockets Layer virtual private network (SSL VPN)                 | TCP 443                   |
| SMTP SSL/TLS                                                           | TCP 465                   |
| Internet Security Association and Key Management Protocol (ISAKMP VPN) | UDP 500                   |
| Syslog                                                                 | UDP 514                   |
| LDAP TLS/SSL                                                           | TCP 636                   |
| IMAP SSL/TLS                                                           | TCP 993                   |
| POP SSL/TLS                                                            | TCP 995                   |
| MS SQL Server                                                          | TCP 1433                  |
| Layer 2 Tunneling Protocol (L2TP)                                      | UDP 1701                  |
| Point-to-Point Tunneling Protocol (PPTP)                               | TCP/UDP 1723              |
| Remote Desktop Protocol (RDP)                                          | TCP/UDP 3389              |
| Terminal Access Controller Access-Control System (TACACS)              | UDP 49                    |

## Acronyms

| Acronym | Definition                                                                 |
|---------|----------------------------------------------------------------------------|
| 3DES    | Triple Digital Encryption Standard                                         |
| AAA     | Authentication, Authorization, and Accounting                              |
| ABAC    | Attribute-based Access Control                                             |
| ACL     | Access Control List                                                        |
| AES     | Advanced Encryption Standard                                               |
| AES256  | Advanced Encryption Standards 256bit                                       |
| AH      | Authentication Header                                                      |
| ALE     | Annualized Loss Expectancy                                                 |
| AP      | Access Point                                                               |
| API     | Application Programming Interface                                          |
| APT     | Advanced Persistent Threat                                                 |
| ARO     | Annualized Rate of Occurrence                                              |
| ARP     | Address Resolution Protocol                                                |
| ASLR    | Address Space Layout Randomization                                         |
| ASP     | Application Service Provider                                               |
| AUP     | Acceptable Use Policy                                                      |
| AV      | Antivirus                                                                  |
| AV      | Asset Value                                                                |
| BAC     | Business Availability Center                                               |
| BCP     | Business Continuity Planning                                               |
| BIA     | Business Impact Analysis                                                   |
| BIOS    | Basic Input/Output System                                                  |
| BPA     | Business Partners Agreement                                                |
| BPDU    | Bridge Protocol Data Unit                                                  |
| BYOD    | Bring Your Own Device                                                      |
| CA      | Certificate Authority                                                      |
| CAC     | Common Access Card                                                         |
| CAN     | Controller Area Network                                                    |
| CAPTCHA | Completely Automated Public Turing Test to Tell Computers and Humans Apart |
| CAR     | Corrective Action Report                                                   |
| CBC     | Cipher Block Chaining                                                      |
| CCMP    | Counter-Mode/CBC-Mac Protocol                                              |
| CCTV    | Closed-circuit Television                                                  |
| CER     | Certificate                                                                |
| CER     | Cross-over Error Rate                                                      |
| CERT    | Computer Emergency Response Team                                           |
| CFB     | Cipher Feedback                                                            |
| CHAP    | Challenge Handshake Authentication Protocol                                |
| CIO     | Chief Information Officer                                                  |
| CIRT    | Computer Incident Response Team                                            |
| CMS     | Content Management System                                                  |
| COOP    | Continuity of Operations Plan                                              |
| COPE    | Corporate Owned, Personally Enabled                                        |
| CP      | Contingency Planning                                                       |
| CRC     | Cyclical Redundancy Check                                                  |
| CRL     | Certificate Revocation List                                                |
| CSIRT   | Computer Security Incident Response Team                                   |
| CSO     | Chief Security Officer                                                     |
| CSP     | Cloud Service Provider                                                     |
| CSR     | Certificate Signing Request                                                |
| CSRF    | Cross-site Request Forgery                                                 |
| CSU     | Channel Service Unit                                                       |
| CTM     | Counter-Mode                                                               |
| CTO     | Chief Technology Officer                                                   |
| CTR     | Counter                                                                    |
| CYOD    | Choose Your Own Device                                                     |
| DAC     | Discretionary Access Control                                               |
| DBA     | Database Administrator                                                     |
| DDoS    | Distributed Denial of Service                                              |
| DEP     | Data Execution Prevention                                                  |
| DER     | Distinguished Encoding Rules                                               |
| DES     | Digital Encryption Standard                                                |
| DFIR    | Digital Forensics and Investigation Response                               |
| DHCP    | Dynamic Host Configuration Protocol                                        |
| DHE     | Data-Handling Electronics                                                  |
| DHE     | Diffie-Hellman Ephemeral                                                   |
| DLL     | Dynamic Link Library                                                       |
| DLP     | Data Loss Prevention                                                       |
| DMZ     | Demilitarized Zone                                                         |
| DNAT    | Destination Network Address Transaction                                    |
| DNS     | Domain Name Service (Server)                                               |
| DoS     | Denial of Service                                                          |
| DRP     | Disaster Recovery Plan                                                     |
| DSA     | Digital Signature Algorithm                                                |
| DSL     | Digital Subscriber Line                                                    |
| DSU     | Data Service Unit                                                          |
| EAP     | Extensible Authentication Protocol                                         |
| ECB     | Electronic Code Book                                                       |
| ECC     | Elliptic Curve Cryptography                                                |
| ECDHE   | Elliptic Curve Diffie-Hellman Ephemeral                                    |
| ECDSA   | Elliptic Curve Digital Signature Algorithm                                 |
| EFS     | Encrypted File System                                                      |
| EMI     | Electromagnetic Interference                                               |
| EMP     | Electro Magnetic Pulse                                                     |
| ERP     | Enterprise Resource Planning                                               |
| ESN     | Electronic Serial Number                                                   |
| ESP     | Encapsulated Security Payload                                              |
| EF      | Exposure Factor                                                            |
| FACL    | File System Access Control List                                            |
| FAR     | False Acceptance Rate                                                      |
| FDE     | Full Disk Encryption                                                       |
| FRR     | False Rejection Rate                                                       |
| FTP     | File Transfer Protocol                                                     |
| FTPS    | Secured File Transfer Protocol                                             |
| GCM     | Galois Counter Mode                                                        |
| GPG     | Gnu Privacy Guard                                                          |
| GPO     | Group Policy Object                                                        |
| GPS     | Global Positioning System                                                  |
| GPU     | Graphic Processing Unit                                                    |
| GRE     | Generic Routing Encapsulation                                              |
| HA      | High Availability                                                          |
| HDD     | Hard Disk Drive                                                            |
| HIDS    | Host-based Intrusion Detection System                                      |
| HIPS    | Host-based Intrusion Prevention System                                     |
| HMAC    | Hashed Message Authentication Code                                         |
| HOTP    | HMAC-based One-Time Password                                               |
| HSM     | Hardware Security Module                                                   |
| HTML    | Hypertext Markup Language                                                  |
| HTTP    | Hypertext Transfer Protocol                                                |
| HTTPS   | Hypertext Transfer Protocol over SSL/TLS                                   |
| HVAC    | Heating, Ventilation and Air Conditioning                                  |
| IaaS    | Infrastructure as a Service                                                |
| ICMP    | Internet Control Message Protocol                                          |
| ICS     | Industrial Control Systems                                                 |
| ID      | Identification                                                             |
| IDEA    | International Data Encryption Algorithm                                    |
| IDF     | Intermediate Distribution Frame                                            |
| IdP     | Identity Provider                                                          |
| IDS     | Intrusion Detection System                                                 |
| IEEE    | Institute of Electrical and Electronic Engineers                           |
| IIS     | Internet Information System                                                |
| IKE     | Internet Key Exchange                                                      |
| IM      | Instant Messaging                                                          |
| IMAP4   | Internet Message Access Protocol v4                                        |
| IoT     | Internet of Things                                                         |
| IP      | Internet Protocol                                                          |
| IPSec   | Internet Protocol Security                                                 |
| IR      | Incident Response                                                          |
| IR      | Infrared                                                                   |
| IRC     | Internet Relay Chat                                                        |
| IRP     | Incident Response Plan                                                     |
| ISA     | Interconnection Security Agreement                                         |
| ISP     | Internet Service Provider                                                  |
| ISSO    | Information Systems Security Officer                                       |
| ITCP    | IT Contingency Plan                                                        |
| IV      | Initialization Vector                                                      |
| KDC     | Key Distribution Center                                                    |
| KEK     | Key Encryption Key                                                         |
| L2TP    | Layer 2 Tunneling Protocol                                                 |
| LAN     | Local Area Network                                                         |
| LDAP    | Lightweight Directory Access Protocol                                      |
| LEAP    | Lightweight Extensible Authentication Protocol                             |
| MaaS    | Monitoring as a Service                                                    |
| MAC     | Mandatory Access Control                                                   |
| MAC     | Media Access Control                                                       |
| MAC     | Message Authentication Code                                                |
| MAN     | Metropolitan Area Network                                                  |
| MBR     | Master Boot Record                                                         |
| MD5     | Message Digest 5                                                           |
| MDF     | Main Distribution Frame                                                    |
| MDM     | Mobile Device Management                                                   |
| MFA     | Multi-Factor Authentication                                                |
| MFD     | Multi-function Device                                                      |
| MITM    | Man-in-the-Middle                                                          |
| MMS     | Multimedia Message Service                                                 |
| MOA     | Memorandum of Agreement                                                    |
| MOU     | Memorandum of Understanding                                                |
| MPLS    | Multi-protocol Label Switching                                             |
| MSCH    | AP Microsoft Challenge Handshake Authentication Protocol                   |
| MSP     | Managed Service Provider                                                   |
| MTBF    | Mean Time Between Failures                                                 |
| MTTF    | Mean Time to Failure                                                       |
| MTTR    | Mean Time to Recover or Mean Time to Repair                                |
| MTU     | Maximum Transmission Unit                                                  |
| NAC     | Network Access Control                                                     |
| NAT     | Network Address Translation                                                |
| NDA     | Non-disclosure Agreement                                                   |
| NFC     | Near Field Communication                                                   |
| NGAC    | Next Generation Access Control                                             |
| NIDS    | Network-based Intrusion Detection System                                   |
| NIPS    | Network-based Intrusion Prevention System                                  |
| NIST    | National Institute of Standards & Technology                               |
| NTFS    | New Technology File System                                                 |
| NTLM    | New Technology LAN Manager                                                 |
| the Network Time Proctocol (   )  | Network Time Protocol                                                      |
| OAUTH   | Open Authorization                                                         |
| OCSP    | Online Certificate Status Protocol                                         |
| OID     | Object Identifier                                                          |
| OS      | Operating System                                                           |
| OTA     | Over The Air                                                               |
| OVAL    | Open Vulnerability Assessment Language                                     |
| P12     | PKCS #12                                                                   |
| P2P     | Peer to Peer                                                               |
| PaaS    | Platform as a Service                                                      |
| PAC     | Proxy Auto Configuration                                                   |
| PAM     | Pluggable Authentication Modules                                           |
| PAP     | Password Authentication Protocol                                           |
| PAT     | Port Address Translation                                                   |
| PBKDF2  | Password-based Key Derivation Function 2                                   |
| PBX     | Private Branch Exchange                                                    |
| PCAP    | Packet Capture                                                             |
| PEAP    | Protected Extensible Authentication Protocol                               |
| PED     | Personal Electronic Device                                                 |
| PEM     | Privacy-enhanced Electronic Mail                                           |
| PFS     | Perfect Forward Secrecy                                                    |
| PFX     | Personal Exchange Format                                                   |
| PGP     | Pretty Good Privacy                                                        |
| PHI     | Personal Health Information                                                |
| PII     | Personally Identifiable Information                                        |
| PIV     | Personal Identity Verification                                             |
| PKI     | Public Key Infrastructure                                                  |
| POODLE  | Padding Oracle on Downgrade Legacy Encryption                              |
| POP     | Post Office Protocol                                                       |
| POTS    | Plain Old Telephone Service                                                |
| PPP     | Point-to-Point Protocol                                                    |
| PPTP    | Point-to-Point Tunneling Protocol                                          |
| PSK     | Pre-shared Key                                                             |
| PTZ     | Pan-Tilt-Zoom                                                              |
| RA      | Recovery Agent                                                             |
| RA      | Registration Authority                                                     |
| RAD     | Rapid Application Development                                              |
| RADIUS  | Remote Authentication Dial-in User Server                                  |
| RAID    | Redundant Array of Inexpensive Disks                                       |
| RAS     | Remote Access Server                                                       |
| RAT     | Remote Access Trojan                                                       |
| RBAC    | Role-based Access Control                                                  |
| RBAC    | Rule-based Access Control                                                  |
| RC4     | Rivest Cipher version 4                                                    |
| RDP     | Remote Desktop Protocol                                                    |
| RFID    | Radio Frequency Identifier                                                 |
| RIPEMD  | RACE Integrity Primitives Evaluation Message Digest                        |
| ROI     | Return on Investment                                                       |
| RMF     | Risk Management Framework                                                  |
| RPO     | Recovery Point Objective                                                   |
| RSA     | Rivest, Shamir, & Adleman                                                  |
| RTBH    | Remotely Triggered Black Hole                                              |
| RTO     | Recovery Time Objective                                                    |
| RTOS    | Real-time Operating System                                                 |
| RTP     | Real-time Transport Protocol                                               |
| S/MIME  | Secure/Multipurpose Internet Mail Extensions                               |
| SaaS    | Software as a Service                                                      |
| SAML    | Security Assertions Markup Language                                        |
| SAN     | Storage Area Network                                                       |
| SAN     | Subject Alternative Name                                                   |
| SCADA   | System Control and Data Acquisition                                        |
| SCAP    | Security Content Automation Protocol                                       |
| SCEP    | Simple Certificate Enrollment Protocol                                     |
| SCP     | Secure Copy                                                                |
| SCSI    | Small Computer System Interface                                            |
| SDK     | Software Development Kit                                                   |
| SDLC    | Software Development Life Cycle                                            |
| SDLM    | Software Development Life Cycle Methodology                                |
| SDN     | Software Defined Network                                                   |
| SED     | Self-encrypting Drive                                                      |
| SEH     | Structured Exception Handler                                               |
| SFTP    | Secured File Transfer Protocol                                             |
| SHA     | Secure Hashing Algorithm                                                   |
| SHTTP   | Secure Hypertext Transfer Protocol                                         |
| SIEM    | Security Information and Event Management                                  |
| SIM     | Subscriber Identity Module                                                 |
| SLA     | Service Level Agreement                                                    |
| SLE     | Single Loss Expectancy                                                     |
| SMB     | Server Message Block                                                       |
| SMS     | Short Message Service                                                      |
| SMTP    | Simple Mail Transfer Protocol                                              |
| SMTPS   | Simple Mail Transfer Protocol Secure                                       |
| SNMP    | Simple Network Management Protocol                                         |
| SOAP    | Simple Object Access Protocol                                              |
| SoC     | System on Chip                                                             |
| SPF     | Sender Policy Framework                                                    |
| SPIM    | Spam over Internet Messaging                                               |
| SPoF    | Single Point of Failure                                                    |
| SQL     | Structured Query Language                                                  |
| SRTP    | Secure Real-Time Protocol                                                  |
| SSD     | Solid State Drive                                                          |
| SSH     | Secure Shell                                                               |
| SSID    | Service Set Identifier                                                     |
| SSL     | Secure Sockets Layer                                                       |
| SSO     | Single Sign-on                                                             |
| STP     | Shielded Twisted Pair                                                      |
| TACACS+ | Terminal Access Controller Access Control System Plus                      |
| TCP/    | IP Transmission Control Protocol/Internet Protocol                         |
| TGT     | Ticket Granting Ticket                                                     |
| TKIP    | Temporal Key Integrity Protocol                                            |
| TLS     | Transport Layer Security                                                   |
| TOTP    | Time-based One-time Password                                               |
| TPM     | Trusted Platform Module                                                    |
| TSIG    | Transaction Signature                                                      |
| UAT     | User Acceptance Testing                                                    |
| UAV     | Unmanned Aerial Vehicle                                                    |
| UDP     | User Datagram Protocol                                                     |
| UEFI    | Unified Extensible Firmware Interface                                      |
| UPS     | Uninterruptable Power Supply                                               |
| URI     | Uniform Resource Identifier                                                |
| URL     | Universal Resource Locator                                                 |
| USB     | Universal Serial Bus                                                       |
| USB OTG | USB On The Go                                                              |
| UTM     | Unified Threat Management                                                  |
| UTP     | Unshielded Twisted Pair                                                    |
| VDE     | Virtual Desktop Environment                                                |
| VDI     | Virtual Desktop Infrastructure                                             |
| VLAN    | Virtual Local Area Network                                                 |
| VLSM    | Variable Length Subnet Masking                                             |
| VM      | Virtual Machine                                                            |
| VoIP    | Voice over IP                                                              |
| VPN     | Virtual Private Network                                                    |
| VTC     | Video Teleconferencing                                                     |
| WAF     | Web Application Firewall                                                   |
| WAP     | Wireless Access Point                                                      |
| WEP     | Wired Equivalent Privacy                                                   |
| WIDS    | Wireless Intrusion Detection System                                        |
| WIPS    | Wireless Intrusion Prevention System                                       |
| WORM    | Write Once Read Many                                                       |
| WPA     | WiFi Protected Access                                                      |
| WPA2    | WiFi Protected Access 2                                                    |
| WPS     | WiFi Protected Setup                                                       |
| WTLS    | Wireless TLS                                                               |
| XML     | Extensible Markup Language                                                 |
| XOR     | Exclusive Or                                                               |
| XSRF    | Cross-site Request Forgery                                                 |
| XSS     | Cross-site Scripting                                                       |
