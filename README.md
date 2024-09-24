# Pioneer
A vendor-agnostic CLI tool for migrating firewall configuration.

# Table of Contents

1. [Pioneer](#pioneer)
2. [Too long, didn't read](#too-long-didnt-read)
3. [Introduction](#introduction)
4. [High level overview](#high-level-overview)
5. [Pioneer concepts](#pioneer-concepts)
    - [Security Device](#security-device)
    - [Migration Project](#migration-project)
    - [Container](#container)
    - [Device object](#device-object)
    - [Policy](#policy)
    - [Managed device](#managed-device)
    - [Class structure and types](#class-structure-and-types)
    - [Import process](#import-process)
    - [Migration process](#migration-process)
6. [Getting started with Pioneer](#getting-started-with-pioneer)
7. [Usage example and demo](#usage-example-and-demo)
8. [Known issues](#known-issues)
9. [Roadmap](#roadmap)
10. [Code issues that must be addressed](#code-issues-that-must-be-addressed)

# Too long, didn't read
<p>Spare time project.
<p>Migrates policies from Cisco's Firepower Management Center to Palo Alto's Panorama Management Center.
<p>Works pretty well. 
<p>Used in production at my job, migrated thousands of firewall policies with very little intervention needed after the migration process.
<p>Video with demo below at section [Getting started with Pioneer](#getting-started-with-pioneer)

## Introduction
Pioneer is a coding project that I started in my spare time. During my experience as a network engineer
I had to migrate a lot of network configuration from a firewall platform to other firewall platforms.
The most boring, repetitive, error-prone and time-consuming config was always the migration of the firewall policies.
<p>The tools provided by different vendors that were supposed to assist in the firewall migration process 
were either non-existent or were not solving all the issues caused by cross-vendor incompatibilities or were producing unexpected results.
Because of this, most of the time I had to write my own scripts in order to be able to migrate thousands
of firewall policies (along with the objects and group objects used to define them) and to fix the cross-vendor
incompatibilities.
<p>At some point, I thought "since there is no such tool that just works out-of-the-box that can just work, why not try to make a tool myself?"
After I got that idea, I started working on it.
I am not officially a programmer, I had limited knowledge of app architectures, full-stack app development 
and programming concepts when I started this. I wrote some code here and there and got pretty good at writing
scripts since I hate to do things manually. But I have never worked on such a big programming task,
from scratch, by myself.

<p>Pioneer is techincally my pilot project when it comes about coding and I'm kind of proud to say that it 
was pretty helpful even in production environments. By using Pioneer, I was able to migrate more than
2000 firewall policies along with all the thousands of objects and group objects used for defining them.
Not only was it helpful during the migration process, it was also really helpful afterwards. After these
migrations, we still had some problems since these are unavoidable when it comes about firewall migrations.
However, very few of the problems were caused by the migrated firewall policies.

<p>I made this code public since I don't want to work on it anymore, as I found more interesting things to do. Unfortunately, I didn't
get to create any UML diagrams or to document every function of the code. However, the code is filled with many comments and docstrings making navigation through it pretty easy.
<p>If you think this code can help you or if you want to finish my idea, you're free to do whatever you want with it!

## High level overview
<p>Pioneer aims to be a tool that can perform full configuration migration between different firewall platforms.
<p>At this point, it can only migrate firewall policies from Cisco's Firepower Management Center to Palo Alto's Panorama Management Center.
I tried to write the code in a scalable manner. Pioneer tries to abstractize every piece of firewall configuration and tries to store it
in a vendor-agnostic mode.
<p>The main idea is to get a 1-to-1 replica of the config of the source security device in Pioneer. The info should be stored in a vendor-agnostic format as much as possible.
<p>Pioneer uses the APIs of a security device (which can be either a firewall or a firewall manager), extracts and processes all the info from the security device and then stores it in a PostgreSQL database.
<p>So far, only the device objects firewall and NAT policies, security zones and the managed devices are imported.
After the data is processed, the user can import the processed security devies into a migration project.
Policies are then further processed and then they can be migrated to the target firewall.
Below you find a more detailed explaination of the key concepts.

### Pioneer concepts
#### Security Device
Represents an abstraction of a firewall or of a firewall manager. It is used to interact with the actual firewall or the firewall manager
and with the database used to store all the info extracted from that device.

#### Migration Project
It is used to store the information from the security devices. It has a source and target security device. All data from these devices is
imported in the migration project's database. The migration project's database also contains some tables that can be used to set vendor-specific options on the to-be-migrated policies.
<p>It also has tables that are used to map different options (such as firewall policy actions) between different platforms.
<p>It can be viewed as a super security device.

#### Container
It is a class where all the other objects are "stored". All the objects and policies are associated with a container.
In cases where the platform does not have an actual container, a virtual container is used. 

#### Device object
Represents an abstraction of an object. An object can be a network object (used for defining network addresses, subnets, FQDNs), a service/port object (used for defining network ports), a group object (group of network objects, port objects) and so on.

#### Policy
Represents an abstraction of a policy. It can be whatever type of policy. Currently only firewall policies can be migrated. NAT policies can only be imported so far.

#### Managed device
Represents an abstraction of a managed device. This is a concept used by firewall managers. In case of standalone firewalls, the managed device should reference the security device itself.

#### Class structure and types
The code uses three types of classes:
<p>Parent class - a class which has all the general attributes which the device-specifc classes inherit.
<p>Device-specific class - for example FMCPolicy - inherits from the parent class. It has a device_info parameter, which stores the actual data retrieved from security device's API. Data is extracted from that parameter and the parent objects are initialized using that data.
<p>Pioneer class - intermediary class used for migration. This class is initialized with the vendor-agnostic data that is stored in the database.
This class is used in the migration process, as it contains data that can be easily transferred between different platforms.

#### Import process
When creating a security device, two things happen:
<p>1. General info (such as the API user, platform and version) is retrieved and the security device's database is created. The retrieval of
the platform version acts as a check mechanism in order to ensure that Pioneer can further interact with the device.
<p>2. All the data of the device gets imported to the database. Pioneer starts to query the device and insert data such as container hierarchies, security device objects (groups are also processed and relationships between the groups and the objects are stored in the database), policies and so on.

#### Migration process
A migration project needs to be created. After that, source and target device must be set. Mappings between different types of config must be done the containers that need to be migrated must be done. Additional options, such as logging targets for the firewall policies can be set.

## Getting started with Pioneer
<p>I highly recommend using a test machine for deploying Pioneer. Don't use a production server, as Pioneer is far from being ready to be deployed on a production server.
<p>I have made a small bash script for getting started. Execute this script on a freshly installed Ubuntu machine. The script checks if all the requirements are met. If the proper Python version is not found, the script will exit and you'll have to manually install the right Python version. The script doesn't automatically install Python in order to avoid breaking OS stuff. Skip restarting any process that uses outdated libraries when prompted to. Make sure that machine has proper network access to all the devices you want Pioneer to connect to.
<p> In order to use the script, make a new file, copy paste the content of "getting_started.sh" file

```bash
vi getting_started.sh
```
*Creates the migration project.*
```bash
chmod +x getting_started.sh
```
*Makes the script executable.*
```bash
./getting_started.sh
```
*Executes the script.*
```bash
cd pioneer/
```
*Changes the directory to Pioneer's directory.*

<p>Below you find a list with all the requirements.
<p>An Ubuntu 20.04 machine. Preferably a fresh installation.
<p>PostgreSQL version must be 15.X.
<p>Python version must be 3.10.6.
<p>An empty (landing) database called "pioneer_projects" must be created along with a "pioneer_admin" user. Check the "utils/gvars.py" file to see/modify what credentials are needed.
<p>Clone the code from the git repo.
<p>Start by installing the requirements in requirements.txt file.

<p>Firepower Management Center version must be at least 6.4.X.
<p>Panorama Management Center version must be at least 10.X.
<p>You can try to use other Firepower Management Center or Panorama Management Center versions, however I cannot guarantee that they will work.

## Usage example and demo
Below you find a list with the commands needed to perform a migration. You also find a video with a demo.
<p>Be aware that when creating stuff, a name convention must be followed: no whitespaces, no hyphens or special characters as separators, name must start with an alphabetical character.

```bash
python3 pioneer.py --create-project 'example_project' 
```
*Creates the migration project.*

```bash
python3 pioneer.py --create-security-device 'dummy_device' --device-type 'allowed_device_type' --hostname 'example.com or IP address' --username 'user' --secret 'pass'
```
*Creates the security device. Hostname can be either a name or IP. (Note: Storing passwords this way needs to be changed.)*

```bash
python3 pioneer.py --project 'example_project' --set-source-device 'dummy_device1' --set-target-device 'dummy_device2'
```
*Sets the source and target devices for the project.*

```bash
python3 pioneer.py --project 'example_project' --map-security-policy-containers --source-container 'source_container' --target-container 'target_container'
```
*Creates a mapping between the source security policy container and the target policy container.*

```bash
python3 pioneer.py --project 'example_project' --map-zones --source-zone 'zone1' --target-zone 'zone2'
```
*Maps all the interfaces/zones present in the policies.*

```bash
python3 pioneer.py --project 'example_project' --send-logs-to-manager 'manager'
```
*Sets the logging target.*

```bash
python3 pioneer.py --project 'example_project' --migrate --security-policy-container 'source_container'
```
*Initiates the migration of the source container.*

<p>NOTE: mapping should be done even in the containers/interfaces have the same name
<p>After the migration is done, you can look into "pioneer/log/{migration_project_name}/special_policies.log" to see what policies were not migrated and why. You can also see what special parameters (such as L7 apps) were not migrated. 
<p>Demo video:

## Known issues
<p>Some NAT policies don't get imported properly. Didn't look into this one.
<p>Objects with very long names and with the same value get created every time they are migrated. This is due to the fact that when applying name constraints, a random number is appended to the name. This was done to avoid the issue where, after applying name constraints, you would have two objects with the same name but different value. However this issue was generated.
<p>Only Firepower Management Center rules with the following actions: ALLOW, TRUST, BLOCK, BLOCK_RESET can be migrated. I didn't do the mappings for the other actions

## Roadmap
<p> Full-CLI functionality for managing projects and devices (adding, deleting, modifying, etc.)
<p>All the info (managed devices, zones, interfaces, and so on) must be extracted from a security device.
<p>Migration of any type of policy between Firepower Management Center and Panorama Management Center. Multiple options such as migrating based on last hit time should also be implemented.
<p>Migration between an API device and a device that is not necessarily using an API, such as Cisco's ASA (I know it has an API, but it's crap)
<p>Migration of firewall security policy users (such as these defined locally on the firewall, LDAP users and so on), schedules.
<p>Migration of all types of policy parameters (including L7 parameters such as applications and URL categories).
<p>A web-GUI.
<p>Migrating any type of configuration between platforms - solving all incompatibilties issues.

## Code issues that must be addressed
<p>Stop generating object's UIDs upon init of the object
<p>Ensure that all policies are tracked by their index.
<p>Map everything before migration and execute the migration only on mapped elements.
<p>Make preload_object_data a class method, not a static method.
<p>Composite primary keys for all the mapping tables to avoid having the same mappings stored multiple times
<p>For PA devices, create audit comments, don’t put comments in description
<p>Track all Firepower Management Center port object that are not TCP or UDP.
<p>Tracking of failed import objects, policies and basically everything else that fails
<p>Logging must be redone.
<p>Proper exceptions must be implemented.
<p>Multi-threading must be implemented for the import and for the migration processes.
<p>Functions that are importing data from the database and processing it into Pioneer objects should be consolidated or entirely refactored.
<p>A more user-friendly experience should be implemented: status messages, progress bar, etc...
<p>Fix all known issues.
