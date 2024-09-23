# Pioneer
A vendor-agnostic CLI tool for migrating firewall configuration.

# Too long, didn't read
<p>Spare time project.
<p>Migrates policies from Cisco's Firepower Management Center to Palo Alto's Panorama Management Center.
<p>Works pretty well. 
<p>Used in production at my job, migrated thousands of firewall policies with very little intervention needed after the migration process.

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

<p>I made this code public since I don't want to work on it anymore, as I found more interesting things to do.
If you think this code can help you or if you want to finish my idea, you're free to do whatever you want with it!

## High level overview
<p>Pioneer aims to be a tool that can perform full configuration migration between different firewall platforms.
<p>At this point, it can only migrate firewall policies from Cisco's Firepower Management Center to Palo Alto's Panorama Management Center.
I tried to write the code in a scalable manner. Pioneer tries to abstractize every piece of firewall configuration and tries to store it
in a vendor-agnostic mode.
<p>The main idea is to get a 1-to-1 replica of the config of the source security device in Pioneer. The info should be stored in a vendor-agnostic format as much as possible.
<p>Pioneer uses the APIs of a Security Device (which can be either a firewall or a firewall manager), extracts it, processes it, and then
it stores it in a PostgreSQL database.
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

#### Migration process

## Getting started with Pioneer

## Usage example and demo

## Known issues

## Roadmap