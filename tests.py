import fireREST

fmc = fireREST.FMC(hostname='10.2.196.131', username='admin', password='2wsx#EDC', domain='Global')

# how to return only policies
policy = fmc.policy.accesspolicy.accessrule.get(container_name='Parking1-child')
# The value to match
value_to_match = 'Parking1-child'

filtered_data_gen = (entry for entry in policy if entry['metadata']['accessPolicy']['name'] == value_to_match)

# Convert generator to a list if needed
filtered_data = list(filtered_data_gen)

for entry in filtered_data:
    print(entry)


# from panos.panorama import Panorama
# pano  = Panorama("10.2.196.196", "admin", "2wsx#EDC")
# test = pano.refresh_devices(devices=["Parking"])

# print(test)
# Access the OPSTATES attribute to get the hierarchy class
# hierarchy_class = pano.OPSTATES['dg_hierarchy']

# # Create an instance of PanoramaDeviceGroupHierarchy
# hierarchy_instance = hierarchy_class(pano)

# # Call the fetch method on the instance
# hierarchy_data = hierarchy_instance.fetch()

# # Print the fetched hierarchy data
# # print(hierarchy_data)
# for key, value in hierarchy_data.items():
#     print("PARENT:", value, "CHILD:",key)


# from panos.panorama import Panorama, DeviceGroup
# from panos.objects import ServiceObject

# # Create a Panorama object
# pano = Panorama("10.2.196.196", "admin", "2wsx#EDC")

# # Create a DeviceGroup object for 'Debug'
# dg = DeviceGroup('Global Internet')

# # Add the device group to Panorama
# pano.add(dg)

# # Create the service object
# testobj = ServiceObject(name='TEST_SCRIPT', protocol='tcp', destination_port='1-65535', description='k', tag=None)

# # Add the service object to the device group
# dg.add(testobj)

# # Find the service object within the device group
# found_obj = dg.find(testobj)

# # Check if the object was found
# if found_obj is not None:
#     # If found, create a similar object
#     similar_obj = found_obj.create_similar()
#     print("Similar object created successfully.")
# else:
#     print("Object not found.")

# dg.find(testobj).create_similar()

# # Find the device group with the desired name
# desired_device_group = None
# for device_group in device_groups:
#     if device_group.name == desired_device_group_name:
#         desired_device_group = device_group
#         break

# # Check if the desired device group was found
# if desired_device_group is not None:
#     hierarchy_state = desired_device_group.OPSTATES['dg_hierarchy'](desired_device_group)
#     hierarchy_state.refresh()  # Call refresh on an instance
#     parent_device_group = hierarchy_state.parent
#     print("Parent Device Group:", parent_device_group, "Child device group:", desired_device_group.name)
# else:
#     print("Device group not found.")

# print(pano.refresh_system_info().version)
# Refresh devices
# device_groups = pano.refresh_devices(include_device_groups=True)
# for dg in device_groups:
#     print(dg.children)
# print("Panorama Version:", panorama_version)
# object = fmc.object.portobjectgroup.get(name="EXCHANGE_ports")2
# print(object)
# ICMP-TEST-TYPE3-CODE3
# ports = fmc.object.port.get(name="obj_icmp_any")

# print(ports)


# source = { 'sourceNetworks' : {'literals': [{'type': 'Host', 'value': '1.1.1.1'}], 'objects': [{'type': 'Host', 'overridable': False, 'id': '005056AB-6282-0ed3-0000-004295037556', 'name': '10.2.39.86'}, {'type': 'Network', 'overridable': False, 'id': '005056AB-6282-0ed3-0000-004295042505', 'name': '100.66.1.0-26'}]}}
# print(source['sourceNetworks'])

# object = fmc.object.networkaddress.get(name="acb-valdns-01.luxoft.coma")
# print(object)










            # print('name:', security_policy_name, 'tag:', security_policy_category, 'group_tag:', security_policy_category, 'disabled:', is_enabled,
            #     'fromzone:', security_policy_source_zones, 'tozone:', security_policy_destination_zones, 'source:', security_policy_source_networks,
            #     'destination:', security_policy_destination_networks, 'service:', security_policy_destination_ports, 'category:', security_policy_urls, 'application:', security_policy_apps,
            #     'description:', security_policy_description, 'log_setting:', log_forwarding, 'log_end:', log_end, 'action:', policy_action)
