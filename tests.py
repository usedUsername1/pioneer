# import fireREST

# fmc = fireREST.FMC(hostname='10.2.196.131', username='admin', password='2wsx#EDC', domain='Global')

# policy = fmc.object.urlgroup.get(name="test-url-inline")

# print(policy)

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


from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject

# Create a Panorama object
pano = Panorama("10.2.196.196", "admin", "2wsx#EDC")

dg_object = DeviceGroup('Global Internet')
pano.add(dg_object)

network_object = AddressObject('test-panos6', '1.1.1.1', 'ip-netmask', None)

try:
    dg_object.add(network_object)
    network_object.create()
except:
    print("pl")


# # Refresh devices
# device_groups = pano.refresh_devices()

# # Specify the name of the device group you want to retrieve information for
# desired_device_group_name = "Parking"

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