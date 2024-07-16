import fireREST

fmc = fireREST.FMC(hostname='10.2.196.131', username='admin', password='2wsx#EDC', domain='Global')

# # how to return only policies
# policy = fmc.policy.accesspolicy.operational.hitcount.get(container_uuid="005056AB-6282-0ed3-0000-004295047368", device_id="3282fe0e-62af-11ee-ba12-f4c3e13450ec")
# policy = fmc.policy.accesspolicy.accessrule.get(container_name="Azure PROD: EUN VPN Access Policy")
# print(policy)

from panos.panorama import Panorama
from panos.panorama import Panorama, DeviceGroup, Template
from panos.network import Zone
from panos.objects import ServiceObject, AddressObject
from panos.policies import SecurityRule, Rulebase, PreRulebase
pano  = Panorama("10.2.196.196", "admin", "2wsx#EDC")
device_groups = pano.refresh_devices(include_device_groups=True)


network_object = AddressObject('TEST-CREATE', '1.1.1.1', 'ip-netmask' , 'test')

# Create the address object in the 'Shared' context
pano.add(network_object)
network_object.create()

print(f"Address object '{network_object.name}' created in 'Shared' context.")