import fireREST

fmc = fireREST.FMC(hostname='10.2.196.131', username='admin', password='2wsx#EDC', domain='Global')

policy = fmc.policy.accesspolicy.accessrule.get(container_name="debug2", name="test")

# policy = fmc.policy.accesspolicy.accessrule.get(container_name="Global Internet Access Policy")
print(policy)

# geolocation_object = fmc.object.continent.get()

# print(geolocation_object)


# ports = fmc.object.port.get()

# print(ports)


# source = { 'sourceNetworks' : {'literals': [{'type': 'Host', 'value': '1.1.1.1'}], 'objects': [{'type': 'Host', 'overridable': False, 'id': '005056AB-6282-0ed3-0000-004295037556', 'name': '10.2.39.86'}, {'type': 'Network', 'overridable': False, 'id': '005056AB-6282-0ed3-0000-004295042505', 'name': '100.66.1.0-26'}]}}
# print(source['sourceNetworks'])