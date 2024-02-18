import fireREST

fmc = fireREST.FMC(hostname='10.2.196.131', username='admin', password='2wsx#EDC', domain='Global')

policy = fmc.policy.accesspolicy.accessrule.get(container_name="debug2", name="New-Rule-#5-ALLOW")

policy = fmc.policy.accesspolicy.get(name="Global Internet Access Policy")
print(policy)

# geolocation_object = fmc.object.continent.get()

# print(geolocation_object)


# ports = fmc.object.port.get()

# print(ports)