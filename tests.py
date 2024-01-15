from fireREST import FMC

# Replace these with your FMC details
fmc_host = 'oro-sfmc-01.luxoft.com'
fmc_username = 'api-admin'
fmc_password = '5z%jUk!#cm4gS$84owQH'

# Instantiate an FMC object
fmc = FMC(hostname=fmc_host, username=fmc_username, password=fmc_password)

# Example: Print the FMC version
print(fmc.policy.accesspolicy.accessrule.get(container_name='Azure: Global VPN Policy'))