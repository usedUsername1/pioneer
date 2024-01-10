from pkg import Connection, PioneerDatabase
from pkg.SecurityDevice import SecurityDevice
from pkg.SecurityDevice.APISecurityDevice import FMCSecurityDevice


test_database = PioneerDatabase('vzlate', 'postgres', '2wsx#EDC', '127.0.0.1', 5432)
test_database.create_database("test")


testdevice = FMCSecurityDevice()
testdevicetype = testdevice._security_device_database._general_table.get_security_device_type_by_name("test")
