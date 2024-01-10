import utils.helper as helper
from pkg import PioneerDatabase, DBConnection


# the MigrationProject class uses as an interface between the user and the database of the project
# the user should interact only with the MigrationProject object, all the operations performed on the project database will be performed
# only via the MigrationProject class
class MigrationProject():
    def __init__(self, name, project_database):
        self.__name = name
        self.__project_database = project_database
        self.__project_devices = []


    # this function adds a device to the project
    # whenever a device is added, what happens?
    def add_device(self, project_device):
        pass
        # self.__project_devices.append(project_device)
        # self.__project_database.


class MigrationProjectDatabase(PioneerDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
    
    def create_specific_tables(self):
        pass

    def table_factory(self, table_name):
        pass



# mapping between packages and interfaces and actions? 
    
# pioneer.py --project test --add-device device1
# pioneer.py --project test --add-device device2
    
# this should come later in the project, for now import only the tables into the project
# the project will basically be just another device. a super-device whose tables will contain all the info
# from the added devices. moreover, there will be a mapping table, in which security zones and policy packages are mapped
# how to actually perform the migration? what does migrating a firewall policy in this context actually mean?
# should there be mappings between the packages of the devices?
# should there be mappings between the zones of the devices?
# pioneer.py --project test --migrate-to device2
    # change the policy packages in the databases according to the mappings
    # change the security zones in the databases according to the mappings