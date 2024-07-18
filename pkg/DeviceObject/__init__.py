import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

#TODO: there is a big problem with how the uid is generated right now as it is initialized
# when the object is initialized.
class Object:
    """
    Base class for representing objects in the system.
    """

    def __init__(self, ObjectContainer, name, description, is_overridable) -> None:
        """
        Initialize an Object instance.

        Parameters:
        - object_info (dict): Information about the object.
        """
        # Initialize attributes
        self._uid = helper.generate_uid()
        self._ObjectContainer = ObjectContainer
        self._name = name
        self._description = description
        self._is_overridable = is_overridable

    def get_uid(self):
        return self._uid
    
    def set_uid(self, uid):
        self._uid = uid
    
    def get_object_container(self):
        return self._ObjectContainer

    def get_name(self):
        """
        Get the name of the object.

        Returns:
            str: Name of the object.
        """
        return self._name

    def set_name(self, value):
        """
        Set the name of the object.

        Parameters:
            value (str): Name of the object.
        """
        self._name = value

    def get_description(self):
        """
        Get the description of the object.

        Returns:
            str: Description of the object.
        """
        return self._description

    def set_description(self, value):
        """
        Set the description of the object.

        Parameters:
            value (str): Description of the object.
        """
        self._description = value

    def get_override_bool(self):
        """
        Get the override status of the object.

        Returns:
            bool: Override status of the object.
        """
        return self._is_overridable

    def set_override_bool(self, value):
        """
        Set the override status of the object.

        Parameters:
            value (bool): Override status of the object.
        """
        self._is_overridable = value

    def get_object_container_name(self):
        """
        Get the name of the object container.

        Returns:
            str: Name of the object container.
        """
        return self._object_container

    def set_object_container_name(self, value):
        """
        Set the name of the object container.

        Parameters:
            value (str): Name of the object container.
        """
        self._object_container = value

    def add_group_member_name(self, group_member_name):
        self._group_member_names.append(group_member_name)
          
# regarding processing groups: the object members of the groups have to be processed as well
class GroupObject(Object):
    """
    A class representing a group object.
    """

    def __init__(self) -> None:
        """
        Initialize the GroupObject instance.

        Args:
            object_info (dict): Information about the group object.
        """
        self._group_member_names = []
        
        self._object_members = set()
        self._group_object_members = set()
    
        # no better idea of where to put it at the moment :(
        # decide if it belongs with the rest of the group members or if it should be kept separately
        self._icmp_object_members = set()

    def get_group_member_names(self):
        return self._group_member_names

    def get_object_members(self):
        return self._object_members

    def get_group_object_members(self):
        return self._group_object_members
    
    def set_object_members(self, object_members):
        self._object_members = object_members

    def set_group_object_members(self, group_object_members):
        self._object_members = group_object_members
    
    def set_icmp_members(self, icmp_members):
        self._icmp_object_members = icmp_members

    def get_icmp_members(self):
        return self._icmp_object_members

class NetworkObject:
    """
    A class representing a generic network object.
    """

    def __init__(self, network_address_value, network_address_type) -> None:
        """
        Initialize the NetworkObject instance.

        Args:
            object_info (dict): Information about the network object.
            network_address_value (str): The network address value.
            network_address_type (str): The network address type.
        """
        self._network_address_value = network_address_value
        self._network_address_type = network_address_type

    def get_network_address_value(self):
        """
        Get the network address value of the object.

        Returns:
            str: The network address value.
        """
        return self._network_address_value
    
    def set_network_address_value(self, value):
        """
        Set the network address value of the object.

        Parameters:
            value (str): The network address value.
        """
        self._network_address_value = value

    def get_network_address_type(self):
        """
        Get the network address type of the object.

        Returns:
            str: The network address type.
        """
        return self._network_address_type
    
    def set_network_address_type(self, value):
        """
        Set the network address type of the object.

        Parameters:
            value (str): The network address type.
        """
        self._network_address_type = value

    def save(self, Database):
        NetworkAddressObjectsTable = Database.get_network_address_objects_table()
        NetworkAddressObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_network_address_value(), self.get_description(), self.get_network_address_type(), self.get_override_bool())  

class NetworkGroupObject(GroupObject):
    def save(self, Database):
        NetworkGroupObjectsTable = Database.get_network_group_objects_table()
        NetworkGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())

    def create_relationships_in_db(self, Database, preloaded_data):
        member_names = self.get_group_member_names()
        network_group_objects_members_table = Database.get_network_group_objects_members_table()
        for member_name in member_names:
            group_member_uid = preloaded_data.get(member_name)
            network_group_objects_members_table.insert(self.get_uid(), group_member_uid)

class PortObject:
    """
    A class representing a port object.
    """

    def __init__(self, source_port, destination_port, port_protocol) -> None:
        """
        Initialize the PortObject instance.

        Args:
            object_info (dict): Information about the port object.
        """
        self._port_protocol = port_protocol
        self._source_port = source_port
        self._destination_port = destination_port

    def get_port_protocol(self):
        """
        Get the port protocol of the object.

        Returns:
            str: The port protocol.
        """
        return self._port_protocol
    
    def set_port_protocol(self, protocol):
        """
        Set the port protocol of the object.

        Parameters:
            protocol (str): The port protocol.
        """
        self._port_protocol = protocol

    def get_source_port(self):
        """
        Get the source port of the object.

        Returns:
            int: The source port.
        """
        return self._source_port
    
    def set_source_port(self, number):
        """
        Set the source port of the object.

        Parameters:
            number (int): The source port.
        """
        self._source_port = number

    def get_destination_port(self):
        """
        Get the destination port of the object.

        Returns:
            int: The destination port.
        """
        return self._destination_port
    
    def set_destination_port(self, number):
        """
        Set the destination port of the object.

        Parameters:
            number (int): The destination port.
        """
        self._destination_port = number

    def save(self, Database):
        PortObjectsTable = Database.get_port_objects_table()
        PortObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_port_protocol(), self.get_source_port(), self.get_destination_port(), self.get_description(), self.get_override_bool())

class ICMPObject:
    """
    Class representing an ICMP object in the system, inheriting from the base Object class.
    """

    def __init__(self, icmp_type, icmp_code) -> None:
        """
        Initialize an ICMPObject instance.

        Parameters:
        - object_info (dict): Information about the ICMP object.
        """
        self._icmp_type = icmp_type
        self._icmp_code = icmp_code
    
    def get_icmp_type(self):
        """
        Get the ICMP type.

        Returns:
            str: ICMP type.
        """
        return self._icmp_type

    def set_icmp_type(self, icmp_type):
        """
        Set the ICMP type.

        Parameters:
            icmp_type (str): ICMP type.
        """
        self._icmp_type = icmp_type

    def get_icmp_code(self):
        """
        Get the ICMP code.

        Returns:
            str: ICMP code.
        """
        return self._icmp_code

    def set_icmp_code(self, icmp_code):
        """
        Set the ICMP code.

        Parameters:
            icmp_code (str): ICMP code.
        """
    def save(self, Database):
        ICMPObjectsTable = Database.get_icmp_objects_table()
        ICMPObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_icmp_type(), self.get_icmp_code(), self.get_description(), self.get_override_bool())

class PortGroupObject(GroupObject):
    def save(self, Database):
        PortGroupObjectsTable = Database.get_port_group_objects_table()
        PortGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())

    def create_relationships_in_db(self, Database, preloaded_data):
        member_names = self.get_group_member_names()
        port_group_objects_members_table = Database.get_port_group_objects_members_table()
        for member_name in member_names:
            group_member_uid = preloaded_data.get(member_name)
            port_group_objects_members_table.insert(self.get_uid(), group_member_uid)

class URLObject:
    def __init__(self, url_value) -> None:
        """
        Initialize a URL Object.

        Parameters:
        - object_info (dict): Information about the URL object.

        Returns:
        None
        """
        self._url_value = url_value
    
    def get_url_value(self):
        """
        Get the URL value.

        Returns:
        str: The URL value.
        """
        return self._url_value

    def set_url_value(self, url_value):
        """
        Set the URL value.

        Parameters:
        - url_value (str): The URL value to set.

        Returns:
        None
        """
        self._url_value = url_value

    def save(self, Database):
        URLObjectsTable = Database.get_url_objects_table()
        URLObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_url_value(), self.get_description(), self.get_override_bool())

class URLGroupObject(GroupObject):
    def save(self, Database):
        URLGroupObjectsTable = Database.get_url_group_objects_table()
        URLGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())

    def create_relationships_in_db(self, Database, preloaded_data):
        member_names = self.get_group_member_names()
        url_group_objects_members_table = Database.get_url_group_objects_members_table()
        for member_name in member_names:
            group_member_uid = preloaded_data.get(member_name)
            url_group_objects_members_table.insert(self.get_uid(), group_member_uid)
    
#TODO later: proper support for the following objects
#TODO: add the necessary parameters to insert, based on the object type
class ScheduleObject:
    def save(self, Database):
        ScheduleObjectsTable = Database.get_schedule_objects_table()
        ScheduleObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description())

class GeolocationObject:
    def save(self, Database):
        GeolocationObjectsTable = Database.get_geolocation_objects_table()
        GeolocationObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid())

class CountryObject:
    def save(self, Database):
        CountryObjectsTable = Database.get_country_objects_table()
        CountryObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid())

class PolicyUserObject:
    def __init__(self, name) -> None:
        self._name = name

    def save(self, Database):
        PolicyUserObjectsTable = Database.get_policy_user_objects_table()
        PolicyUserObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid())

class URLCategoryObject:
    def __init__(self, reputation) -> None:
        self._reputation = reputation

    def save(self, Database):
        URLCategoryObjectsTable = Database.get_url_category_objects_table()
        URLCategoryObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self._reputation)

class L7AppObject:
    def save(self, Database):
        L7AppObjectsTable = Database.get_l7_app_objects_table()
        L7AppObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid())

class L7AppFilterObject:
    def __init__(self, type) -> None:
        self._type = type
    def save(self, Database):
        L7AppFilterObjectsTable = Database.get_l7_app_filter_objects_table()
        L7AppFilterObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self._type)

class L7AppGroupObject:
    def save(self, Database):
        L7AppGroupObjectsTable = Database.get_l7_app_group_objects_table()
        L7AppGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid())