import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class Object:
    """
    Base class for representing objects in the system.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an Object instance.

        Parameters:
        - object_info (dict): Information about the object.
        """
        general_logger.debug("Called Object::__init__()")
        # Store the provided object information
        self._object_info = object_info
        
        # Initialize attributes
        self._name = None
        self._description = None
        self._is_overridable = None

    def get_name(self):
        """
        Get the name of the object.

        Returns:
            str: Name of the object.
        """
        general_logger.debug("Called Object::get_name()")
        return self._name

    def set_name(self, value):
        """
        Set the name of the object.

        Parameters:
            value (str): Name of the object.
        """
        general_logger.debug("Called Object::set_name()")
        self._name = value

    def get_description(self):
        """
        Get the description of the object.

        Returns:
            str: Description of the object.
        """
        general_logger.debug("Called Object::get_description()")
        return self._description

    def set_description(self, value):
        """
        Set the description of the object.

        Parameters:
            value (str): Description of the object.
        """
        general_logger.debug("Called Object::set_description()")
        self._description = value

    def get_override_bool(self):
        """
        Get the override status of the object.

        Returns:
            bool: Override status of the object.
        """
        general_logger.debug("Called Object::get_override_bool()")
        return self._is_overridable

    def set_override_bool(self, value):
        """
        Set the override status of the object.

        Parameters:
            value (bool): Override status of the object.
        """
        general_logger.debug("Called Object::set_override_bool()")
        self._is_overridable = value

    def get_object_container_name(self):
        """
        Get the name of the object container.

        Returns:
            str: Name of the object container.
        """
        general_logger.debug("Called Object::get_object_container_name()")
        return self._object_container

    def set_object_container_name(self, value):
        """
        Set the name of the object container.

        Parameters:
            value (str): Name of the object container.
        """
        general_logger.debug("Called Object::set_object_container_name()")
        self._object_container = value

    def get_info(self):
        """
        Get information about the object.

        Returns:
            dict: Information about the object.
        """
        general_logger.debug("Called Object::get_object_device_info()")
        return self._object_info
    
# regarding processing groups: the object members of the groups have to be processed as well
class GroupObject(Object):
    """
    A class representing a group object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the GroupObject instance.

        Args:
            object_info (dict): Information about the group object.
        """
        super().__init__(object_info)
        self._members = None
    
    def get_member_names(self):
        """
        Get the member names of the group object.

        Returns:
            list: The names of the members.
        """
        return self._members
    
    def set_member_names(self, members):
        """
        Set the member objects of the group object.

        Parameters:
            members (list): The list of member names.
        """
        self._members = members

class NetworkObject(Object):
    """
    A class representing a network object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the NetworkObject instance.

        Args:
            object_info (dict): Information about the network object.
        """
        general_logger.debug("Called NetworkObject::__init__()")
        super().__init__(object_info)
        self._network_address_value = None
        self._network_address_type = None

    def get_network_address_value(self):
        """
        Get the network address value of the object.

        Returns:
            str: The network address value.
        """
        general_logger.debug("Called NetworkObject::get_network_address_value()")
        return self._network_address_value
    
    def set_network_address_value(self, value):
        """
        Set the network address value of the object.

        Parameters:
            value (str): The network address value.
        """
        general_logger.debug("Called NetworkObject::set_network_address_value()")
        self._network_address_value = value

    def get_network_address_type(self):
        """
        Get the network address type of the object.

        Returns:
            str: The network address type.
        """
        general_logger.debug("Called NetworkObject::get_network_address_type()")
        return self._network_address_type
    
    def set_network_address_type(self, value):
        """
        Set the network address type of the object.

        Parameters:
            value (str): The network address type.
        """
        general_logger.debug("Called NetworkObject::set_network_address_type()")
        self._network_address_type = value
    
    def process_object(self):
        """
        Process the network object.

        Returns:
            dict: Processed information about the network object.
        """
        general_logger.debug("Called NetworkObject::process_object()")
        
        # Set the values with for the object with the data you got in the object_info variable, which holds the info of the device as extracted from the Security Device
        self.set_name()
        self.set_object_container_name()        
        self.set_network_address_value()
        self.set_description()
        self.set_network_address_type()
        self.set_override_bool()

        processed_object_info = {
            "network_address_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "network_address_value": self.get_network_address_value(),
            "network_address_description": self.get_description(),
            "network_address_type": self.get_network_address_type(),
            "overridable_object": self.get_override_bool()
        }

        return processed_object_info

class NetworkGroupObject(GroupObject):
    """
    A class representing a network group object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the NetworkGroupObject instance.

        Args:
            object_info (dict): Information about the network group object.
        """
        super().__init__(object_info)

    def process_object(self):
        """
        Process the network group object.

        Returns:
            dict: Information about the processed network group object.
        """
        processed_group_object_info = []

        self.set_name()
        self.set_object_container_name()
        # no need to set the member names, they will be set in the implementation of return_network_objects function
        self.set_description()
        self.set_override_bool()

        processed_group_object_info = {
            "network_address_group_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "network_address_group_members": self.get_member_names(),
            "network_address_group_description": self.get_description(),
            "overridable_object": self.get_override_bool()
        }

        return processed_group_object_info

# For simplicity, all geo data is going to be treated as a Geolocation object.
# For example, in FMC, you have Geolocation objects (made out of countries and other continents), and then you have the countries and the continents. they are not object entities per se
# but can be treated as such
# There is a problem with treating all the entities (Geolocation, Continent and Country) as the same Python object, however.
# Geolocation can have continents (which can also be made out of multiple countries) or countries. All the information is retrieved at the country object level!
# All objects can have member alpha2, alpha3 and numeric codes, but only country objects have these actual values defined on them.
# Hence, there are getters and setters for both the actual values and for the members.
# This can be certainly done in a smarter way. So at some point, this might change, especially because you can use the set_continetns and set_countries from the FMC geolocation objects
# logic for all the security devices. However, this will change at some point later.
class GeolocationObject(Object):
    """
    A class representing a geolocation object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the GeolocationObject instance.

        Args:
            object_info (dict): Information about the geolocation object.
        """
        general_logger.debug("Called GeolocationObject::__init__()")
        super().__init__(object_info)
        self._continents = None
        self._countries = None
        self._country_alpha2_codes = None
        self._country_alpha3_codes = None
        self._country_numeric_codes = None

    def set_continents(self, value):
        """
        Set the continents associated with the geolocation object.

        Args:
            value (list): List of continents.
        """
        general_logger.debug("Called GeolocationObject::set_continents()")
        self._continents = value

    def get_continents(self):
        """
        Get the continents associated with the geolocation object.

        Returns:
            list: List of continents.
        """
        general_logger.debug("Called GeolocationObject::get_continents()")
        return self._continents

    def set_countries(self, value):
        """
        Set the countries associated with the geolocation object.

        Args:
            value (list): List of countries.
        """
        general_logger.debug("Called GeolocationObject::set_countries()")
        self._countries = value

    def get_countries(self):
        """
        Get the countries associated with the geolocation object.

        Returns:
            list: List of countries.
        """
        general_logger.debug("Called GeolocationObject::get_countries()")
        return self._countries

    def set_member_alpha2_codes(self, value):
        """
        Set the member alpha-2 codes of the geolocation object.

        Args:
            value (list): List of alpha-2 codes.
        """
        general_logger.debug("Called GeolocationObject::set_member_alpha2_codes()")
        self._country_alpha2_codes = value

    def get_alpha2_codes(self):
        """
        Get the member alpha-2 codes of the geolocation object.

        Returns:
            list: List of alpha-2 codes.
        """
        general_logger.debug("Called GeolocationObject::get_alpha2_codes()")
        return self._country_alpha2_codes

    def set_member_alpha3_codes(self, value):
        """
        Set the member alpha-3 codes of the geolocation object.

        Args:
            value (list): List of alpha-3 codes.
        """
        general_logger.debug("Called GeolocationObject::set_member_alpha3_codes()")
        self._country_alpha3_codes = value

    def get_alpha3_codes(self):
        """
        Get the member alpha-3 codes of the geolocation object.

        Returns:
            list: List of alpha-3 codes.
        """
        general_logger.debug("Called GeolocationObject::get_alpha3_codes()")
        return self._country_alpha3_codes

    def set_member_numeric_codes(self, value):
        """
        Set the member numeric codes of the geolocation object.

        Args:
            value (list): List of numeric codes.
        """
        general_logger.debug("Called GeolocationObject::set_member_numeric_codes()")
        self._country_numeric_codes = value

    def get_numeric_codes(self):
        """
        Get the member numeric codes of the geolocation object.

        Returns:
            list: List of numeric codes.
        """
        general_logger.debug("Called GeolocationObject::get_numeric_codes()")
        return self._country_numeric_codes

    def get_member_continent_names(self):
        """
        Get the names of the continents associated with the geolocation object.

        Returns:
            list: List of continent names.
        """
        general_logger.debug("Called GeolocationObject::get_member_continent_names()")
        if self._continents is None:
            return None
        
        continent_member_names = []
        for continent in self._continents:
            continent.set_name()
            continent_member_names.append(continent.get_name())
        
        return continent_member_names

    def get_member_country_names(self):
        """
        Get the names of the countries associated with the geolocation object.

        Returns:
            list: List of country names.
        """
        general_logger.debug("Called GeolocationObject::get_member_country_names()")
        if self._countries is None:
            return None
        
        country_member_names = []
        for country in self._countries:
            country.set_name()
            country_member_names.append(country.get_name())
        
        return country_member_names

    def get_member_alpha2_codes(self):
        """
        Get the alpha-2 codes of the countries associated with the geolocation object.

        Returns:
            list: List of alpha-2 codes.
        """
        general_logger.debug("Called GeolocationObject::get_member_alpha2_codes()")
        if self._countries is None:
            return None
        
        country_alpha2_codes = []
        for country in self._countries:
            country.set_member_alpha2_codes()
            country_alpha2_codes.append(country.get_alpha2_codes())

        return country_alpha2_codes

    def get_member_alpha3_codes(self):
        """
        Get the alpha-3 codes of the countries associated with the geolocation object.

        Returns:
            list: List of alpha-3 codes.
        """
        general_logger.debug("Called GeolocationObject::get_member_alpha3_codes()")
        if self._countries is None:
            return None
        
        country_alpha3_codes = []
        for country in self._countries:
            country.set_member_alpha3_codes()
            country_alpha3_codes.append(country.get_alpha3_codes())

        return country_alpha3_codes

    def get_member_numeric_codes(self):
        """
        Get the numeric codes of the countries associated with the geolocation object.

        Returns:
            list: List of numeric codes.
        """
        general_logger.debug("Called GeolocationObject::get_member_numeric_codes()")
        if self._countries is None:
            return None
        
        country_numeric_codes = []
        for country in self._countries:
            country.set_member_numeric_codes()
            country_numeric_codes.append(country.get_numeric_codes())

        return country_numeric_codes

    def process_object(self):
        """
        Process the geolocation object.

        Returns:
            dict: Processed information about the geolocation object.
        """
        general_logger.debug("Called GeolocationObject::process_object()")
        # Setters are necessary because the objects' attributes are not set upon their creation. We can only get this data after we construct the object with the data from the security device.

        self.set_name()
        self.set_object_container_name()
        self.set_continents()
        self.set_countries()
        self.set_member_alpha2_codes()
        self.set_member_alpha3_codes()
        self.set_member_numeric_codes()

        processed_geolocation_object_info = {
            "geolocation_object_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "continent_member_names": self.get_member_continent_names(),
            "country_member_names": self.get_member_country_names(),
            "country_member_alpha2_codes": self.get_member_alpha2_codes(),
            "country_member_alpha3_codes": self.get_member_alpha3_codes(),
            "country_member_numeric_codes": self.get_member_numeric_codes(),           
        }

        return processed_geolocation_object_info

class PortObject(Object):
    """
    A class representing a port object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the PortObject instance.

        Args:
            object_info (dict): Information about the port object.
        """
        general_logger.debug("Called PortObject::__init__()")
        super().__init__(object_info)
        self._port_protocol = None
        self._port_number = None

    def get_port_protocol(self):
        """
        Get the port protocol of the object.

        Returns:
            str: The port protocol.
        """
        general_logger.debug("Called PortObject::get_port_protocol()")
        return self._port_protocol
    
    def set_port_protocol(self, protocol):
        """
        Set the port protocol of the object.

        Parameters:
            protocol (str): The port protocol.
        """
        general_logger.debug("Called PortObject::set_port_protocol()")
        self._port_protocol = protocol

    def get_port_number(self):
        """
        Get the port number of the object.

        Returns:
            int: The port number.
        """
        general_logger.debug("Called PortObject::get_port_number()")
        return self._port_number
    
    def set_port_number(self, number):
        """
        Set the port number of the object.

        Parameters:
            number (int): The port number.
        """
        general_logger.debug("Called PortObject::set_port_number()")
        self._port_number = number
    
    def process_object(self):
        """
        Process the network object.

        Returns:
            dict: Processed information about the port object.
        """
        general_logger.debug("Called PortObject::process_object()")
        # Set the values with for the object with the data you got in the object_info variable, which holds the info of the device as extracted from the Security Device
        self.set_name()
        self.set_object_container_name()
        self.set_port_protocol()
        self.set_port_number()        
        self.set_description()
        self.set_override_bool()

        processed_object_info = {
            "port_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "port_protocol": self.get_port_protocol(),
            "port_number": self.get_port_number(),
            "port_description": self.get_description(),
            "overridable_object": self.get_override_bool()
        }

        return processed_object_info
    
class PortGroupObject(GroupObject):
    """
    A class representing a port group object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the PortGroupObject instance.

        Args:
            object_info (dict): Information about the port group object.
        """
        super().__init__(object_info)

    def process_object(self):
        """
        Process the port group object.

        Returns:
            dict: Information about the processed port group object.
        """
        processed_group_object_info = []

        self.set_name()
        self.set_object_container_name()
        # no need to set the member names, they will be set in the implementation of return_network_objects function
        self.set_description()
        self.set_override_bool()

        processed_group_object_info = {
            "port_group_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "port_group_members": self.get_member_names(),
            "port_group_description": self.get_description(),
            "overridable_object": self.get_override_bool()
        }

        return processed_group_object_info

class ICMPObject(Object):
    """
    Class representing an ICMP object in the system, inheriting from the base Object class.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an ICMPObject instance.

        Parameters:
        - object_info (dict): Information about the ICMP object.
        """
        general_logger.debug("Called ICMPObject::__init__()")
        super().__init__(object_info)
        self._icmp_type = None
        self._icmp_code = None
    
    def get_icmp_type(self):
        """
        Get the ICMP type.

        Returns:
            str: ICMP type.
        """
        general_logger.debug("Called ICMPObject::get_icmp_type()")
        return self._icmp_type

    def set_icmp_type(self, icmp_type):
        """
        Set the ICMP type.

        Parameters:
            icmp_type (str): ICMP type.
        """
        general_logger.debug("Called ICMPObject::set_icmp_type()")
        self._icmp_type = icmp_type

    def get_icmp_code(self):
        """
        Get the ICMP code.

        Returns:
            str: ICMP code.
        """
        general_logger.debug("Called ICMPObject::get_icmp_code()")
        return self._icmp_code

    def set_icmp_code(self, icmp_code):
        """
        Set the ICMP code.

        Parameters:
            icmp_code (str): ICMP code.
        """
        general_logger.debug("Called ICMPObject::set_icmp_code()")
        self._icmp_code = icmp_code

    def process_object(self):
        """
        Process the ICMP object to gather its information.

        This method sets various attributes of the ICMP object, including name, object container name,
        ICMP type, ICMP code, description, and override boolean. After setting these attributes, it constructs
        a dictionary containing the processed information about the ICMP object.

        Returns:
            dict: A dictionary containing the processed information about the ICMP object.
                  It includes the following keys:
                  - "icmp_name": The name of the ICMP object.
                  - "object_container_name": The name of the object container.
                  - "icmp_type": The ICMP type.
                  - "icmp_code": The ICMP code.
                  - "icmp_description": The description of the ICMP object.
                  - "overridable_object": A boolean indicating whether the object is overridable.
        """
        self.set_name()
        self.set_object_container_name()
        self.set_icmp_type()
        self.set_icmp_code()
        self.set_description()
        self.set_override_bool()

        processed_object_info = {
            "icmp_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "icmp_type": self.get_icmp_type(),
            "icmp_code": self.get_icmp_code(),
            "icmp_description": self.get_description(),
            "overridable_object": self.get_override_bool()
        }

        return processed_object_info

# class SecurityZone(Object):
#     def __init__(self, name, description, is_overridable, object_container_name=None) -> None:
#         super().__init__(name, description, is_overridable, object_container_name)


    