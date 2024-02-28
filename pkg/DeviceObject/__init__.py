import utils.helper as helper
from abc import abstractmethod

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
        helper.logging.debug("Called Object::__init__()")
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
        helper.logging.debug("Called Object::get_name()")
        return self._name

    def set_name(self, value):
        """
        Set the name of the object.

        Parameters:
            value (str): Name of the object.
        """
        helper.logging.debug("Called Object::set_name()")
        self._name = value

    def get_description(self):
        """
        Get the description of the object.

        Returns:
            str: Description of the object.
        """
        helper.logging.debug("Called Object::get_description()")
        return self._description

    def set_description(self, value):
        """
        Set the description of the object.

        Parameters:
            value (str): Description of the object.
        """
        helper.logging.debug("Called Object::set_description()")
        self._description = value

    def get_override_bool(self):
        """
        Get the override status of the object.

        Returns:
            bool: Override status of the object.
        """
        helper.logging.debug("Called Object::get_override_bool()")
        return self._is_overridable

    def set_override_bool(self, value):
        """
        Set the override status of the object.

        Parameters:
            value (bool): Override status of the object.
        """
        helper.logging.debug("Called Object::set_override_bool()")
        self._is_overridable = value

    def get_object_container_name(self):
        """
        Get the name of the object container.

        Returns:
            str: Name of the object container.
        """
        helper.logging.debug("Called Object::get_object_container_name()")
        return self._object_container

    def set_object_container_name(self, value):
        """
        Set the name of the object container.

        Parameters:
            value (str): Name of the object container.
        """
        helper.logging.debug("Called Object::set_object_container_name()")
        self._object_container = value

    def get_info(self):
        """
        Get information about the object.

        Returns:
            dict: Information about the object.
        """
        helper.logging.debug("Called Object::get_object_device_info()")
        return self._object_info
    
# regarding processing groups: the object members of the groups have to be processed as well
class GroupObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._members = None
    
    # get the member names. for storing the names in the database, in the network_address_group_members column
    # this will return a list with the names of all the objects of the members
    def get_member_names(self):
        return self._members
    
    # set the member objects of the group objects
    def set_member_names(self, members):
        self._members = members

    #TODO: implement this
    @abstractmethod
    def is_group(self):
        pass


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
        helper.logging.debug("Called NetworkObject::__init__()")
        super().__init__(object_info)
        self._network_address_value = None
        self._network_address_type = None

    def get_network_address_value(self):
        """
        Get the network address value of the object.

        Returns:
            str: The network address value.
        """
        helper.logging.debug("Called NetworkObject::get_network_address_value()")
        return self._network_address_value
    
    def set_network_address_value(self, value):
        """
        Set the network address value of the object.

        Parameters:
            value (str): The network address value.
        """
        helper.logging.debug("Called NetworkObject::set_network_address_value()")
        self._network_address_value = value

    def get_network_address_type(self):
        """
        Get the network address type of the object.

        Returns:
            str: The network address type.
        """
        helper.logging.debug("Called NetworkObject::get_network_address_type()")
        return self._network_address_type
    
    def set_network_address_type(self, value):
        """
        Set the network address type of the object.

        Parameters:
            value (str): The network address type.
        """
        helper.logging.debug("Called NetworkObject::set_network_address_type()")
        self._network_address_type = value
    
    def process_object(self):
        """
        Process the network object.

        Returns:
            dict: Processed information about the network object.
        """
        helper.logging.debug("Called NetworkObject::process_object()")
        
        # Set the values with for the object with the data you got in the object_info variable, which holds the info of the device as extracted from the Security Device
        self.set_name()
        self.set_object_container_name()        
        self.set_network_address_value()
        self.set_description()
        self.set_network_address_type()
        self.set_override_bool()

        processed_group_object_info = {
            "network_address_name": self.get_name(),
            "object_container_name": self.get_object_container_name(),
            "network_address_value": self.get_network_address_value(),
            "network_address_description": self.get_description(),
            "network_address_type": self.get_network_address_type(),
            "overridable_object": self.get_override_bool()
        }

        return processed_group_object_info

class NetworkGroupObject(GroupObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)

    # regarding processing groups    
    def process_object(self):
        processed_group_object_info = []

        self.set_name()
        self.set_object_container_name()
        self.set_member_names()
        self.set_description()
        self.set_override_bool()

        # make sure you process the members of each network group
        for member in self._members:
            processed_group_object_info.append(self.process_members(member))

        processed_group_object_info = {
        "network_address_group_name": self.get_name(),
        "object_container_name": self.get_object_container_name(),
        "network_address_group_members": self.get_member_names(),
        "network_address_group_description": self.get_description(),
        "overridable_object": self.get_override_bool()
        }

        return processed_group_object_info

    @abstractmethod
    def process_members(self, member):
        pass

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
        helper.logging.debug("Called GeolocationObject::__init__()")
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
        helper.logging.debug("Called GeolocationObject::set_continents()")
        self._continents = value

    def get_continents(self):
        """
        Get the continents associated with the geolocation object.

        Returns:
            list: List of continents.
        """
        helper.logging.debug("Called GeolocationObject::get_continents()")
        return self._continents

    def set_countries(self, value):
        """
        Set the countries associated with the geolocation object.

        Args:
            value (list): List of countries.
        """
        helper.logging.debug("Called GeolocationObject::set_countries()")
        self._countries = value

    def get_countries(self):
        """
        Get the countries associated with the geolocation object.

        Returns:
            list: List of countries.
        """
        helper.logging.debug("Called GeolocationObject::get_countries()")
        return self._countries

    def set_member_alpha2_codes(self, value):
        """
        Set the member alpha-2 codes of the geolocation object.

        Args:
            value (list): List of alpha-2 codes.
        """
        helper.logging.debug("Called GeolocationObject::set_member_alpha2_codes()")
        self._country_alpha2_codes = value

    def get_alpha2_codes(self):
        """
        Get the member alpha-2 codes of the geolocation object.

        Returns:
            list: List of alpha-2 codes.
        """
        helper.logging.debug("Called GeolocationObject::get_alpha2_codes()")
        return self._country_alpha2_codes

    def set_member_alpha3_codes(self, value):
        """
        Set the member alpha-3 codes of the geolocation object.

        Args:
            value (list): List of alpha-3 codes.
        """
        helper.logging.debug("Called GeolocationObject::set_member_alpha3_codes()")
        self._country_alpha3_codes = value

    def get_alpha3_codes(self):
        """
        Get the member alpha-3 codes of the geolocation object.

        Returns:
            list: List of alpha-3 codes.
        """
        helper.logging.debug("Called GeolocationObject::get_alpha3_codes()")
        return self._country_alpha3_codes

    def set_member_numeric_codes(self, value):
        """
        Set the member numeric codes of the geolocation object.

        Args:
            value (list): List of numeric codes.
        """
        helper.logging.debug("Called GeolocationObject::set_member_numeric_codes()")
        self._country_numeric_codes = value

    def get_numeric_codes(self):
        """
        Get the member numeric codes of the geolocation object.

        Returns:
            list: List of numeric codes.
        """
        helper.logging.debug("Called GeolocationObject::get_numeric_codes()")
        return self._country_numeric_codes

    def get_member_continent_names(self):
        """
        Get the names of the continents associated with the geolocation object.

        Returns:
            list: List of continent names.
        """
        helper.logging.debug("Called GeolocationObject::get_member_continent_names()")
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
        helper.logging.debug("Called GeolocationObject::get_member_country_names()")
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
        helper.logging.debug("Called GeolocationObject::get_member_alpha2_codes()")
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
        helper.logging.debug("Called GeolocationObject::get_member_alpha3_codes()")
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
        helper.logging.debug("Called GeolocationObject::get_member_numeric_codes()")
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
        helper.logging.debug("Called GeolocationObject::process_object()")
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


# class SecurityZone(Object):
#     def __init__(self, name, description, is_overridable, object_container_name=None) -> None:
#         super().__init__(name, description, is_overridable, object_container_name)


    