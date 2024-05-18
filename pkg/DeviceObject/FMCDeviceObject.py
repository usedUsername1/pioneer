import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GeolocationObject, PortObject, ICMPObject, URLObject, \
NetworkGroupObject, PortGroupObject, URLGroupObject, GroupObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class FMCObject(Object):
    """
    A class representing a FMC object.
    """

    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize the FMCObject instance.

        Args:
            object_info (dict): Information about the FMC object.
        """
        self._name = object_info['name']
        self._description = object_info.get('description')
        self._is_overridable = object_info['overridable']
        super().__init__(ObjectContainer, object_info, self._name, self._description, self._is_overridable)

    def set_object_member_names(self):
        general_logger.info(f"Getting the names of object members of group <{self._name}>.")
        try:
            object_members = self._object_info['objects']
            for object_member in object_members:
                self.add_group_member_name(object_member['name'])
        except:
            general_logger.info(f"There are no object members for group <{self._name}>.")

    @staticmethod
    def convert_port_literals_to_objects(port_literals):
        """
        Convert port literals to port object names.

        Args:
            port_literals (list): List of port literals.

        Returns:
            list: List of port object names.
        """
        port_objects_list = []

        # Process each port literal
        for port_literal in port_literals:
            # Extract protocol and initialize port number
            literal_protocol = port_literal['protocol']
            try:
                literal_port_nr = port_literal['port']
            except:
                literal_port_nr = "1-65535"
            
            try:
                # Convert protocol number to its corresponding keyword
                literal_protocol_keyword = helper.protocol_number_to_keyword(literal_protocol)
            except PioneerExceptions.UnknownProtocolNumber:
                # Log error if protocol number cannot be converted
                general_logger.error(f"Protocol number: {literal_protocol} cannot be converted to a known IANA keyword.")
            
            # Handle ICMP literals separately
            if literal_protocol in ["1", "58"]:
                # Log info for encountered ICMP literals
                general_logger.info(f"I have encountered an ICMP literal: {port_literal['type']}.")
                
                # Extract ICMP type
                literal_port_nr = port_literal['icmpType']
                
                # Check for ICMP code
                try:
                    icmp_code = port_literal['code']
                    port_object_name = f"{gvars.port_literal_prefix}{literal_protocol_keyword}_{literal_port_nr}_{icmp_code}"
                    port_objects_list.append(port_object_name)
                except KeyError:
                    # If no ICMP code, continue without it
                    general_logger.debug(f"No ICMP code for the following port literal: {port_literal['type']}.")
            
            # Create the name of the port object
            port_object_name = f"{gvars.port_literal_prefix}{literal_protocol_keyword}_{literal_port_nr}"
            port_objects_list.append(port_object_name)

        # Log completion and return port objects list
        general_logger.debug(f"Finished converting all literals to objects. This is the list with converted literals {port_objects_list}.")
        return port_objects_list

    @staticmethod
    def convert_network_literal_to_object(ObjectContainer, network_literal):
        """
        Convert network literals to objects.

        Args:
            network_literals (list): List of network literals.

        Returns:
            list: List of network object names.
        """
        general_logger.debug(f"Converting literal <{network_literal}> to object.")

        # Extract the value of the network literal
        literal_value = network_literal['value']

        # Extract the type of the network literal. Can be either "Host" or "Network"
        # The name of the converted object will depend on the network literal type
        literal_type = network_literal['type']

        # The literal type can be either a host or a network
        if literal_type == 'Network':
            general_logger.debug(f"<{network_literal}> is of type Network.")
            # Define the CIDR notation IP address
            ip_cidr = literal_value

            # Create an IPv4 network object
            network = ipaddress.ip_network(ip_cidr, strict=False)

            # Extract the network address and netmask
            network_address = network.network_address
            netmask = str(network.prefixlen)  # Extract the prefix length instead of the full netmask

        elif literal_type == 'Host':
            general_logger.debug(f"<{network_literal}> is of type Host.")
            netmask = '32'
            network_address = literal_value  # Assuming literal_value is the host address

        else:
            general_logger.debug(f"Cannot determine type of <{network_literal}>. Presented type is <{literal_type}>.")

        # Create the name of the object (NL_networkaddress_netmask)
        network_object_name = gvars.network_literal_prefix + str(network_address) + "_" + str(netmask)

        # now all the info regarding the literal object is extracted, it is time to create
        # the object_info dictionary
        literal_object_info = {'name':network_object_name, 'value':literal_value, 'type':literal_type, 'description':gvars.literal_objects_description, 'overridable':False}
        
        return FMCNetworkObject(ObjectContainer, literal_object_info)

    @staticmethod
    def convert_url_literal_to_objects(ObjectContainer, url_literal):
        literal_value = url_literal['url']
        url_object_name = gvars.url_literal_prefix + literal_value
        object_info = {'name':url_object_name, 'url':literal_value, 'description':gvars.literal_objects_description, 'overridable':False}
        return FMCURLObject(ObjectContainer, object_info)

class FMCNetworkObject(FMCObject, NetworkObject):
    """
    A class representing a network object in Firepower Management Center (FMC).
    """

    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize the FMCNetworkObject instance.

        Args:
            object_info (dict): Information about the network object.
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        self._network_address_value = object_info['value']
        self._network_address_type = object_info['type']
        NetworkObject.__init__(self, self._network_address_value, self._network_address_type)

class FMCNetworkGroupObject(NetworkGroupObject, FMCObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initializes a new FMCNetworkGroupObject.

        Args:
            object_info (dict): Information about the network group object.
        """
        super().__init__(ObjectContainer, object_info)

    def check_for_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking network group <{self._name}> for literal members.")
        # get the group object info
        object_info = self.get_info()
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObject.convert_network_literal_to_object(ObjectContainer, literal_member)
                converted_literal.set_attributes()

                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.get_name())
                converted_literal.save(Database)
        except:
            general_logger.info(f"No literal members found for network group <{self._name}>.")

    # since we are dealing with a group object, there are a few operations that must be done
    # before the object is saved in the database
    # we need to get the names of the objects that are members of the group objects and track them
    # we need to check for literals. the name of the converted literal object will be tracked as well
    # finally, the object group will be inserted
    def save(self, Database):
        # set the names of the object members
        self.set_object_member_names()
        # check for literals
        self.check_for_literals(self.get_object_container(), Database)
        NetworkGroupObjectsTable = Database.get_network_group_objects_table()
        NetworkGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())   

class FMCCountryObject(GeolocationObject):
    """
    A class representing a FMC country object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCCountryObject instance.

        Args:
            object_info (dict): Information about the country object.
        """
        super().__init__(object_info)
    
    def set_name(self):
        """
        Set the name of the country object.

        Returns:
            str: The name of the country object.
        """
        try:
            name = self._object_info['name']
        except KeyError:
            name = None
        return super().set_name(name)

    def set_object_container_name(self):
        """
        Set the name of the object container for the country object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)
    
    def set_continents(self):
        """
        Set the continents associated with the country object.

        Returns:
            None
        """
        return super().set_continents(None)
    
    def set_countries(self):
        """
        Set the countries associated with the country object.

        Returns:
            None
        """
        pass

    def set_member_alpha2_codes(self):
        """
        Set the member alpha-2 code of the country object.

        Returns:
            str: The alpha-2 code of the country.
        """
        alpha2_code = self._object_info['iso2']
        return super().set_member_alpha2_codes(alpha2_code)
    
    def set_member_alpha3_codes(self):
        """
        Set the member alpha-3 code of the country object.

        Returns:
            str: The alpha-3 code of the country.
        """
        alpha3_code = self._object_info['iso3']
        return super().set_member_alpha3_codes(alpha3_code)
    
    def set_member_numeric_codes(self):
        """
        Set the member numeric code of the country object.

        Returns:
            int: The numeric code of the country.
        """
        numeric_code = self._object_info['id']
        return super().set_member_numeric_codes(numeric_code)
    
    def get_member_country_names(self):
        """
        Get the name of the country.

        Returns:
            str: The name of the country.
        """
        return self._name

    def get_member_alpha2_codes(self):
        """
        Get the alpha-2 code of the country.

        Returns:
            str: The alpha-2 code of the country.
        """
        return self._country_alpha2_codes
    
    def get_member_alpha3_codes(self):
        """
        Get the alpha-3 code of the country.

        Returns:
            str: The alpha-3 code of the country.
        """
        return self._country_alpha3_codes
    
    def get_member_numeric_codes(self):
        """
        Get the numeric code of the country.

        Returns:
            int: The numeric code of the country.
        """
        return self._country_numeric_codes

class FMCContinentObject(GeolocationObject):
    """
    A class representing an FMC continent object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCContinentObject instance.

        Args:
            object_info (dict): Information about the continent object.
        """
        super().__init__(object_info)
        
    def set_name(self):
        """
        Set the name of the continent object.
        
        Returns:
            str: The name of the continent object.
        """
        name = self._object_info['name']
        return super().set_name(name)

    def set_object_container_name(self):
        """
        Set the name of the object container for the continent object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)
    
    def set_continents(self):
        """
        Set the continents associated with the continent object.

        Returns:
            None
        """
        self._continents = None
    
    def get_member_continent_names(self):
        """
        Get the name of the continent.

        Returns:
            str: The name of the continent.
        """
        return self._object_info['name']
    
    @abstractmethod
    def set_continents(self):
        """
        Abstract method to set the continents associated with the continent object.
        """
        pass

    def set_countries(self):
        """
        Set the countries associated with the continent object.

        This method retrieves information about the countries associated with the continent from the object's information.
        It constructs a list of FMCCountryObject instances based on the retrieved country information.
        If there are no countries associated with the continent, the method sets the countries list to None.

        Returns:
            None
        """
        # Debugging message to indicate that the method is being called
        
        # Initialize an empty list to store country objects
        countries_objects_list = []
        
        try:
            # Attempt to retrieve country information from the object's information
            country_info = self._object_info['countries']
            
            # Iterate over each country information entry
            for country_info_entry in country_info:
                # Create an FMCCountryObject instance for each country and append it to the list
                countries_objects_list.append(FMCCountryObject(country_info_entry))
        
        except KeyError:
            # If there is no country information, set the countries list to None
            countries_objects_list = None
            
        # Call the superclass method to set the countries list
        return super().set_countries(countries_objects_list)

    def set_member_alpha2_codes(self):
        """
        Set the member alpha-2 codes of the continent object.

        Returns:
            None
        """
        pass

    def set_member_alpha3_codes(self):
        """
        Set the member alpha-3 codes of the continent object.

        Returns:
            None
        """
        pass

    def set_member_numeric_codes(self):
        """
        Set the member numeric codes of the continent object.

        Returns:
            None
        """
        pass

    #TODO: move this
    def get_continent_info(self):
        """
        Get information about the continent.

        Returns:
            dict: Information about the continent.
        """
        return self._object_info

class FMCGeolocationObject(GeolocationObject):
    """
    A class representing a FMC geolocation object
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCGeolocationObject instance.

        Args:
            object_info (dict): Information about the geolocation object.
        """
        general_logger.debug(f"Called FMCGeolocationObject::__init__()")
        super().__init__(object_info)

    def set_name(self):
        """
        Set the name of the geolocation object.
        
        Returns:
            str: The name of the geolocation object.
        """
        name = self._object_info['name']
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the geolocation object.

        Returns:
            None
        """
        value = None
        return super().set_description(value)

    def set_object_container_name(self):
        """
        Set the name of the object container for the geolocation object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)

    def set_continents(self):
        """
        Set the continents associated with the geolocation object.

        This method sets the continents associated with the geolocation object by creating instances of
        FMCContinentObject for each continent retrieved from the object's information.
        If there are no continents associated with the geolocation object, it sets the continents list to None.

        Returns:
            list: A list of FMCContinentObject instances representing continents.
        """
        # Debugging message to indicate that the method is being called
        
        # Initialize an empty list to store continent objects
        continent_objects_list = []
        
        try:
            # Attempt to retrieve continent information from the object's information
            continents_info = self._object_info['continents']
            
            # Iterate over each continent information entry
            for continent_info in continents_info:
                # Create an FMCContinentObject instance for each continent and append it to the list
                continent_objects_list.append(FMCContinentObject(continent_info))
        
        except KeyError:
            # If there is no continent information, set the continents list to None
            continent_objects_list = None
        
        # Call the superclass method to set the continents list
        return super().set_continents(continent_objects_list)

    #TODO: maybe make this method static?
    def set_countries(self):
        """
        Set the countries associated with the geolocation object.

        This method sets the countries associated with the geolocation object by creating instances of
        FMCCountryObject for each country retrieved from the object's information.
        It also adds countries of the continents associated with the geolocation object.

        Returns:
            list: A list of FMCCountryObject instances representing countries.
        """
        # Debugging message to indicate that the method is being called
        
        # Initialize an empty list to store country objects
        countries_objects_list = []
        
        # Attempt to retrieve country information from the object's information
        country_info = self._object_info.get('countries', [])
        
        # Iterate over each country information entry
        for country_entry in country_info:
            # Create an FMCCountryObject instance for each country and append it to the list
            countries_objects_list.append(FMCCountryObject(country_entry))
        
        # Add countries of the continents associated with the geolocation object
        for continent in self._continents:
            for country_info in continent.get_continent_info().get('countries', []):
                countries_objects_list.append(FMCCountryObject(country_info))
        
        # Call the superclass method to set the countries list
        return super().set_countries(countries_objects_list)

    # Don't delete this. They need to be here, otherwise GeolocationObject::process_policy_info() will throw an error since the method
    # called in there doesn't have parameters, however, the method definition of the class includes parameters.
    @abstractmethod
    def set_member_alpha2_codes(self):
        """
        Abstract method to set the member alpha-2 codes.
        """
        pass

    @abstractmethod
    def set_member_alpha3_codes(self):
        """
        Abstract method to set the member alpha-3 codes.
        """
        pass

    @abstractmethod
    def set_member_numeric_codes(self):
        """
        Abstract method to set the member numeric codes.
        """
        pass

#TODO: the problem is ICMP objects and port objects are treated the same by FMC, there is no distinction between them.
# we need to determine the type of the object and then call the right 
class FMCPortObject(FMCObject, PortObject):
    """
    Class representing a port object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and PortObject classes.
    """
    # before initializing the object, check if it is an ICMP object
    # if it is, send it to the FMCICMPObject constructctor
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize an FMCPortObject instance.

        Parameters:
        - object_info (dict): Information about the port object.
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        self._source_port = "1-65535"
        self._destination_port = object_info.get('port', "1-65535")
        self._port_protocol = object_info['protocol']
        PortObject.__init__(ObjectContainer, object_info, self._source_port, self._destination_port, self._port_protocol)
    
class FMCICMPObject(FMCObject, ICMPObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        self._icmp_type = self._object_info.get('icmpType', "any")
        self._icmp_code = self._object_info.get('code')
        ICMPObject.__init__(self, ObjectContainer, object_info)

class FMCPortGroupObject(PortGroupObject, FMCObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initializes a new FMCNetworkGroupObject.

        Args:
            object_info (dict): Information about the network group object.
        """
        super().__init__(ObjectContainer, object_info)

    def save(self, Database):
        # set the names of the object members
        self.set_object_member_names()
        PortGroupObjectsTable = Database.get_port_group_objects_table()
        PortGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())   

class FMCURLObject(FMCObject, URLObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize an FMC URL Object.

        Parameters:
        - object_info (dict): Information about the URL object.

        Returns:
        None
        """
        super().__init__(ObjectContainer, object_info)
    
    def set_url_value(self):
        """
        Set the URL value for the FMC URL Object.

        Returns:
        None
        """
        url_value = self._object_info['url']
        return super().set_url_value(url_value)

class FMCURLGroupObject(URLGroupObject, FMCObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize an FMC URL Group Object.

        Parameters:
        - object_info (dict): Information about the URL group object.

        Returns:
        None
        """
        super().__init__(ObjectContainer, object_info)
    
    def check_for_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking URL group <{self._name}> for literal members.")
        # get the group object info
        object_info = self.get_info()
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObject.convert_url_literal_to_objects(ObjectContainer, literal_member)

                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.get_name())
                converted_literal.save(Database)
        except:
            general_logger.info(f"No literal members found for URL group <{self._name}>.")

    def save(self, Database):
        # set the names of the object members
        self.set_object_member_names()
        # check for literals
        self.check_for_literals(self.get_object_container(), Database)
        URLGroupObjectsTable = Database.get_url_group_objects_table()
        URLGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())   