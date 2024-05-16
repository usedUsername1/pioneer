import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GroupObject, GeolocationObject, PortObject, ICMPObject, URLObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

#TODO: are class specific group classes needed?, eg FMCPortGroupObject

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
        super().__init__(ObjectContainer, object_info)
    
    def set_name(self):
        """
        Set the name of the FMC object.
        
        Returns:
            str: The name of the FMC object.
        """
        name = self._object_info['name']
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the FMC object.

        Returns:
            str: The description of the FMC object.
        """
        try:
            description = self._object_info['description']
        except KeyError:
            description = None
        return super().set_description(description)

    def set_object_container_name(self):
        """
        Set the name of the object container for the FMC object.

        Returns:
            str: The name of the object container.
        """
        container_name = 'virtual_object_container'
        return super().set_object_container_name(container_name)
    
    def set_override_bool(self):
        """
        Set the override status of the FMC object.

        Returns:
            bool: The override status of the FMC object.
        """
        is_overridable = self._object_info['overridable']
        return super().set_override_bool(is_overridable)

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
    def convert_network_literals_to_objects(network_literals):
        """
        Convert network literals to objects.

        Args:
            network_literals (list): List of network literals.

        Returns:
            list: List of network object names.
        """
        network_objects_list = []

        # Loop through the network literals.
        for network_literal in network_literals:
            general_logger.debug(f"Converting literal {network_literal} to object.")
            # Extract the value of the network literal
            literal_value = network_literal['value']

            # Extract the type of the network literal. Can be either "Host" or "Network"
            # The name of the converted object will depend on the network literal type
            literal_type = network_literal['type']

            # The literal type can be either a host or a network
            if literal_type == 'Network':
                general_logger.debug(f"{network_literal} is of type Network.")
                # Define the CIDR notation IP address
                ip_cidr = literal_value

                # Create an IPv4 network object
                network = ipaddress.ip_network(ip_cidr, strict=False)

                # Extract the network address and netmask
                network_address = network.network_address
                netmask = str(network.prefixlen)  # Extract the prefix length instead of the full netmask

            elif literal_type == 'Host':
                general_logger.debug(f"{network_literal} is of type Host.")
                netmask = '32'
                network_address = literal_value  # Assuming literal_value is the host address

            else:
                general_logger.debug(f"Cannot determine type of {network_literal}. Presented type is {literal_type}.")
                continue

            # Create the name of the object (NL_networkaddress_netmask)
            network_object_name = gvars.network_literal_prefix + str(network_address) + "_" + str(netmask)
            general_logger.debug(f"Converted network literal {network_literal} to object {network_object_name}.")
            network_objects_list.append(network_object_name)
        
        general_logger.debug(f"Finished converting all literals to objects. This is the list with converted literals {network_objects_list}.")
        return network_objects_list

    @staticmethod
    def convert_url_literals_to_objects(url_literals):
        url_objects_list = []

        for url_literal in url_literals:
            url_object_name = gvars.url_literal_prefix + url_literal['url']
            url_objects_list.append(url_object_name)
        
        return url_objects_list

class FMCLiteral(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)

    def set_name(self):
        """
        Set the name of the literal network object.

        Returns:
            str: The name of the object.
        """
        name = self._object_info
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the literal network object.

        Returns:
            str: The description of the object.
        """
        description = gvars.literal_objects_description
        return super().set_description(description)

    def set_object_container_name(self):
        """
        Set the name of the object container for the FMC object.

        Returns:
            str: The name of the object container.
        """
        container_name = 'virtual_object_container'
        return super().set_object_container_name(container_name)

    def set_override_bool(self):
        """
        Set the override boolean for the literal network object.

        Returns:
            bool: The override boolean value.
        """
        is_overridable = False
        return super().set_override_bool(is_overridable)

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
        super().__init__(ObjectContainer, object_info)
    
    def set_network_address_value(self):
        """
        Set the value of the network address for the network object.

        Returns:
            str: The value of the network address.
        """
        value = self._object_info['value']
        return super().set_network_address_value(value)

    def set_network_address_type(self):
        """
        Set the type of the network address for the network object.

        Returns:
            str: The type of the network address.
        """
        type = self._object_info['type']
        return super().set_network_address_type(type)

class FMCNetworkLiteralObject(FMCLiteral, NetworkObject):
    """
    Class representing a literal network object in the Firepower Management Center (FMC).
    Inherits from the NetworkObject class.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an FMCNetworkLiteralObject instance.

        Parameters:
        - object_info (dict): Information about the network object.
        """
        super().__init__(object_info)

    def set_network_address_value(self):
        """
        Set the value of the network address for the literal network object.

        Returns:
            str: The network address value.
        """
        split_name = self._name.split('_')
        subnet_id = split_name[1]
        netmask = split_name[2]
        value = subnet_id + '/' + netmask
        return super().set_network_address_value(value)

    def set_network_address_type(self):
        """
        Set the type of the network address for the literal network object.

        Returns:
            str: The type of the network address.
        """
        split_name = self._name.split('_')
        netmask = split_name[2]
        type = ''

        if netmask == '32':
            type = 'Host'
        else:
            type = 'Network'

        return super().set_network_address_type(type)

class FMCNetworkGroupObject(GroupObject, FMCObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initializes a new FMCNetworkGroupObject.

        Args:
            object_info (dict): Information about the network group object.
        """
        self._group_type = 'network'
        super().__init__(ObjectContainer, object_info, self._group_type)

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

class FMCPortObject(FMCObject, PortObject):
    """
    Class representing a port object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and PortObject classes.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an FMCPortObject instance.

        Parameters:
        - object_info (dict): Information about the port object.
        """
        super().__init__(object_info)
    
    def set_port_number(self):
        """
        Set the port number for the port object.

        Returns:
            str: The port number.
        """
        try:

            port_number = self._object_info['port']
        except KeyError:
            general_logger.info(f"<{self._name}> port object does not have a port number defined.")
            port_number = "1-65535"
        return super().set_port_number(port_number)

    def set_port_protocol(self):
        """
        Set the protocol for the port object.

        Returns:
            str: The port protocol.
        """
        protocol = self._object_info['protocol']
        return super().set_port_protocol(protocol)

class FMCPortLiteralObject(FMCLiteral, PortObject):
    """
    Class representing a literal port object in the Firepower Management Center (FMC).
    Inherits from the PortObject class.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an FMCPortLiteralObject instance.

        Parameters:
        - object_info (dict): Information about the port object.
        """
        super().__init__(object_info)
    
    def set_port_number(self):
        """
        Set the port number for the literal port object.

        Returns:
            str: The port number.
        """
        split_name = self._name.split('_')
        port_number = split_name[2]
        return super().set_port_number(port_number)
    
    def set_port_protocol(self):
        """
        Set the protocol for the literal port object.

        Returns:
            str: The port protocol.
        """
        split_name = self._name.split('_')
        protocol = split_name[1]
        return super().set_port_protocol(protocol)
    
class FMCICMPObject(FMCObject, ICMPObject):
    """
    Class representing an ICMP object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and ICMPObject classes.
    """

    def set_icmp_type(self):
        """
        Set the ICMP type for the ICMP object.

        Returns:
            str: The ICMP type.
        """
        try:

            icmp_type = self._object_info['icmpType']
        except KeyError:
            icmp_type = 'any'

        return super().set_icmp_type(icmp_type)
    
    def set_icmp_code(self):
        """
        Set the ICMP code for the ICMP object.

        Returns:
            str: The ICMP code.
        """
        try:

            icmp_code = self._object_info['code']
        except KeyError:
            icmp_code = None
        return super().set_icmp_code(icmp_code)
    
class FMCLiteralICMPObject(ICMPObject):
    """
    Class representing a literal ICMP object in the Firepower Management Center (FMC).
    Inherits from the ICMPObject class.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize an FMCLiteralICMPObject instance.

        Parameters:
        - object_info (dict): Information about the ICMP object.
        """
        super().__init__(object_info)
    
    def set_name(self):
        """
        Set the name of the literal ICMP object.

        Returns:
            str: The name of the object.
        """
        name = self._object_info
        return super().set_name(name)
    
    def set_description(self):
        """
        Set the description of the literal ICMP object.

        Returns:
            str: The description of the object.
        """
        description = gvars.literal_objects_description
        return super().set_description(description)

    def set_icmp_type(self):
        """
        Set the ICMP type for the literal ICMP object.

        Returns:
            str: The ICMP type.
        """
        split_name = self._name.split('_')
        icmp_type = split_name[2]
        return super().set_icmp_type(icmp_type)
    
    def set_icmp_code(self):
        """
        Set the ICMP code for the literal ICMP object.

        Returns:
            str: The ICMP code.
        """
        split_name = self._name.split('_')
        try:
            icmp_code = split_name[3]
        except IndexError:
            icmp_code = None
        return super().set_icmp_code(icmp_code)

    def set_object_container_name(self):
        """
        Set the name of the object container for the FMC object.

        Returns:
            str: The name of the object container.
        """
        container_name = 'virtual_object_container'
        return super().set_object_container_name(container_name)

    def set_override_bool(self):
        """
        Set the override boolean for the literal ICMP object.

        Returns:
            bool: The override boolean value.
        """
        is_overridable = False
        return super().set_override_bool(is_overridable)

class FMCPortGroupObject(GroupObject, FMCObject):
    def __init__(self, object_info) -> None:
        """
        Initialize an FMC Port Group Object.

        Parameters:
        - object_info (dict): Information about the port group object.

        Returns:
        None
        """
        super().__init__(object_info)


#TODO: implement the classes and process URL objects
class FMCURLObject(FMCObject, URLObject):
    def __init__(self, object_info) -> None:
        """
        Initialize an FMC URL Object.

        Parameters:
        - object_info (dict): Information about the URL object.

        Returns:
        None
        """
        super().__init__(object_info)
    
    def set_url_value(self):
        """
        Set the URL value for the FMC URL Object.

        Returns:
        None
        """
        url_value = self._object_info['url']
        return super().set_url_value(url_value)

class FMCURLLiteral(FMCLiteral, URLObject):
    def __init__(self, object_info) -> None:
        """
        Initialize an FMC URL Literal Object.

        Parameters:
        - object_info (dict): Information about the URL literal object.

        Returns:
        None
        """
        super().__init__(object_info)
    
    def set_url_value(self):
        """
        Set the URL value for the FMC URL Literal Object.

        Returns:
        None
        """
        split_info = self._object_info.split('_')
        url_value = split_info[1]
        return super().set_url_value(url_value)

class FMCURLGroupObject(GroupObject, FMCObject):
    def __init__(self, object_info) -> None:
        """
        Initialize an FMC URL Group Object.

        Parameters:
        - object_info (dict): Information about the URL group object.

        Returns:
        None
        """
        super().__init__(object_info)