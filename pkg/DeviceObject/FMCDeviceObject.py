import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GeolocationObject, CountryObject, PortObject, ICMPObject, URLObject, \
NetworkGroupObject, PortGroupObject, URLGroupObject, ScheduleObject, PolicyUserObject, URLCategoryObject, \
L7AppObject, L7AppFilterObject, L7AppGroupObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class FMCObjectWithLiterals(Object):
    def set_object_member_names(self):
        general_logger.info(f"Getting the names of object members of group <{self._name}>.")
        try:
            object_members = self.object_info['objects']
            for object_member in object_members:
                self.add_group_member_name(object_member['name'])
        except:
            general_logger.info(f"There are no object members for group <{self._name}>.")

    def check_for_network_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking network group <{self._name}> for literal members.")
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = self.object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObjectWithLiterals.convert_network_literal_to_object(ObjectContainer, literal_member)
                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.name)
                converted_literal.save(Database)
        except:
            general_logger.info(f"No literal members found for network group <{self._name}>.")

    def check_for_url_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking URL group <{self._name}> for literal members.")
        # get the group object info
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = self.object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObjectWithLiterals.convert_url_literal_to_object(ObjectContainer, literal_member)

                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.name)
                converted_literal.save(Database)
        except:
            general_logger.info(f"No literal members found for URL group <{self._name}>.")

    @staticmethod
    def convert_port_literals_to_objects(ObjectContainer, port_literal, polinfo):
        """
        Convert port literals to port object names.

        Args:
            port_literal (dict): A port literal.

        Returns:
            list: List of port object names.
        """
        general_logger.debug(f"Converting literal <{port_literal}> to object.")

        # Extract protocol and initialize port number
        literal_protocol = port_literal['protocol']
        try:
            literal_port_nr = port_literal['port']
        except KeyError:
            literal_port_nr = "1-65535"

        try:
            # Convert protocol number to its corresponding keyword
            literal_protocol_keyword = helper.protocol_number_to_keyword(literal_protocol)
        
        except PioneerExceptions.UnknownProtocolNumber:
            # Log error if protocol number cannot be converted
            general_logger.warn(f"Protocol number: <{literal_protocol}> cannot be converted to a known IANA keyword.")
            literal_protocol_keyword = "ALL_PROTOCOLS"

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
            except KeyError:
                # If no ICMP code, create the port object name without it
                general_logger.debug(f"No ICMP code for the following port literal: {port_literal['type']}.")
                port_object_name = f"{gvars.port_literal_prefix}{literal_protocol_keyword}_{literal_port_nr}"
                icmp_code = None

            icmp_object_info = {'name': port_object_name,
                                'icmpType': literal_port_nr,
                                'code': icmp_code,
                                'description':gvars.literal_objects_description,
                                'overridable':False}

            return FMCICMPObject(ObjectContainer, icmp_object_info)
        
        else:
            # Create the name of the port object
            port_object_name = f"{gvars.port_literal_prefix}{literal_protocol_keyword}_{literal_port_nr}"

            # Create the port object information dictionary
            port_object_info = {
                'name': port_object_name,
                'protocol': literal_protocol_keyword,
                'source_port_number': '1-65535',
                'port': literal_port_nr,
                'description': gvars.literal_objects_description,
                'overridable': False
            }

            # Create and return the FMCObject with the provided information
            return FMCPortObject(ObjectContainer, port_object_info)

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
    def convert_url_literal_to_object(ObjectContainer, url_literal):
        literal_value = url_literal['url']
        url_object_name = gvars.url_literal_prefix + literal_value
        object_info = {'name':url_object_name, 'url':literal_value, 'description':gvars.literal_objects_description, 'overridable':False}
        return FMCURLObject(ObjectContainer, object_info)

    @staticmethod
    def convert_policy_region_to_object(ObjectContainer, region_info):
        try:
            region_name = region_info['name']
            object_info = {'name':region_name}
        except:
            pass
        return FMCGeolocationObject(ObjectContainer, object_info)

    @staticmethod
    def convert_policy_country_to_object(ObjectContainer, region_info):
        try:
            region_name = region_info['name']
            object_info = {'name':region_name}
        except:
            pass
        return FMCCountryObject(ObjectContainer, object_info)

class FMCObject(Object):
    """
    Represents an FMC (Firepower Management Center) object in the system.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize the FMCObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info: A dictionary containing information about the FMC object.
        """
        self._object_info = object_info
        super().__init__(
            object_container,
            object_info.get('name'),
            object_info.get('description'),
            object_info.get('overridable', False)
        )

    @property
    def object_info(self):
        """
        Get the information dictionary for the FMC object.

        Returns:
            dict: The object information dictionary.
        """
        return self._object_info

    @object_info.setter
    def object_info(self, value):
        """
        Set the information dictionary for the FMC object.

        Args:
            value (dict): The new object information dictionary.
        """
        self._object_info = value

class FMCNetworkObject(FMCObject, NetworkObject):
    """
    A class representing a network object in the Firepower Management Center (FMC).
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize the FMCNetworkObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info (dict): Information about the network object, including its value and type.
        """
        # Initialize FMCObject with base class attributes
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize NetworkObject with specific attributes
        NetworkObject.__init__(self, object_info['value'], object_info['type'])

class FMCNetworkGroupObject(NetworkGroupObject, FMCObjectWithLiterals, FMCObject):
    """
    Represents a network group object in the Firepower Management Center (FMC) with support for literals.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize the FMCNetworkGroupObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info (dict): Information about the network group object.
        """
        FMCObject.__init__(self, object_container, object_info)
        NetworkGroupObject.__init__(self)

    def save(self, db):
        """
        Save the FMCNetworkGroupObject to the db.

        Args:
            db: The db instance to use for saving.
        """
        # Set the names of the object members
        self.set_object_member_names()
        
        # Check for literals and handle them
        self.check_for_network_literals(self.object_container, db)
        
        # Save the network group object to the db
        db.network_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description,
            self.is_overridable
        )

class FMCPortObject(FMCObject, PortObject):
    """
    Class representing a port object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and PortObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCPortObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info (dict): Information about the port object, including port details and protocol.
        """
        # Initialize FMCObject with the provided container and information
        FMCObject.__init__(self, object_container, object_info)

        # Initialize PortObject with extracted port details and protocol
        # All FMC Port objects will have the source_port parameter set to all ports.
        PortObject.__init__(self, "1-65535", object_info.get('port', "1-65535"), object_info.get('protocol'))
    
class FMCICMPObject(FMCObject, ICMPObject):
    """
    Class representing an ICMP object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and ICMPObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCICMPObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info (dict): Information about the ICMP object, including type and code.
        """
        # Initialize FMCObject with the provided container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize ICMPObject with the ICMP type and code from object_info
        ICMPObject.__init__(self, object_info.get('icmpType', 'any'), object_info.get('code'))

class FMCPortGroupObject(PortGroupObject, FMCObject, FMCObjectWithLiterals):
    """
    A class representing a port group object in the Firepower Management Center (FMC).
    Inherits from PortGroupObject, FMCObject, and FMCObjectWithLiterals.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCPortGroupObject instance.

        Args:
            object_container: The container that holds this FMC object.
            object_info (dict): Information about the port group object, including its name, description, and overridability.
        """
        # Initialize FMCObject with the provided container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize PortGroupObject
        PortGroupObject.__init__(self)

    def save(self, db):
        """
        Save the port group object to the db.

        Args:
            db: The db instance used to persist the object.
        """
        # Set the names of the object members
        self.set_object_member_names()
        
        # Insert the port group object into the table
        db.port_group_objects_table.insert(
            self.uid,                 
            self.name,                
            self.object_container.uid, 
            self.description,         
            self.override_bool        
        )

class FMCURLObject(FMCObject, URLObject):
    """
    A class representing a URL object in the Firepower Management Center (FMC).
    Inherits from FMCObject and URLObject classes.
    """

    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize an FMCURLObject instance.

        Args:
            ObjectContainer: The container that holds this FMC object.
            object_info (dict): Information about the URL object, including its URL value.
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        URLObject.__init__(self, object_info.get('url'))

class FMCURLGroupObject(URLGroupObject, FMCObject, FMCObjectWithLiterals):
    """
    A class representing a URL group object in the Firepower Management Center (FMC).
    Inherits from URLGroupObject, FMCObject, and FMCObjectWithLiterals classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCURLGroupObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the URL group object, including its name and description.
        """
        FMCObject.__init__(self, object_container, object_info)
        URLGroupObject.__init__(self)

    def save(self, db) -> None:
        """
        Save the FMC URL Group Object to the db.

        Args:
            db (Database): The db instance used for saving the object.
        """
        # Set the names of the object members.
        self.set_object_member_names()
        
        # Check for literals related to URL and track them.
        self.check_for_url_literals(self.object_container, db)
        
        # Insert the FMC URL group object into the URL group objects table.
        db.url_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description,
            self.is_overridable
        )

class FMCScheduleObject(FMCObject, ScheduleObject):
    """
    A class representing a schedule object in the Firepower Management Center (FMC).
    Inherits from FMCObject and ScheduleObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCScheduleObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the schedule object, including its name and description.
        """
        FMCObject.__init__(self, object_container, object_info)
        ScheduleObject.__init__(self)

class FMCGeolocationObject(FMCObject, GeolocationObject):
    """
    A class representing a geolocation object in the Firepower Management Center (FMC).
    Inherits from FMCObject and GeolocationObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCGeolocationObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the geolocation object, including its name.
        """
        # Initialize the FMCObject base class
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the GeolocationObject base class
        GeolocationObject.__init__(self)

class FMCCountryObject(FMCObject, CountryObject):
    """
    A class representing a country object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and CountryObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCCountryObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the country object, including its name.
        """
        # Initialize the FMCObject base class
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the CountryObject base class
        CountryObject.__init__(self)

class FMCPolicyUserObject(FMCObject, PolicyUserObject):
    """
    A class representing a policy user object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and PolicyUserObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCPolicyUserObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the policy user object, including the name.
        """
        # Initialize the FMCObject base class with the object container and info
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the PolicyUserObject base class with the name from object_info
        PolicyUserObject.__init__(self, object_info.get('name'))

class FMCURLCategoryObject(FMCObject, URLCategoryObject):
    """
    A class representing a URL category object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and URLCategoryObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCURLCategoryObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the URL category object, including the reputation.
        """
        # Initialize the FMCObject base class with the object container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the URLCategoryObject base class with the reputation from object_info
        URLCategoryObject.__init__(self, object_info.get('reputation'))

class FMCL7AppObject(FMCObject, L7AppObject):
    """
    A class representing an L7 application object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and L7AppObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCL7AppObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the L7 application object.
        """
        # Initialize the FMCObject base class with the object container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the L7AppObject base class without additional parameters
        L7AppObject.__init__(self)

class FMCL7AppFilterObject(FMCObject, L7AppFilterObject):
    """
    A class representing an L7 application filter object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and L7AppFilterObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCL7AppFilterObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the L7 application filter object.
        """
        # Initialize the FMCObject base class with the object container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Extract the type from object_info and initialize the L7AppFilterObject base class
        filter_type = object_info.get('type')
        L7AppFilterObject.__init__(self, filter_type)

class FMCL7AppGroupObject(FMCObject, L7AppGroupObject):
    """
    A class representing an L7 application group object in the Firepower Management Center (FMC).
    Inherits from both FMCObject and L7AppGroupObject classes.
    """

    def __init__(self, object_container, object_info) -> None:
        """
        Initialize an FMCL7AppGroupObject instance.

        Args:
            object_container (ObjectContainer): The container that holds this FMC object.
            object_info (dict): Information about the L7 application group object.
        """
        # Initialize the FMCObject base class with the object container and information
        FMCObject.__init__(self, object_container, object_info)
        
        # Initialize the L7AppGroupObject base class
        L7AppGroupObject.__init__(self)