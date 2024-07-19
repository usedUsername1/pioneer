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
            object_members = self._object_info['objects']
            for object_member in object_members:
                self.add_group_member_name(object_member['name'])
        except:
            general_logger.info(f"There are no object members for group <{self._name}>.")

    def check_for_network_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking network group <{self._name}> for literal members.")
        # get the group object info
        object_info = self.get_object_info()
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObjectWithLiterals.convert_network_literal_to_object(ObjectContainer, literal_member)
                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.get_name())
                converted_literal.save(Database)
        except:
            general_logger.info(f"No literal members found for network group <{self._name}>.")

    def check_for_url_literals(self, ObjectContainer, Database):
        general_logger.info(f"Checking URL group <{self._name}> for literal members.")
        # get the group object info
        object_info = self.get_object_info()
        converted_literal = ''
        
        # check for literals key in the object definition
        try:
            literal_members = object_info['literals']
            # now loop through the literal_members
            for literal_member in literal_members:
                converted_literal = FMCObjectWithLiterals.convert_url_literal_to_object(ObjectContainer, literal_member)

                # add the name of the literal object to the list tracking the member names of the object
                self.add_group_member_name(converted_literal.get_name())
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
        
        #TODO: make sure you track all of these as well
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

    #TODO: fix this. does the try/except make sense here?
    @staticmethod
    def convert_policy_region_to_object(ObjectContainer, region_info):
        try:
            region_name = region_info['name']
            object_info = {'name':region_name}
        except:
            print(region_info)
        return FMCGeolocationObject(ObjectContainer, object_info)

    @staticmethod
    def convert_policy_country_to_object(ObjectContainer, region_info):
        try:
            region_name = region_info['name']
            object_info = {'name':region_name}
        except:
            print(region_info)
        return FMCCountryObject(ObjectContainer, object_info)

#TODO: see what to do with the overridable parameter, it looks kind of wrong at the moment
# since multiple FMC objects that intherit from this class don't have this attribute
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
        self._object_info = object_info
        super().__init__(ObjectContainer, object_info.get('name'), object_info.get('description'), object_info.get('overridable'))

    def get_object_info(self):
        return self._object_info

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
        NetworkObject.__init__(self, object_info['value'], object_info['type'] )

class FMCNetworkGroupObject(NetworkGroupObject, FMCObjectWithLiterals, FMCObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initializes a new FMCNetworkGroupObject.

        Args:
            object_info (dict): Information about the network group object.
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        NetworkGroupObject.__init__(self)
    # since we are dealing with a group object, there are a few operations that must be done
    # before the object is saved in the database
    # we need to get the names of the objects that are members of the group objects and track them
    # we need to check for literals. the name of the converted literal object will be tracked as well
    # finally, the object group will be inserted
    def save(self, Database):
        # set the names of the object members
        self.set_object_member_names()
        # check for literals
        self.check_for_network_literals(self.get_object_container(), Database)
        NetworkGroupObjectsTable = Database.get_network_group_objects_table()
        NetworkGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())   

#TODO: the problem is ICMP objects and port objects are treated the same by FMC, there is no distinction between them.
# we need to determine the type of the object and then call the right
#TODO: remove the self._ parameters as they can be passed to the constructor directly. they are redundant
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
        PortObject.__init__(self, "1-65535", object_info.get('port', "1-65535"), object_info['protocol'])
    
class FMCICMPObject(FMCObject, ICMPObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        ICMPObject.__init__(self, object_info.get('icmpType', "any"), object_info.get('code'))

class FMCPortGroupObject(PortGroupObject, FMCObject, FMCObjectWithLiterals):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initializes a new FMCNetworkGroupObject.

        Args:
            object_info (dict): Information about the network group object.
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        PortGroupObject.__init__(self)

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
        FMCObject.__init__(self, ObjectContainer, object_info)
        URLObject.__init__(self, object_info['url'])

class FMCURLGroupObject(URLGroupObject, FMCObject, FMCObjectWithLiterals):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize an FMC URL Group Object.

        Parameters:
        - object_info (dict): Information about the URL group object.

        Returns:
        None
        """
        FMCObject.__init__(self, ObjectContainer, object_info)
        URLGroupObject.__init__(self)

    def save(self, Database):
        # set the names of the object members
        self.set_object_member_names()
        # check for literals
        self.check_for_url_literals(self.get_object_container(), Database)
        URLGroupObjectsTable = Database.get_url_group_objects_table()
        URLGroupObjectsTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid(), self.get_description(), self.get_override_bool())

class FMCScheduleObject(FMCObject, ScheduleObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        ScheduleObject.__init__(self)

class FMCGeolocationObject(FMCObject, GeolocationObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        GeolocationObject.__init__(self)

class FMCCountryObject(FMCObject, CountryObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        CountryObject.__init__(self)

class FMCPolicyUserObject(FMCObject, PolicyUserObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        PolicyUserObject.__init__(self, object_info['name'])

class FMCURLCategoryObject(FMCObject, URLCategoryObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        URLCategoryObject.__init__(self, object_info['reputation'])

class FMCL7AppObject(FMCObject, L7AppObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        L7AppObject.__init__(self)

class FMCL7AppFilterObject(FMCObject, L7AppFilterObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        L7AppFilterObject.__init__(self, object_info['type'])

class FMCL7AppGroupObject(FMCObject, L7AppGroupObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        FMCObject.__init__(self, ObjectContainer, object_info)
        L7AppGroupObject.__init__(self)