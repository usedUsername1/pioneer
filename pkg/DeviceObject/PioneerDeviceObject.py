import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GeolocationObject, CountryObject, PortObject, ICMPObject, URLObject, \
NetworkGroupObject, PortGroupObject, URLGroupObject, ScheduleObject, PolicyUserObject, URLCategoryObject, \
L7AppObject, L7AppFilterObject, L7AppGroupObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')
from collections import defaultdict, deque

class ObjectCache:
    """
    A class that implements a simple cache for storing objects.
    
    Attributes:
        _cache (dict): A dictionary to store cached objects, keyed by their unique identifier.
    """

    def __init__(self) -> None:
        """
        Initialize the ObjectCache instance.
        
        Initializes an empty dictionary to serve as the cache.
        """
        self._cache = {}

    def get_or_create(self, key, create_func):
        """
        Retrieve an object from the cache or create it if it does not exist.

        Args:
            key (Hashable): The key used to identify the object in the cache.
            create_func (Callable): A function that creates and returns a new object if the key is not in the cache.

        Returns:
            object: The cached object associated with the key. If the key was not in the cache, a new object is created 
            and added to the cache before being returned.
        
        Example:
            cache = ObjectCache()
            obj = cache.get_or_create('some_key', lambda: SomeClass())
        """
        # Check if the key is not already in the cache
        if key not in self._cache:
            # Create a new object using the provided function and store it in the cache
            self._cache[key] = create_func()
        
        # Return the cached object (either newly created or retrieved from the cache)
        return self._cache[key]

class PioneerObject(Object):
    """
    Class representing a Pioneer object, inheriting from Object.
    """

    def __init__(self, object_container, name, description, is_overridable) -> None:
        """
        Initialize a PioneerObject instance.

        Args:
            object_container (object_container): The container for this object.
            name (str): The name of the object.
            description (str): The description of the object.
            is_overridable (bool): Whether the object is overridable.
        """
        super().__init__(object_container, name, description, is_overridable)

class PioneerNetworkObject(PioneerObject, NetworkObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        """
        Initialize a PioneerNetworkObject instance.

        Args:
            ObjectContainer (ObjectContainer): The container for this object.
            object_info (tuple): A tuple containing information about the network object:
                - object_uid (str): Unique identifier of the object.
                - object_name (str): Name of the object.
                - (unused) (placeholder)
                - object_value (str): The value associated with the network object.
                - object_description (str): Description of the object.
                - object_type (str): Type of the network object.
                - overridable_object (bool): Whether the object is overridable.
        """
        # Extract values from the object_info tuple
        object_uid = object_info[0]
        object_name = object_info[1]
        object_value = object_info[3]
        object_description = object_info[4]
        object_type = object_info[5]
        overridable_object = object_info[6]

        # Initialize the base class PioneerObject with extracted values
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)

        # Initialize the NetworkObject with extracted values
        NetworkObject.__init__(self, object_value, object_type)

        # Set the UID for the object
        self.uid = object_uid

class PioneerNetworkGroupObject(NetworkGroupObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerNetworkGroupObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the network group object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - (unused) (placeholder)
                - description (str): Description of the object.
                - overridable (bool): Whether the object is overridable.
        """

        # Initialize the base class PioneerObject
        PioneerObject.__init__(self, object_container, object_info[1], object_info[3], object_info[4])

        # Initialize the NetworkGroupObject
        NetworkGroupObject.__init__(self)

        # Set the UID for the object
        self.uid = object_info[0]

    def extract_members(self, member_type, object_cache, network_group_objects_members_table) -> None:
        """
        Extract members based on the specified type and cache them.

        Args:
            member_type (str): Type of the members to extract ('object' or 'group').
            object_cache (ObjectCache): Cache to store and retrieve object instances.
            network_group_objects_members_table (Table): Table object to query the members.
        """
        if member_type == 'object':
            columns = [
                "network_address_objects.uid",
                "network_address_objects.name",
                "network_address_objects.object_container_uid",
                "network_address_objects.value",
                "network_address_objects.description",
                "network_address_objects.type",
                "network_address_objects.overridable_object"
            ]
            obj_class = PioneerNetworkObject
            join_conditions = [
                {
                    "table": "network_address_objects",
                    "condition": "network_group_objects_members.object_uid = network_address_objects.uid"
                }
            ]
            name_column = 'network_group_objects_members.group_uid'

        elif member_type == 'group':
            columns = [
                "network_group_objects.uid",
                "network_group_objects.name",
                "network_group_objects.object_container_uid",
                "network_group_objects.description",
                "network_group_objects.overridable_object"
            ]
            obj_class = PioneerNetworkGroupObject
            join_conditions = [
                {
                    "table": "network_group_objects",
                    "condition": "network_group_objects_members.object_uid = network_group_objects.uid"
                }
            ]
            name_column = 'network_group_objects_members.group_uid'

        else:
            raise ValueError("Invalid type specified. Must be 'object' or 'group'.")

        # Fetch members information from the database
        members_info = network_group_objects_members_table.get(
            columns=columns,
            name_col=name_column,
            val=self.uid,
            join=join_conditions,
            not_null_condition=False,
            multiple_where=False
        )

        # Create and cache objects based on the fetched data
        for member_info in members_info:
            uid = member_info[0]
            name = member_info[1]
            key = (uid, name)

            member = object_cache.get_or_create(
                key,
                lambda: obj_class(None, member_info)
            )

            # Add the member to the appropriate collection based on type
            if member_type == 'object':
                self.object_members.add(member)
            elif member_type == 'group':
                self._group_object_members.add(member)
                # If needed, extract members of nested groups
                member.extract_members('object', object_cache, network_group_objects_members_table)
                member.extract_members('group', object_cache, network_group_objects_members_table)
        
class PioneerPortObject(PortObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerPortObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the port object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - (unused) (placeholder)
                - protocol (str): Protocol used by the port object.
                - source_port_number (int): Source port number.
                - destination_port_number (int): Destination port number.
                - description (str): Description of the object.
                - overridable (bool): Whether the object is overridable.
        """
        # Initialize the base class PioneerObject
        PioneerObject.__init__(self, object_container, object_info[1], object_info[6], object_info[7])

        # Initialize the PortObject with protocol, source, and destination ports
        PortObject.__init__(self, object_info[4], object_info[5], object_info[3])

        # Set the UID for the object
        self.uid = object_info[0]

class PioneerICMPObject(ICMPObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerICMPObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the ICMP object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - (unused) (placeholder)
                - type (str): ICMP type.
                - code (str): ICMP code.
                - description (str): Description of the object.
                - overridable (bool): Whether the object is overridable.
        """
        # Initialize the base class PioneerObject
        PioneerObject.__init__(self, object_container, object_info[1], object_info[5], object_info[6])

        # Initialize the ICMPObject with type and code
        ICMPObject.__init__(self, object_info[3], object_info[4])

        # Set the UID for the object
        self.uid = object_info[0]

class PioneerPortGroupObject(PortGroupObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerPortGroupObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the port group object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - description (str): Description of the object.
                - overridable (bool): Whether the object is overridable.
        """
        # Initialize base classes
        PioneerObject.__init__(self, object_container, object_info[1], object_info[3], object_info[4])
        PortGroupObject.__init__(self)

        # Set UID property
        self.uid = object_info[0]

    def extract_members(self, member_type, object_cache, port_group_objects_network_group_objects_members_table):
        """
        Extract members based on the type and cache them.

        Args:
            member_type (str): Type of members to extract ('object', 'icmp_object', or 'group').
            object_cache (ObjectCache): Cache for storing objects.
            port_group_objects_network_group_objects_members_table (DatabaseTable): Table for fetching members information.
        
        Raises:
            ValueError: If an unknown type is provided.
        """
        # Determine the columns to fetch and the class for the objects based on type
        if member_type == 'object':
            columns = [
                "port_objects.uid",
                "port_objects.name",
                "port_objects.object_container_uid",
                "port_objects.protocol",
                "port_objects.source_port_number",
                "port_objects.destination_port_number",
                "port_objects.description",
                "port_objects.overridable_object"
            ]
            obj_class = PioneerPortObject
            join_conditions = [
                {
                    "table": "port_objects",
                    "condition": "port_group_objects_members.object_uid = port_objects.uid"
                }
            ]
            name_col = 'port_group_objects_members.group_uid'

        elif member_type == 'icmp':
            columns = [
                "icmp_objects.uid",
                "icmp_objects.name",
                "icmp_objects.object_container_uid",
                "icmp_objects.type",
                "icmp_objects.code",
                "icmp_objects.description",
                "icmp_objects.overridable_object"
            ]
            obj_class = PioneerICMPObject
            join_conditions = [
                {
                    "table": "icmp_objects",
                    "condition": "port_group_objects_members.object_uid = icmp_objects.uid"
                }
            ]
            name_col = 'port_group_objects_members.group_uid'

        elif member_type == 'group':
            columns = [
                "port_group_objects.uid",
                "port_group_objects.name",
                "port_group_objects.object_container_uid",
                "port_group_objects.description",
                "port_group_objects.overridable_object"
            ]
            obj_class = PioneerPortGroupObject
            join_conditions = [
                {
                    "table": "port_group_objects",
                    "condition": "port_group_objects_members.object_uid = port_group_objects.uid"
                }
            ]
            name_col = 'port_group_objects_members.group_uid'

        else:
            raise ValueError(f"Unknown member type: {member_type}")

        # Fetch members information from the database table
        members_info = port_group_objects_network_group_objects_members_table.get(
            columns=columns,
            name_col=name_col,
            val=self.uid,
            join=join_conditions,
            not_null_condition=False,
            multiple_where=False
        )

        # Create and cache objects based on the fetched data
        for member_info in members_info:
            uid = member_info[0]
            name = member_info[1]
            key = (uid, name)

            member = object_cache.get_or_create(
                key,
                lambda: obj_class(None, member_info)
            )
            if member_type == 'object':
                self.object_members.add(member)
            elif member_type == 'icmp':
                self._icmp_object_members.add(member)
            elif member_type == 'group':
                self._group_object_members.add(member)
                # Extract members from nested groups
                member.extract_members('object', object_cache, port_group_objects_network_group_objects_members_table)
                member.extract_members('icmp', object_cache, port_group_objects_network_group_objects_members_table)
                member.extract_members('group', object_cache, port_group_objects_network_group_objects_members_table)

    def check_icmp_members_recursively(self, has_icmp) -> bool:
        """
        Recursively check if any ICMP object members exist.

        Args:
            has_icmp (bool): Flag to track the presence of ICMP objects.
        
        Returns:
            bool: Updated flag indicating the presence of ICMP objects.
        """
        if self._icmp_object_members:
            return True

        if self._group_object_members:
            for group_object_member in self._group_object_members:
                has_icmp = group_object_member.check_icmp_members_recursively(has_icmp)
                if has_icmp:  # Short-circuit if True is found
                    return True

        return has_icmp

class PioneerURLObject(URLObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerURLObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the URL object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - url (str): URL value of the object.
                - overridable (bool): Whether the object is overridable.
                - description (str): Description of the object.
        """
        # Initialize base classes
        PioneerObject.__init__(self, object_container, object_info[1],  object_info[5], object_info[4])
        URLObject.__init__(self, object_info[3])

        # Set UID property
        self.uid = object_info[0]

class PioneerURLGroupObject(URLGroupObject, PioneerObject):
    def __init__(self, object_container, object_info) -> None:
        """
        Initialize a PioneerURLGroupObject instance.

        Args:
            object_container (ObjectContainer): The container for this object.
            object_info (tuple): Information about the URL group object:
                - uid (str): Unique identifier of the object.
                - name (str): Name of the object.
                - description (str): Description of the object.
                - overridable (bool): Whether the object is overridable.
        """
        # Initialize base classes
        PioneerObject.__init__(self, object_container, object_info[1], object_info[3], object_info[4])
        URLGroupObject.__init__(self)

        # Set UID property
        self.uid = object_info[0]

    def extract_members(self, member_type, object_cache, url_group_objects_members_table):
        """
        Extract and cache members of the URL group object.

        Args:
            member_type (str): The type of members to extract. Can be 'object' or 'group'.
            object_cache (ObjectCache): Cache to store and retrieve objects.
            url_group_objects_members_table (Table): Table to fetch members information from.
        
        Raises:
            ValueError: If the member_type is unknown.
        """
        if member_type == 'object':
            columns = [
                "url_objects.uid",
                "url_objects.name",
                "url_objects.object_container_uid",
                "url_objects.url_value",
                "url_objects.description",
                "url_objects.overridable_object"
            ]
            obj_class = PioneerURLObject
            join_conditions = [
                {
                    "table": "url_objects",
                    "condition": "url_group_objects_members.object_uid = url_objects.uid"
                }
            ]
            name_col = 'url_group_objects_members.group_uid'

        elif member_type == 'group':
            columns = [
                "url_group_objects.uid",
                "url_group_objects.name",
                "url_group_objects.object_container_uid",
                "url_group_objects.description",
                "url_group_objects.overridable_object"
            ]
            obj_class = PioneerURLGroupObject
            join_conditions = [
                {
                    "table": "url_group_objects",
                    "condition": "url_group_objects_members.object_uid = url_group_objects.uid"
                }
            ]
            name_col = 'url_group_objects_members.group_uid'

        else:
            raise ValueError(f"Unknown member type: {member_type}")

        # Fetch members information
        members_info = url_group_objects_members_table.get(
            columns=columns,
            name_col=name_col,
            val=self.uid,
            join=join_conditions,
            not_null_condition=False,
            multiple_where=False
        )

        # Create and cache objects based on the fetched data
        for member_info in members_info:
            uid = member_info[0]
            name = member_info[1]
            key = (uid, name)

            member = object_cache.get_or_create(
                key,
                lambda: obj_class(None, member_info)
            )
            if member_type == 'object':
                self.object_members.add(member)
            elif member_type == 'group':
                self._group_object_members.add(member)
                # If needed, extract members of nested groups
                member.extract_members('object', object_cache, url_group_objects_members_table)
                member.extract_members('group', object_cache, url_group_objects_members_table)

@staticmethod
def recursive_update_objects_and_groups(objects_set, group_objects_set):
    """
    Recursively updates objects_set with all objects from the group_objects_set.
    Also updates group_objects_set with all group members.
    """
    # Create a set to keep track of groups that need further processing
    groups_to_process = set(group_objects_set)
    # Create a set to keep track of processed groups
    processed_groups = set()

    while groups_to_process:
        # Create a copy of the groups to process for the current iteration
        current_groups = groups_to_process - processed_groups
        # Clear the original set to start fresh
        groups_to_process.clear()

        if not current_groups:
            break

        for current_group in current_groups:
            # Update objects_set with members of the current group
            objects_set.update(current_group.object_members)
            # Add new groups from the current group to the groups_to_process
            new_groups = current_group.group_object_members
            groups_to_process.update(new_groups)
            group_objects_set.update(new_groups)
            # Mark the current group as processed
            processed_groups.add(current_group)
