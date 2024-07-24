import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class Object:
    """
    Base class for representing objects in the system.
    """

    def __init__(self, object_container, name, description, is_overridable) -> None:
        """
        Initialize an Object instance.

        Args:
            object_container (ObjectContainer): The container that holds this object.
            name (str): The name of the object.
            description (str): A description of the object.
            is_overridable (bool): Indicates if the object can be overridden.
        """
        # Generate a unique identifier for the object
        self._uid = helper.generate_uid()
        self._object_container = object_container
        self._name = name
        self._description = description
        self._is_overridable = is_overridable
        self._group_member_names = []  # Initialize an empty list for group members

    @property
    def uid(self) -> str:
        """
        Get the UID of the object.

        Returns:
            str: The UID of the object.
        """
        return self._uid

    @uid.setter
    def uid(self, value) -> None:
        """
        Set the UID of the object.

        Args:
            value (str): The UID to set.
        """
        self._uid = value

    @property
    def object_container(self):
        """
        Get the container that holds this object.

        Returns:
            ObjectContainer: The container that holds this object.
        """
        return self._object_container

    @property
    def name(self) -> str:
        """
        Get the name of the object.

        Returns:
            str: The name of the object.
        """
        return self._name

    @name.setter
    def name(self, value) -> None:
        """
        Set the name of the object.

        Args:
            value (str): The name of the object.
        """
        self._name = value

    @property
    def description(self) -> str:
        """
        Get the description of the object.

        Returns:
            str: The description of the object.
        """
        return self._description

    @description.setter
    def description(self, value) -> None:
        """
        Set the description of the object.

        Args:
            value (str): The description of the object.
        """
        self._description = value

    @property
    def is_overridable(self) -> bool:
        """
        Get the override status of the object.

        Returns:
            bool: Indicates if the object can be overridden.
        """
        return self._is_overridable

    @is_overridable.setter
    def is_overridable(self, value: bool) -> None:
        """
        Set the override status of the object.

        Args:
            value (bool): The override status of the object.
        """
        self._is_overridable = value

    @property
    def object_container_name(self) -> str:
        """
        Get the name of the object container.

        Returns:
            str: The name of the object container.
        """
        return self._object_container.name

    @object_container_name.setter
    def object_container_name(self, value) -> None:
        """
        Set the name of the object container.

        Args:
            value (str): The name of the object container.
        """
        self._object_container.name = value

    def add_group_member_name(self, group_member_name) -> None:
        """
        Add a group member name to the list.

        Args:
            group_member_name (str): The name of the group member to add.
        """
        self._group_member_names.append(group_member_name)
          
# regarding processing groups: the object members of the groups have to be processed as well
class GroupObject(Object):
    """
    Represents a group object in the system.
    """

    def __init__(self) -> None:
        """
        Initialize the GroupObject instance with default values.

        Args:
            None
        """
        super().__init__(object_container=None, name='', description='', is_overridable=False)
        self._group_member_names = []
        self._object_members = set()
        self._group_object_members = set()
        self._icmp_object_members = set()

    @property
    def group_member_names(self) -> list:
        """
        Get the list of group member names.

        Returns:
            list: The list of group member names.
        """
        return self._group_member_names

    @group_member_names.setter
    def group_member_names(self, value: list) -> None:
        """
        Set the list of group member names.

        Args:
            value (list): The list of group member names to set.
        """
        self._group_member_names = value

    @property
    def object_members(self) -> set:
        """
        Get the set of object members.

        Returns:
            set: The set of object members.
        """
        return self._object_members

    @object_members.setter
    def object_members(self, value: set) -> None:
        """
        Set the set of object members.

        Args:
            value (set): The set of object members to set.
        """
        self._object_members = value

    @property
    def group_object_members(self) -> set:
        """
        Get the set of group object members.

        Returns:
            set: The set of group object members.
        """
        return self._group_object_members

    @group_object_members.setter
    def group_object_members(self, value: set) -> None:
        """
        Set the set of group object members.

        Args:
            value (set): The set of group object members to set.
        """
        self._group_object_members = value

    @property
    def icmp_object_members(self) -> set:
        """
        Get the set of ICMP object members.

        Returns:
            set: The set of ICMP object members.
        """
        return self._icmp_object_members

    @icmp_object_members.setter
    def icmp_object_members(self, value: set) -> None:
        """
        Set the set of ICMP object members.

        Args:
            value (set): The set of ICMP object members to set.
        """
        self._icmp_object_members = value

class NetworkObject:
    """
    Represents a generic network object.
    """

    def __init__(self, network_address_value, network_address_type) -> None:
        """
        Initialize the NetworkObject instance.

        Args:
            network_address_value (str): The network address value.
            network_address_type (str): The network address type.
        """
        self._network_address_value = network_address_value
        self._network_address_type = network_address_type

    @property
    def network_address_value(self) -> str:
        """
        Get the network address value of the object.

        Returns:
            str: The network address value.
        """
        return self._network_address_value

    @network_address_value.setter
    def network_address_value(self, value) -> None:
        """
        Set the network address value of the object.

        Args:
            value (str): The network address value.
        """
        self._network_address_value = value

    @property
    def network_address_type(self) -> str:
        """
        Get the network address type of the object.

        Returns:
            str: The network address type.
        """
        return self._network_address_type

    @network_address_type.setter
    def network_address_type(self, value) -> None:
        """
        Set the network address type of the object.

        Args:
            value (str): The network address type.
        """
        self._network_address_type = value

    def save(self, db) -> None:
        """
        Save the network object to the db.

        Args:
            db: The db object where the network object will be saved.
        """
        db.network_address_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.network_address_value,
            self.description,
            self.network_address_type,
            self.is_overridable
        )  

class NetworkGroupObject(GroupObject):
    """
    Represents a network group object, inheriting from GroupObject.
    """

    def save(self, db) -> None:
        """
        Save the network group object to the db.

        Args:
            db: The db object where the network group object will be saved.
        """
        db.network_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description,
            self.is_overridable
        )

    def create_relationships_in_db(self, db, preloaded_data) -> None:
        """
        Create relationships in the db for the network group object.

        Args:
            db: The db object where relationships will be created.
            preloaded_data (dict): Preloaded data mapping member names to their UIDs.
        """        
        for member_name in self.group_member_names:
            group_member_uid = preloaded_data.get(member_name)
            if group_member_uid:
                db.network_group_objects_members_table.insert(self.uid, group_member_uid)

class PortObject:
    """
    Represents a port object with source and destination ports and a protocol.
    """

    def __init__(self, source_port, destination_port, port_protocol) -> None:
        """
        Initialize the PortObject instance.

        Args:
            source_port (int): The source port number.
            destination_port (int): The destination port number.
            port_protocol (str): The protocol used by the port (e.g., 'TCP', 'UDP').
        """
        self._source_port = source_port
        self._destination_port = destination_port
        self._port_protocol = port_protocol

    @property
    def port_protocol(self) -> str:
        """
        Get the port protocol of the object.

        Returns:
            str: The port protocol.
        """
        return self._port_protocol

    @port_protocol.setter
    def port_protocol(self, protocol) -> None:
        """
        Set the port protocol of the object.

        Parameters:
            protocol (str): The port protocol.
        """
        self._port_protocol = protocol

    @property
    def source_port(self) -> int:
        """
        Get the source port of the object.

        Returns:
            int: The source port.
        """
        return self._source_port

    @source_port.setter
    def source_port(self, number: int) -> None:
        """
        Set the source port of the object.

        Parameters:
            number (int): The source port.
        """
        self._source_port = number

    @property
    def destination_port(self) -> int:
        """
        Get the destination port of the object.

        Returns:
            int: The destination port.
        """
        return self._destination_port

    @destination_port.setter
    def destination_port(self, number: int) -> None:
        """
        Set the destination port of the object.

        Parameters:
            number (int): The destination port.
        """
        self._destination_port = number

    def save(self, db) -> None:
        """
        Save the port object to the db.

        Args:
            db: The db object where the port object will be saved.
        """
        db.port_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.port_protocol,
            self.source_port,
            self.destination_port,
            self.description,
            self.is_overridable
        )

class ICMPObject:
    """
    Represents an ICMP object in the system.
    """

    def __init__(self, icmp_type, icmp_code) -> None:
        """
        Initialize an ICMPObject instance.

        Parameters:
            icmp_type (str): The type of the ICMP object.
            icmp_code (str): The code of the ICMP object.
        """
        self._icmp_type = icmp_type
        self._icmp_code = icmp_code

    @property
    def icmp_type(self) -> str:
        """
        Get the ICMP type.

        Returns:
            str: The ICMP type.
        """
        return self._icmp_type

    @icmp_type.setter
    def icmp_type(self, value) -> None:
        """
        Set the ICMP type.

        Parameters:
            value (str): The ICMP type.
        """
        self._icmp_type = value

    @property
    def icmp_code(self) -> str:
        """
        Get the ICMP code.

        Returns:
            str: The ICMP code.
        """
        return self._icmp_code

    @icmp_code.setter
    def icmp_code(self, value) -> None:
        """
        Set the ICMP code.

        Parameters:
            value (str): The ICMP code.
        """
        self._icmp_code = value

    def save(self, db) -> None:
        """
        Save the ICMP object to the db.

        Args:
            db: The db object where the ICMP object will be saved.
        """
        db.icmp_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.icmp_type,
            self.icmp_code,
            self.description,
            self.is_overridable
        )

class PortGroupObject(GroupObject):
    """
    Represents a port group object.
    Inherits from GroupObject to handle a collection of port-related objects.
    """

    def save(self, db) -> None:
        """
        Save the port group object to the db.

        Args:
            db: The db object where the port group object will be saved.
        """
        db.port_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description,
            self.is_overridable
        )

    def create_relationships_in_db(self, db, preloaded_data) -> None:
        """
        Create relationships in the db for the port group object.

        Args:
            db: The db object where relationships will be created.
            preloaded_data (dict): A dictionary mapping member names to their UIDs.
        """
        for member_name in self.group_member_names:
            group_member_uid = preloaded_data.get(member_name)
            if group_member_uid is not None:
                db.port_group_objects_members_table.insert(self.uid, group_member_uid)

class URLObject:
    """
    Represents a URL object in the system.
    """

    def __init__(self, url_value) -> None:
        """
        Initialize a URLObject instance.

        Args:
            url_value (str): The URL value for the object.
        """
        self._url_value = url_value

    @property
    def url_value(self) -> str:
        """
        Get the URL value of the object.

        Returns:
            str: The URL value.
        """
        return self._url_value

    @url_value.setter
    def url_value(self, value) -> None:
        """
        Set the URL value of the object.

        Args:
            value (str): The URL value to set.
        """
        self._url_value = value

    def save(self, db) -> None:
        """
        Save the URL object to the db.

        Args:
            db: The db object where the URL object will be saved.
        """
        db.url_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.url_value,
            self.description,
            self.is_overridable
        )

class URLGroupObject(GroupObject):
    """
    Represents a URL group object in the system.
    """

    def save(self, db) -> None:
        """
        Save the URL group object to the db.

        Args:
            db: The db object where the URL group object will be saved.
        """
        url_group_objects_table = db.url_group_objects_table
        url_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description,
            self.is_overridable
        )

    def create_relationships_in_db(self, db, preloaded_data) -> None:
        """
        Create relationships between the URL group object and its members in the db.

        Args:
            db: The db object used for creating relationships.
            preloaded_data (dict): Dictionary containing member names and their corresponding UIDs.
        """
        for member_name in self.group_member_names:
            group_member_uid = preloaded_data.get(member_name)
            if group_member_uid:
                db.url_group_objects_members_table.insert(self.uid, group_member_uid)
    

class ScheduleObject:
    """
    Represents a schedule object in the system.
    """

    def save(self, db) -> None:
        """
        Save the schedule object to the db.

        Args:
            db: The db object where the schedule object will be saved.
        """
        db.schedule_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.description
        )

class GeolocationObject:
    """
    Represents a geolocation object in the system.
    """

    def save(self, db) -> None:
        """
        Save the geolocation object to the db.

        Args:
            db: The db object where the geolocation object will be saved.
        """
        db.geolocation_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid
        )

class CountryObject:
    """
    Represents a country object in the system.
    """

    def save(self, db) -> None:
        """
        Save the country object to the db.

        Args:
            db: The db object where the country object will be saved.
        """
        db.country_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid
        )

class PolicyUserObject:
    """
    Represents a policy user object in the system.
    """

    def __init__(self, name) -> None:
        """
        Initialize a PolicyUserObject instance.

        Args:
            name (str): The name of the policy user object.
        """
        self.name = name

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value) -> None:
        self._name = value

    def save(self, db) -> None:
        """
        Save the policy user object to the db.

        Args:
            db: The db object where the policy user object will be saved.
        """
        db.policy_user_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid
        )

class URLCategoryObject:
    """
    Represents a URL category object in the system.
    """

    def __init__(self, reputation) -> None:
        """
        Initialize a URLCategoryObject instance.

        Args:
            reputation (str): The reputation of the URL category.
        """
        self.reputation = reputation

    @property
    def reputation(self) -> str:
        return self._reputation

    @reputation.setter
    def reputation(self, value) -> None:
        self._reputation = value

    def save(self, db) -> None:
        """
        Save the URL category object to the db.

        Args:
            db: The db object where the URL category object will be saved.
        """
        db.url_category_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.reputation
        )

class L7AppObject:
    """
    Represents a Layer 7 application object in the system.
    """

    def save(self, db) -> None:
        """
        Save the Layer 7 application object to the db.

        Args:
            db: The db object where the Layer 7 application object will be saved.
        """
        db.l7_app_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid
        )

class L7AppFilterObject:
    """
    Represents a Layer 7 application filter object in the system.
    """

    def __init__(self, type) -> None:
        """
        Initialize an L7AppFilterObject instance.

        Args:
            type (str): The type of the Layer 7 application filter.
        """
        self.type = type

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, value) -> None:
        self._type = value

    def save(self, db) -> None:
        """
        Save the Layer 7 application filter object to the db.

        Args:
            db: The db object where the Layer 7 application filter object will be saved.
        """
        db.l7_app_filter_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid,
            self.type
        )

class L7AppGroupObject:
    """
    Represents a Layer 7 application group object in the system.
    """

    def save(self, db) -> None:
        """
        Save the Layer 7 application group object to the db.

        Args:
            db: The db object where the Layer 7 application group object will be saved.
        """
        db.l7_app_group_objects_table.insert(
            self.uid,
            self.name,
            self.object_container.uid
        )