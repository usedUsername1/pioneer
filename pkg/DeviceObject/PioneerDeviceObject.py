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
    def __init__(self):
        self._cache = {}

    def get_or_create(self, key, create_func):
        if key not in self._cache:
            self._cache[key] = create_func()
        return self._cache[key]

class PioneerObject(Object):
    def __init__(self, ObjectContainer, name, description, is_overridable) -> None:
        super().__init__(ObjectContainer, name, description, is_overridable)

# should the PioneerGroups also have a members python attribute which will be a list with all the 
# python object representations of the member objects?
    # if so, should members be retrieved upon the instantiation of the group object?

class PioneerNetworkObject(PioneerObject, NetworkObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_value = object_info[3]
        object_description = object_info[4]
        object_type = object_info[5]
        overridable_object = object_info[6]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        NetworkObject.__init__(self, object_value, object_type)
        self.set_uid(object_uid)

class PioneerNetworkGroupObject(NetworkGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        NetworkGroupObject.__init__(self)
        self.set_uid(object_uid)
    
    def extract_members(self, type, object_cache, NetworkGroupObjectsMembersTable):
        if type == 'object':
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
            name_col = 'network_group_objects_members.group_uid'

        elif type == 'group':
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
            name_col = 'network_group_objects_members.group_uid'

        # Fetch members information
        members_info = NetworkGroupObjectsMembersTable.get(
            columns=columns,
            name_col=name_col,
            val=self.get_uid(),
            join=join_conditions,  # Pass the list of joins
            not_null_condition=False,  # Adjust if necessary
            multiple_where=False  # Adjust if necessary
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
            if type == 'object':
                self._object_members.add(member)
            elif type == 'group':
                self._group_object_members.add(member)
                # If needed, extract members of nested groups
                member.extract_members('object', object_cache, NetworkGroupObjectsMembersTable)
                member.extract_members('group', object_cache, NetworkGroupObjectsMembersTable)
        
class PioneerPortObject(PortObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_protocol = object_info[3]
        source_port_number = object_info[4]
        destination_port_number = object_info[5]
        object_description = object_info[6]
        overridable_object = object_info[7]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        PortObject.__init__(self, source_port_number, destination_port_number, object_protocol)
        self.set_uid(object_uid)

class PioneerICMPObject(ICMPObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_type = object_info[3]
        object_code = object_info[4]
        object_description = object_info[5]
        overridable_object = object_info[6]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        ICMPObject.__init__(self, object_type, object_code)
        self.set_uid(object_uid)

class PioneerPortGroupObject(PortGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        PortGroupObject.__init__(self)
        self.set_uid(object_uid)

    def extract_members(self, type, object_cache, PortGroupObjectsMembersTable):
        if type == 'object':
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

        elif type == 'icmp_object':
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

        elif type == 'group':
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
            raise ValueError(f"Unknown type: {type}")

        # Fetch members information
        members_info = PortGroupObjectsMembersTable.get(
            columns=columns,
            name_col=name_col,
            val=self.get_uid(),
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
            if type == 'object':
                self._object_members.add(member)
            elif type == 'icmp_object':
                self._icmp_object_members.add(member)
            elif type == 'group':
                self._group_object_members.add(member)
                # If needed, extract members of nested groups
                member.extract_members('port_object', object_cache, PortGroupObjectsMembersTable)
                member.extract_members('icmp_object', object_cache, PortGroupObjectsMembersTable)
                member.extract_members('group', object_cache, PortGroupObjectsMembersTable)

class PioneerURLObject(URLObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        url_value = object_info[3]
        overridable_object = object_info[4]
        object_description = object_info[5]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        URLObject.__init__(self, url_value)
        self.set_uid(object_uid)

class PioneerURLGroupObject(URLGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        URLGroupObject.__init__(self)
        self.set_uid(object_uid)

    def extract_members(self, type, object_cache, URLGroupObjectsMembersTable):
        if type == 'object':
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

        elif type == 'group':
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
            raise ValueError(f"Unknown type: {type}")

        # Fetch members information
        members_info = URLGroupObjectsMembersTable.get(
            columns=columns,
            name_col=name_col,
            val=self.get_uid(),
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
            if type == 'object':
                self._object_members.add(member)
            elif type == 'group':
                self._group_object_members.add(member)
                # If needed, extract members of nested groups
                member.extract_members('object', object_cache, URLGroupObjectsMembersTable)
                member.extract_members('group', object_cache, URLGroupObjectsMembersTable)

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
            objects_set.update(current_group.get_object_members())
            # Add new groups from the current group to the groups_to_process
            new_groups = current_group.get_group_object_members()
            groups_to_process.update(new_groups)
            group_objects_set.update(new_groups)
            # Mark the current group as processed
            processed_groups.add(current_group)
