from pkg.SecurityZone import SecurityZone

class FMCSecurityZone(SecurityZone):
    def __init__(self, zone_container, object_info) -> None:
        """
        Initialize an FMCSecurityZone instance.

        Args:
            zone_container (ZoneContainer): The container that holds the security zone.
            object_info (dict): Dictionary containing information about the security zone. 
                                Must include 'name' as a key.

        """
        super().__init__(zone_container, object_info['name'])
        self._object_info = object_info