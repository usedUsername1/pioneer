from pkg.SecurityZone import SecurityZone
class FMCSecurityZone(SecurityZone):
    def __init__(self, ZoneContainer, object_info) -> None:
        self._name = object_info['name']
        super().__init__(ZoneContainer, object_info, self._name)