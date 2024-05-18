from pkg.SecurityZone import SecurityZone
class FMCSecurityZone(SecurityZone):
    def __init__(self, ZoneContainer, object_info) -> None:
        super().__init__(ZoneContainer, object_info)
    
    def set_name(self):
        name = self._object_info['name']
        return super().set_name(name)