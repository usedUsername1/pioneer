import utils.helper as helper

class Object:
    def __init__(self, object_info) -> None:
        self._object_info = object_info
        self._name = None
        self._object_container = None
        self._description = None
        self._is_overridable = None
        self._object_container = None
    
    def get_name(self):
        return self._name
    
    def set_name(self, value):
        self._name = value
    
    def get_description(self):
        return self._description
    
    def set_description(self, value):
        self._description = value
    
    def get_override_bool(self):
        return self._is_overridable
    
    def set_override_bool(self, value):
        self._is_overridable = value
    
    def get_object_container_name(self):
        return self._object_container
    
    def set_object_container_name(self, value):
        self._object_container = value
    
    def process_object(self):
        pass

    def process_device_object(self, object_type):
        helper.logging.debug("Called process_device_object()")
        helper.logging.info(f"################## Processing device objects info. Processing the following objects: '{object_type}' ##################.")




class GroupObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._members = None
    
    def get_members(self):
        return self._members
    
    def set_members(self, members):
        self._members = members

    #TODO: define setters here!
    def process_object(self):
        
        self.set_name()
        self.set_object_container_name()
        self.set_members()
        self.set_description()
        self.set_override_bool()

        processed_group_object_info = {
        "network_address_group_name": self._name,
        "object_container_name": self._object_container,
        "network_address_group_members": self.get_members(),
        "network_address_group_description": self._description,
        "overridable_object": self._is_overridable
        }

        return processed_group_object_info
    
class NetworkObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._network_address_value = None
        self._network_address_type = None

    def get_network_address_value(self):
        return self._network_address_value
    
    def set_network_address_value(self, value):
        self._network_address_value = value

    def get_network_address_type(self):
        return self._network_address_type
    
    def set_network_address_type(self, value):
        self._network_address_type = value
    
    def process_object(self):
        processed_group_object_info = {
            "network_address_name": self._name,
            "object_container_name": self._object_container,
            "network_address_value": self.get_network_address_value(),
            "network_address_description": self._description,
            "network_address_type": self.get_network_address_type(),
            "overridable_object": self._is_overridable
        }

        return processed_group_object_info

class NetworkGroupObject(GroupObject):
    pass

# For simplicity, all geo data is going to be treated as a Geolocation object.
# For example, in FMC, you have Geolocation objects (made out of countries and other continents), and then you have the countries and the continents. they are not object entities per se
# but can be treated as such
class GeolocationObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._continents = None
        self._countries = None
        self._country_alpha2_codes = None
        self._country_alpha3_codes = None
        self._country_numeric_codes = None

    def set_continents(self, value):
        self._continents = value

    def get_continents(self):
        return self._continents

    def set_countries(self, value):
        self._countries = value

    def get_countries(self):
        return self._countries

    def set_country_alpha2_codes(self, value):
        self._country_alpha2_codes = value

    def get_country_alpha2_codes(self):
        return self._country_alpha2_codes

    def set_country_alpha3_codes(self, value):
        self._country_alpha3_codes = value

    def get_country_alpha3_codes(self):
        return self._country_alpha3_codes

    def set_country_numeric_codes(self, value):
        self._country_numeric_codes = value

    def get_country_numeric_codes(self):
        return self._country_numeric_codes

    def process_object(self):
        self.set_name()
        self.set_object_container_name()
        self.set_continents()
        self.set_countries()
        self.set_country_alpha2_codes()
        self.set_country_alpha3_codes()
        self.set_country_numeric_codes()

        processed_geolocation_object_info = {
            "geolocation_object_name": self._name,
            "object_container_name": self._object_container,
            "continent_member_names": self._continents,
            "country_member_names": self._countries,
            "country_member_alpha2_codes": self._country_alpha2_codes,
            "country_member_alpha3_codes": self._country_alpha3_codes,
            "country_member_numeric_codes": self._country_numeric_codes,           
        }

        return processed_geolocation_object_info


# class SecurityZone(Object):
#     def __init__(self, name, description, is_overridable, object_container_name=None) -> None:
#         super().__init__(name, description, is_overridable, object_container_name)


    