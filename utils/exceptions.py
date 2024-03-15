# contains custom exceptions related to the pioneer program

# this is an exception that will be raised whenever an unkown IANA-protocol number is passed
# to the function protocol_number_to_keyword()
class UnknownProtocolNumber(Exception):
    """Exception raised for unknown protocol numbers."""
    def __init__(self, protocol_number):
        self.protocol_number = protocol_number
        self.message = f"Unknown protocol number: {protocol_number}"
        super().__init__(self.message)

class InexistentContainer(Exception):
    """Exception raised when the user tries to import a device group that does not exist."""

    def __init__(self, message="Device group not found") -> None:
        self._message = message
        super().__init__(self._message)