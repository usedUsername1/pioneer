# contains custom exceptions related to the pioneer program

# this is an exception that will be raised whenever an unkown IANA-protocol number is passed
# to the function protocol_number_to_keyword()
class UnknownProtocolNumber(Exception):
    """Exception raised for unknown protocol numbers."""
    def __init__(self, protocol_number):
        self.protocol_number = protocol_number
        self.message = f"Unknown protocol number: {protocol_number}"
        super().__init__(self.message)