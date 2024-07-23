import argparse
import sys
import utils.exceptions as PioneerExceptions
import logging
import os
import psutil
import uuid

def generate_uid():
    """
    Generates a UUID (Universally Unique Identifier) and returns it as a string.
    """
    return str(uuid.uuid4())

general_logger = logging.getLogger('general')

def create_parser():
    """
    Creates and configures the argument parser for the Pioneer CLI tool.

    Pioneer is a vendor-agnostic CLI tool for migrating firewall policies. This function sets up the argument parser,
    defines mutually exclusive argument groups, and specifies individual arguments related to projects, devices, 
    mappings and so on.

    Returns:
        argparse.ArgumentParser: Configured argument parser for Pioneer CLI tool.
    """
    # Initialize the argument parser with a description
    parser = argparse.ArgumentParser(description="Pioneer is a vendor-agnostic CLI tool for migrating firewall policies.")
    
    # Create a mutually exclusive group for create, set, and delete parameters
    exclusive_arg_group = parser.add_mutually_exclusive_group()
    
    # Arguments related to projects
    exclusive_arg_group.add_argument("--create-project [name]", help="Create a migration project.")
    exclusive_arg_group.add_argument("--delete-project [name]", help="Delete a migration project.")
    exclusive_arg_group.add_argument("--list-projects", help="Print a list of all projects.")
    exclusive_arg_group.add_argument("--project [name]", help="Specify the migration project where you make the changes.")
    parser.add_argument("--set-source-device [name]", help="Set the source device of the project.")
    parser.add_argument("--set-target-device [name]", help="Set the target device of the project.")

    # Arguments related to devices
    exclusive_arg_group.add_argument("--delete-security-device [name]", help="Delete a security device.")
    exclusive_arg_group.add_argument("--list-security-devices", help="List all security devices.")
    parser.add_argument("--create-security-device [name]", help="Create a security device.")
    parser.add_argument("--device-type [type]", help="Specify the type of device you are creating.")
    parser.add_argument("--username [username]", help="Specify the user to perform operations on the device.")
    parser.add_argument("--secret [secret]", help="Specify the password or API token of the user.")
    parser.add_argument("--hostname [hostname]", help="Specify the hostname or IP address of the security device.")
    parser.add_argument("--port [port]", default='https', help="Specify the port. Default value is https.")
    parser.add_argument("--domain [fmc_domain]", default='Global', help="For FMC devices, specify the administration domain.")

    parser.add_argument("--device-name [device_name]", help="Specify the security device where you make the changes.")
    parser.add_argument("--migrate", nargs='?', const=True, default=False, help="Flag to initiate the migration process.")

    # Container mapping arguments
    parser.add_argument("--map-containers", action='store_true', help="Flag to indicate if you want to map containers.")
    parser.add_argument("--source-container", dest='source_container_name', help="Specify the source container name.")
    parser.add_argument("--target-container", dest='target_container_name', help="Specify the target container name.")

    # Zone mapping arguments
    parser.add_argument("--map-zones", action='store_true', help="Flag to indicate if you want to map zones.")
    parser.add_argument("--source-zone", dest='source_zone_name', help="Specify the source zone name.")
    parser.add_argument("--target-zone", dest='target_zone_name', help="Specify the target zone name.")
    
    parser.add_argument("--target-device", dest='target_device_name', help="Specify the target security device for changes.")

    # Import configuration argument
    parser.add_argument("--import-config", nargs='?', const=True, default=False, help="Flag to import configuration from the target device.")
    parser.add_argument("--security-policy-container [container_name]", help="Import a security policy container.")

    # Temporary arguments related to migration projects
    parser.add_argument("--send-logs-to-manager", help="Specify the manager name to send logs to.")
    parser.add_argument("--set-security-profile", help="Specify the security profile name.")

    # Arguments related to both devices and projects
    parser.add_argument("--description [description]", help="Add a description for the project/device. Max length is 256 characters.", default='no description')

    # Parse the arguments and print help message if no arguments are supplied
    parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    return parser

def setup_logging(log_folder, log_files=None):
    """
    Set up logging configuration.

    This function creates a log folder if it doesn't exist and configures logging to write errors and above to the console
    and all levels of logs to the specified log files in the specified log folder.

    Parameters:
        log_folder (str): Path to the log folder where log files will be stored.
        log_files (dict, optional): Dictionary containing logger names as keys and corresponding log file names as values. 
                                    If not provided, a default filename ('logfile.log') will be used.

    Returns:
        None
    """
    # Create the log folder if it doesn't exist
    os.makedirs(log_folder, exist_ok=True)

    # Get the root logger
    root_logger = logging.getLogger()

    # Set the logger level to DEBUG to capture all levels of logs
    root_logger.setLevel(logging.DEBUG)

    # Create a custom formatter with desired format and explicit encoding
    class UnicodeFormatter(logging.Formatter):
        def format(self, record):
            # Ensure the message is properly encoded to handle Unicode characters
            record.msg = str(record.msg).encode('utf-8', errors='replace').decode('utf-8')
            return super().format(record)

    # Instantiate the custom formatter
    formatter = UnicodeFormatter('%(asctime)s - %(levelname)s - %(message)s')

    # Configure logging to write errors and above to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)  # Log only errors and above to the console
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Configure logging to write to multiple files
    if log_files is not None:
        for logger_name, log_file in log_files.items():
            # Create a logger for each log file
            file_logger = logging.getLogger(logger_name)
            file_logger.setLevel(logging.DEBUG)
            
            # Create a file handler for each log file
            file_handler = logging.FileHandler(os.path.join(log_folder, log_file), mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_logger.addHandler(file_handler)

def load_protocol_mapping():
    """
    Load and return a dictionary mapping protocol numbers to their respective protocol names.

    This function returns a dictionary where each key is a protocol number (as a string), and the value is the name 
    of the protocol associated with that number. This mapping helps in interpreting protocol numbers in network data.

    Returns:
        dict: A dictionary mapping protocol numbers (str) to protocol names (str).
    """

    return {
    "0": "HOPOPT",
    "1": "ICMP",
    "2": "IGMP",
    "3": "GGP",
    "4": "IP-in-IP",
    "5": "ST",
    "6": "TCP",
    "7": "CBT",
    "8": "EGP",
    "9": "IGP",
    "10": "BBN-RCC-MON",
    "11": "NVP-II",
    "12": "PUP",
    "13": "ARGUS",
    "14": "EMCON",
    "15": "XNET",
    "16": "CHAOS",
    "17": "UDP",
    "18": "MUX",
    "19": "DCN-MEAS",
    "20": "HMP",
    "21": "PRM",
    "22": "XNS-IDP",
    "23": "TRUNK-1",
    "24": "TRUNK-2",
    "25": "LEAF-1",
    "26": "LEAF-2",
    "27": "RDP",
    "28": "IRTP",
    "29": "ISO-TP4",
    "30": "NETBLT",
    "31": "MFE-NSP",
    "32": "MERIT-INP",
    "33": "DCCP",
    "34": "3PC",
    "35": "IDPR",
    "36": "XTP",
    "37": "DDP",
    "38": "IDPR-CMTP",
    "39": "TP++",
    "40": "IL",
    "41": "IPv6",
    "42": "SDRP",
    "43": "IPv6-Route",
    "44": "IPv6-Frag",
    "45": "IDRP",
    "46": "RSVP",
    "47": "GRE",
    "48": "DSR",
    "49": "BNA",
    "50": "ESP",
    "51": "AH",
    "52": "I-NLSP",
    "53": "SWIPE",
    "54": "NARP",
    "55": "MOBILE",
    "56": "TLSP",
    "57": "SKIP",
    "58": "IPv6-ICMP",
    "59": "IPv6-NoNxt",
    "60": "IPv6-Opts",
    "61": "Any host internal protocol",
    "62": "CFTP",
    "63": "Any local network",
    "64": "SAT-EXPAK",
    "65": "KRYPTOLAN",
    "66": "RVD",
    "67": "IPPC",
    "68": "Any distributed file system",
    "69": "SAT-MON",
    "70": "VISA",
    "71": "IPCV",
    "72": "CPNX",
    "73": "CPHB",
    "74": "WSN",
    "75": "PVP",
    "76": "BR-SAT-MON",
    "77": "SUN-ND",
    "78": "WB-MON",
    "79": "WB-EXPAK",
    "80": "ISO-IP",
    "81": "VMTP",
    "82": "SECURE-VMTP",
    "83": "VINES",
    "84": "TTP/IPTM",
    "85": "NSFNET-IGP",
    "86": "DGP",
    "87": "TCF",
    "88": "EIGRP",
    "89": "OSPFIGP",
    "90": "Sprite-RPC",
    "91": "LARP",
    "92": "MTP",
    "93": "AX.25",
    "94": "IPIP",
    "95": "MICP",
    "96": "SCC-SP",
    "97": "ETHERIP",
    "98": "ENCAP",
    "99": "Any private encryption scheme",
    "100": "GMTP",
    "101": "IFMP",
    "102": "PNNI",
    "103": "PIM",
    "104": "ARIS",
    "105": "SCPS",
    "106": "QNX",
    "107": "A/N",
    "108": "IPComp",
    "109": "SNP",
    "110": "Compaq-Peer",
    "111": "IPX-in-IP",
    "112": "VRRP",
    "113": "PGM",
    "114": "Any 0-hop protocol",
    "115": "L2TP",
    "116": "DDX",
    "117": "IATP",
    "118": "STP",
    "119": "SRP",
    "120": "UTI",
    "121": "SMP",
    "122": "SM",
    "123": "PTP",
    "124": "ISIS over IPv4",
    "125": "FIRE",
    "126": "CRTP",
    "127": "CRUDP",
    "128": "SSCOPMCE",
    "129": "IPLT",
    "130": "SPS",
    "131": "PIPE",
    "132": "SCTP",
    "133": "FC",
    "134": "RSVP-E2E-IGNORE",
    "135": "Mobility Header",
    "136": "UDPLite",
    "137": "MPLS-in-IP",
    "138": "manet",
    "139": "HIP",
    "140": "Shim6",
    "141": "WESP",
    "142": "ROHC",
    "143-252": "Unassigned",
    "253": "Use for experimentation and testing",
    "254": "Use for experimentation and testing",
    "255": "Reserved"
    }

def protocol_number_to_keyword(protocol_number):
    """
    Convert a protocol number to its corresponding protocol name.

    This function uses a predefined mapping of protocol numbers to protocol names. It retrieves the name for the given
    protocol number. If the protocol number is not recognized, it raises an exception.

    Parameters:
        protocol_number (str): The protocol number as a string to be converted to its corresponding name.

    Returns:
        str: The name of the protocol corresponding to the given number.

    Raises:
        PioneerExceptions.UnknownProtocolNumber: If the provided protocol number is not in the mapping dictionary.
    """
    # Load the dictionary mapping protocol numbers to protocol names
    protocol_mapping = load_protocol_mapping()

    # Check if the provided protocol_number exists in the protocol_mapping dictionary
    if protocol_number not in protocol_mapping:
        # Raise an exception if the protocol_number is not recognized
        raise PioneerExceptions.UnknownProtocolNumber(protocol_number)

    # Return the protocol name corresponding to the provided protocol_number
    return protocol_mapping[protocol_number]

def netmask_to_cidr_bits(netmask):
    """
    Convert a netmask to its corresponding CIDR prefix length.

    This function takes a netmask in dotted decimal format and converts it to the equivalent CIDR notation prefix length.
    The CIDR prefix length represents the number of bits set to '1' in the netmask.

    Parameters:
        netmask (str): The netmask in dotted decimal format (e.g., '255.255.255.0').

    Returns:
        int: The CIDR prefix length corresponding to the netmask, or None if the netmask format is invalid.

    Raises:
        ValueError: If the netmask is not in a valid dotted decimal format or contains non-numeric values.
    """
    try:
        # Convert the netmask to its binary representation by:
        # 1. Splitting the netmask into its four octets.
        # 2. Converting each octet to an 8-bit binary string.
        # 3. Concatenating these binary strings to form the full binary representation of the netmask.
        binary_netmask = ''.join(format(int(octet), '08b') for octet in netmask.split('.'))

        # Count the number of '1' bits in the binary netmask to determine the CIDR prefix length.
        cidr_prefix_length = binary_netmask.count('1')

        return cidr_prefix_length

    except ValueError:
        # Return None if there's an error in the conversion process, indicating an invalid netmask format.
        return None
