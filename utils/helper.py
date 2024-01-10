import argparse
import sys
import psycopg2

# this function returns a parser objects for the pioneer tool
def create_parser():
    parser = argparse.ArgumentParser(description="Pioneer is a vendor-agnostic CLI tool for migrating firewall policies.")
    
    # the create, set and delete parameters should be mutually exclusive
    exclusive_arg_group = parser.add_mutually_exclusive_group()
    
    # TODO: implement arguments for the --pro
    # arguments related to projects
    exclusive_arg_group.add_argument("--create-project [name]", help="Create a migration project.")
    exclusive_arg_group.add_argument("--delete-project [name]", help="Delete a migration project.")
    exclusive_arg_group.add_argument("--list-projects", help="Print a list with all the projects.")
    exclusive_arg_group.add_argument("--project [name]", help="Specify the migration project where you make the changes.")
    exclusive_arg_group.add_argument("--import-security-device --device [name]", help="Import a security device into a project.")

    # arguments related to devices
    exclusive_arg_group.add_argument("--delete-security-device [name]", help="Delete a security device.")
    exclusive_arg_group.add_argument("--list-security-devices", help="List all security devices.")
    parser.add_argument("--create-security-device [name]", help="Create a security device.")
    parser.add_argument("--device-type [type]", help="Specify the device type you are creating.")
    parser.add_argument("--username [username]", help="Specify the user that you will use to perform operations on the device.")
    parser.add_argument("--secret [secret]", help="Specify the password or the API token of the user.")
    parser.add_argument("--hostname [hostname]", help="Specify the hostname or the IP address of the security device.")
    parser.add_argument("--port [port]", default='https', help="Specify the port. Implicit value is https")
    parser.add_argument("--domain [fmc_domain]", default='Global', help="Only for FMC devices. Specify the administration domain")

    parser.add_argument("--device-name [device_name]", help="Specify the security device where you make the changes.")
    parser.add_argument("--import-sec-policy-package", help="Import a policy package from target device. If nothing is specifed, all policy packages are imported")
    parser.add_argument("--import-nat-policy-package", help="Import a NAT policy package from the target device. If nothing is specifed, all NAT policy packages are imported.")

    # arguments related both to devices and projects
    parser.add_argument("--description [description]", help="Add a description for the project/device. Max length is 256 characters", default='no description')

    # parse the arguments, print help message if no arguments are supplied
    parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    return parser

