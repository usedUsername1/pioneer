import utils.helper as helper

class Container:
    def __init__(self, name, security_device_name, parent) -> None:
        self._name = name
        self._security_device_name = security_device_name
        self._parent = parent


    def get_name(self):
        return self._name

    def get_parent(self):
        return self._parent

    def get_security_device_name(self):
        return self._security_device_name
    
    def is_child_container(self):
        if self._parent is None:
            helper.logging.info(f"Security policy container: {self._name}, is a NOT child container.")
            return False
        else:
            helper.logging.info(f"Security policy container: {self._name}, is a child container.")
            return True
    

    def get_container_info(self):
        helper.logging.debug(f"Called get_container_info with the following container: {self._name}")
        print("I AM IN GET CONTAINER INFO FROM CONTAINER CLASS")
        """
        Retrieves information about security policy containers.

        Args:
            policy_container_names_list (list): A list of names of security policy containers.

        Returns:
            list: A list of dictionaries containing information about each security policy container.
                Each dictionary has the following keys:
                - 'security_policy_container_name': Name of the security policy container.
                - 'security_policy_parent': Name of the parent security policy container, or None if it has no parent."""
        security_policies_container_processed_info = []

        if sec_policy_container.is_child_container():
            # Try to retrieve the parent of the policy. There is an "inherit" boolean attribute in the acp_info response. If it is equal to 'true', then the policy has a parent
            while sec_policy_container.is_child_container():
                # Get the name of the current ACP name
                child_policy_container_name = sec_policy_container.get_name()

                # Get the name of the acp parent
                parent_policy_container_name = sec_policy_container.get_parent_name()

                helper.logging.info(f"Security policy container: {child_policy_container_name}, is the child of {parent_policy_container_name}.")
                security_policies_container_processed_info.append({
                    'security_policy_container_name': child_policy_container_name,
                    'security_policy_parent': parent_policy_container_name
                })

                #TODO: how do you retrieve the info of the parent container here?
                # Retrieve the parent info to be processed in the next iteration of the loop
                sec_policy_container = self.get_security_policy_container_info(name=parent_policy_container_name)


            # If the parent policy does not have a parent, then map the ACP to None
            else:
                helper.logging.info(f"Security policy container: {parent_policy_container_name}, is not a child contaier.")
                security_policies_container_processed_info.append({
                    'security_policy_container_name': parent_policy_container_name,
                    'security_policy_parent': None
                })
        
        else:
            security_policies_container_processed_info.append({
                'security_policy_container_name': self._name,
                'security_policy_parent': None
            })


        helper.logging.debug(f"I am done processing the info of security policy containers. Got the following data: {security_policies_container_processed_info}.")
        return security_policies_container_processed_info
        


class ObjectsContainer(Container):
    pass

class SecurityPoliciesContainer(Container):
    pass

class NATPoliciesContainer(Container):
    pass

