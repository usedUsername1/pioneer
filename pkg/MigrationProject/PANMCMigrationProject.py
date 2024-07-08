from pkg.MigrationProject import MigrationProject
class PANMCMigrationProject(MigrationProject):
    def __init__(self, name, Database):
        super().__init__(name, Database)
    
    def adapt_security_container_config(self):
        # adapt the config by applying name constraints, URL name constraints and by
        # converting the URLs in URL groups to URL categories - this might be a problem
        # change the interfaces 
        pass

    # save it to the file file, don't print it
    def print_compatibility_issues(self):
        print("""You are migrating to a Panorama Management Center device. The following is a list with compatibility issues and how they will be fixed:
Object/Policy/Port/URL object names: All names will be cut to have less than 63 characters. In case a name is longer than 63 characters, only the first 60 characters will be kept and
a random suffix will be generated in order to avoid duplicates. All special characters will be removed and replaced with "_".
Security Policies restricting ping access: All policies that control ping access will be split in two. The original policy and the ping policy. This is needed because 
PA treats ping as an application. The second rule will keep the exact same source and destinations, but will have all port objects removed and application set to ping.""" + '\n')