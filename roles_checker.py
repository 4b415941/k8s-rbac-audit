import logging

class RolePermissionChecker:
    def __init__(self, json_data, role_type):
        self.logger = logging.getLogger(role_type)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(f'[!][%(name)s] → %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.json_data = json_data
        self.detections = {}
        self.analyze_roles()

    @property
    def results(self):
        return self.detections

    def add_detection(self, role_name, issue):
        if role_name:
            if role_name not in self.detections:
                self.detections[role_name] = [issue]
            else:
                self.detections[role_name].append(issue)

    def analyze_roles(self):
        for role in self.json_data['items']:
            role_name = role['metadata']['name']
            for rule in role['rules']:
                if 'resources' not in rule:
                    continue
                self.check_read_secrets(rule, role_name)
                self.check_cluster_admin(rule, role_name)
                self.check_any_resource(rule, role_name)
                self.check_any_verb(rule, role_name)
                self.check_high_risk_resources(rule, role_name)
                self.check_role_bindings(rule, role_name)
                self.check_create_pods(rule, role_name)
                self.check_pods_exec(rule, role_name)
                self.check_pods_attach(rule, role_name)

    def check_read_secrets(self, rule, role_name):
        verbs = ['*', 'get', 'list']
        if 'secrets' in rule['resources'] and any(verb in rule['verbs'] for verb in verbs):
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to list secrets!')
                self.add_detection(filtered_name, 'Has permission to list secrets!')

    def check_cluster_admin(self, rule, role_name):
        if '*' in rule['resources'] and '*' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has Admin-Cluster permission!')
                self.add_detection(filtered_name, 'Has Admin-Cluster permission!')

    def check_any_verb(self, rule, role_name):
        resources = ['secrets', 'pods', 'deployments', 'daemonsets', 'statefulsets', 'replicationcontrollers', 
                     'replicasets', 'cronjobs', 'jobs', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings', 
                     'users', 'groups']
        if any(resource in rule['resources'] for resource in resources) and '*' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to access {resources[0]} with any verb!')
                self.add_detection(filtered_name, f'Has permission to access {resources[0]} with any verb!')

    def check_any_resource(self, rule, role_name):
        verbs = ['delete', 'deletecollection', 'create', 'list', 'get', 'impersonate']
        if '*' in rule['resources'] and any(verb in rule['verbs'] for verb in verbs):
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to use {verbs[0]} on any resource!')
                self.add_detection(filtered_name, f'Has permission to use {verbs[0]} on any resource')

    def check_high_risk_resources(self, rule, role_name):
        high_risk_verbs = ['create', 'update']
        high_risk_resources = ['deployments', 'daemonsets', 'statefulsets', 'replicationcontrollers', 'replicasets', 'jobs', 'cronjobs']
        if any(resource in rule['resources'] for resource in high_risk_resources) and any(verb in rule['verbs'] for verb in high_risk_verbs):
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to {high_risk_verbs[0]} {high_risk_resources[0]}!')
                self.add_detection(filtered_name, f'Has permission to {high_risk_verbs[0]} {high_risk_resources[0]}!')

    def check_role_bindings(self, rule, role_name):
        resources = ['rolebindings', 'roles', 'clusterrolebindings']
        if any(resource in rule['resources'] for resource in resources) and 'create' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to create {resources[0]}!')
                self.add_detection(filtered_name, f'Has permission to create {resources[0]}!')

    def check_create_pods(self, rule, role_name):
        if 'pods' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to create pods!')
                self.add_detection(filtered_name, 'Has permission to create pods!')

    def check_pods_exec(self, rule, role_name):
        if 'pods/exec' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to use pod exec!')
                self.add_detection(filtered_name, 'Has permission to use pod exec!')

    def check_pods_attach(self, rule, role_name):
        if 'pods/attach' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.filter_default_names(role_name)
            if filtered_name:
                self.logger.warning(f'{filtered_name} has permission to attach pods!')
                self.add_detection(filtered_name, 'Has permission to attach pods!')

    @staticmethod
    def filter_default_names(name):
        default_names = ['system:', 'edit', 'admin', 'cluster-admin', 'aws-node', 'kubernetes-']
        if not any(name.startswith(prefix) for prefix in default_names):
            return name
