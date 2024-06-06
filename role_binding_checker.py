class RoleBindingChecker:
    def __init__(self, json_data, extensive_roles, binding_type):
        self.json_data = json_data
        self.extensive_roles = extensive_roles
        self.binding_type = binding_type
        self.detected_bindings = []
        self.check_bindings()

    def check_bindings(self):
        for binding in self.json_data['items']:
            binding_name = binding['metadata']['name']
            role_ref = binding['roleRef']['name']
            if 'subjects' not in binding:
                continue
            if role_ref in self.extensive_roles:
                self.detected_bindings.append(role_ref)
                for subject in binding['subjects']:
                    if 'name' not in subject:
                        continue
                    self.log_binding_results(subject, binding_name, self.binding_type)

    def log_binding_results(self, subject, binding_name, binding_type):
        if subject['kind'] == 'ServiceAccount':
            print(f'[!][{binding_type}] → {binding_name} is bound to {subject["name"]} ServiceAccount.')
        else:
            print(f'[!][{binding_type}] → {binding_name} is bound to the {subject["kind"]}: {subject["name"]}.')
