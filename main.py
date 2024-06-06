import argparse
from roles_checker import RolePermissionChecker
from role_binding_checker import RoleBindingChecker
from utils import read_json_file

def get_argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cluster_roles_file', type=str, required=False, help='Path to the ClusterRoles JSON file')
    parser.add_argument('--roles_file', type=str, required=False, help='Path to the Roles JSON file')
    parser.add_argument('--role_bindings_file', type=str, required=False, help='Path to the RoleBindings JSON file')
    parser.add_argument('--cluster_role_bindings_file', type=str, required=False, help='Path to the ClusterRoleBindings JSON file')
    return parser.parse_args()

if __name__ == '__main__':
    args = get_argument_parser()
    extensive_roles = []
    extensive_cluster_roles = []

    if args.cluster_roles_file:
        print('\n[*] Started enumerating risky ClusterRoles:')
        cluster_role_data = read_json_file(args.cluster_roles_file)
        cluster_role_checker = RolePermissionChecker(cluster_role_data, 'ClusterRole')
        extensive_cluster_roles = list(cluster_role_checker.results.keys())

    if args.roles_file:
        print('[*] Started enumerating risky Roles:')
        role_data = read_json_file(args.roles_file)
        role_checker = RolePermissionChecker(role_data, 'Role')
        extensive_roles = list(role_checker.results.keys())
        extensive_roles = [role for role in extensive_roles if role not in extensive_cluster_roles]
        extensive_roles.extend(extensive_cluster_roles)

    if args.cluster_role_bindings_file:
        print('[*] Started enumerating risky ClusterRoleBindings:')
        cluster_role_binding_data = read_json_file(args.cluster_role_bindings_file)
        RoleBindingChecker(cluster_role_binding_data, extensive_roles, 'ClusterRoleBinding')

    if args.role_bindings_file:
        print('[*] Started enumerating risky RoleBindings:')
        role_binding_data = read_json_file(args.role_bindings_file)
        RoleBindingChecker(role_binding_data, extensive_roles, 'RoleBinding')
