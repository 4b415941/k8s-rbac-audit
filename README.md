# Kubernetes Role and RoleBinding Analyzer

This script analyzes Kubernetes roles and role bindings to identify potential security risks.

## Features

- Reads configurations from specified JSON files
- Detects dangerous permissions such as listing secrets, admin privileges, and access to high-risk resources
- Logs findings of risky permissions and bindings
- Checks if risky roles are bound to specific users or service accounts

## Usage

1. Clone the repository:

   ```sh
   git clone https://github.com/4b415941/k8s-rbac-audit.git
   cd repo-name
   ```

2. Install required dependencies:

   ```sh
   pip install -r requirements.txt
   ```

3. Run the script with the required JSON files:

   ```sh
   python main.py --cluster_roles_file cluster_roles.json --roles_file roles.json --role_bindings_file role_bindings.json --cluster_role_bindings_file cluster_role_bindings.json
   ```

## Arguments

- `--cluster_roles_file`: Path to the ClusterRoles JSON file
- `--roles_file`: Path to the Roles JSON file
- `--role_bindings_file`: Path to the RoleBindings JSON file
- `--cluster_role_bindings_file`: Path to the ClusterRoleBindings JSON file

## Example

```sh
python main.py --cluster_roles_file cluster_roles.json --roles_file roles.json --role_bindings_file role_bindings.json --cluster_role_bindings_file cluster_role_bindings.json
```

## How It Works

1. **Input Files and Arguments:**
   - Reads Kubernetes role and role binding configurations from specified JSON files.

2. **Role Permission Analysis:**
   - Analyzes `ClusterRole` and `Role` configurations.
   - Detects and logs risky permissions.

3. **Role Binding Analysis:**
   - Analyzes `RoleBinding` and `ClusterRoleBinding` configurations.
   - Checks if risky roles are bound to specific users or service accounts.
   - Logs findings of risky role bindings.

By identifying security vulnerabilities in Kubernetes configurations, this script contributes to a more secure environment.
