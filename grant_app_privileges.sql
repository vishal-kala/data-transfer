CREATE OR REPLACE PROCEDURE grant_app_privileges(ENV STRING, SUFFIX STRING, USERWAREHOUSE STRING, APP_NAME STRING, SCHEMA_NAME STRING, APP_ZONES ARRAY, ENABLEWIP STRING)
  returns string not null
  language python
  runtime_version = '3.8'
  packages = ('snowflake-snowpark-python')
  handler = 'grant_app_privileges_py'
as
$$
def exec_stmt(snowpark_session, stmt):
    try:
        if snowpark_session:
            snowpark_session.sql(stmt).collect()
        return "Success\n"
    except Exception as e:
        return f"Error while executing {stmt}. {e}\n"


def exec_stmts(snowpark_session, stmt_list):
    result = ""

    for stmt in stmt_list:
        result += f"{stmt}\n"
        result += exec_stmt(snowpark_session, stmt)

    return result


def grant_app_privileges_py(snowpark_session, env: str, suffix: str, userwarehouse: str, app_name: str,
                            schema_name: str, app_zones: list, enablewip: str):
    app_policy = {
        "MGSSFCOREETL": {
            "DISCOVERY": ["READ_WRITE", "ETL"],
            "RAW": ["READ_WRITE", "ETL"],
            "ARCHIVE": ["READ_WRITE", "ETL"],
            "TRUSTED": ["READ_WRITE", "ETL"],
            "REFINED": ["READ_WRITE", "ETL"],
            "REPORTING": ["READ_WRITE", "ETL"],
            "ANALYTICS": ["READ_WRITE", "ETL"]
        },
        "MGSSFCOREDATAENG": {
            "DISCOVERY": ["READ_WRITE"],
            "RAW": ["READ_ONLY"],
            "ARCHIVE": ["READ_ONLY"],
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_ONLY"],
            "REPORTING": ["READ_ONLY"],
            "ANALYTICS": ["READ_ONLY"]
        },
        "MGSSFCOREDATASTW": {
            "DISCOVERY": ["READ_WRITE"],
            "RAW": ["READ_ONLY"],
            "ARCHIVE": ["READ_ONLY"],
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_ONLY"],
            "REPORTING": ["READ_ONLY"],
            "ANALYTICS": ["READ_ONLY"]
        },
        "MGSSFCOREDATAANY": {
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_WRITE"],
            "REPORTING": ["READ_WRITE"],
        },
        "MGSSFCOREDATASCI": {
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_ONLY"],
            "REPORTING": ["READ_ONLY"],
            "ANALYTICS": ["READ_WRITE"]
        },
        "MGSSFCOREANYENG": {
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_WRITE"],
            "REPORTING": ["READ_WRITE"],
            "ANALYTICS": ["READ_WRITE"]
        },
        "MGSSFCOREBUSU": {
            "TRUSTED": ["READ_ONLY"],
            "REFINED": ["READ_ONLY"],
            "REPORTING": ["READ_ONLY"],
            "ANALYTICS": ["READ_ONLY"]
        }
    }

    statements = []

    # When WIP is enabled, the Data Engineer will assume the same permissions as the ETL role.
    if enablewip.lower() == 'true':
        app_policy['MGSSFCOREDATAENG'] = app_policy['MGSSFCOREETL']

    # Handle App Specific Roles
    for role, policy in app_policy.items():
        role = role.replace('CORE', app_name)
        sf_role = f'{role}{env}'

        statements.extend(warehouse_permission_statements(userwarehouse, sf_role))

        for zone, privs in policy.items():
            if zone not in app_zones:
                continue

            sf_database = f'{zone}_{suffix}'
            sf_schema = f'{zone}_{suffix}.{schema_name}'

            statements.extend(all_roles_permission_statements(sf_database, sf_schema, sf_role))

            if 'ETL' in privs:
                statements.extend(etl_role_permission_statements(sf_schema, sf_role))

            if 'READ_ONLY' in privs:
                statements.extend(read_only_permission_statements(sf_schema, sf_role))

            if 'READ_WRITE' in privs:
                statements.extend(read_write_permission_statements(sf_schema, sf_role))

                if enablewip.lower() == 'true':
                    statements.extend(wip_specific_permission_statements(sf_schema, sf_role))
                    statements.extend(change_mgmt_db_permission_statements(build_change_mgmt_db_name(suffix), sf_role))

    # Handle Future permissions for Core Roles
    for role, policy in app_policy.items():
        sf_role = f'{role}{env}'

        for zone, privs in policy.items():
            if zone not in app_zones:
                continue

            sf_schema = f'{zone}_{suffix}.{schema_name}'

            statements.extend(all_core_roles_permission_statements(sf_schema, sf_role))

            if 'READ_ONLY' in privs:
                statements.extend(read_only_core_permission_statements(sf_schema, sf_role))

            if 'READ_WRITE' in privs:
                statements.extend(read_write_core_permission_statements(sf_schema, sf_role))

    # Execute all statements
    result = exec_stmts(snowpark_session, statements)

    return f"{result}\nPrivileges granted successfully"


def build_change_mgmt_db_name(suffix):
    return f"DL_CHANGE_MGMT_{suffix}"


def warehouse_permission_statements(wh, role):
    statements = [f"grant usage on warehouse {wh} to role {role}"]

    return statements


def permission_metrics():
    metrics = {
        "dynamic table": {
            "read-only": "SELECT",
            "read-write": "SELECT, MONITOR, OPERATE"
        },
        "event table": {
            "read-only": "SELECT",
            "read-write": "SELECT, INSERT"
        },
        "external table": {
            "read-only": "SELECT",
            "read-write": "SELECT, INSERT, UPDATE, DELETE, REFERENCES"
        },
        "file format": {
            "all-roles": "USAGE"
        },
        "function": {
            "all-roles": "USAGE"
        },
        "materialized view": {
            "read-only": "SELECT",
            "read-write": "SELECT"
        },
        "model": {
            "all-roles": "USAGE"
        },
        "pipe": {
            "all-roles": "USAGE",
            "read-write": "MONITOR, OPERATE"
        },
        "procedure": {
            "all-roles": "USAGE"
        },
        "sequence": {
            "all-roles": "USAGE"
        },
        "stage": {
            "all-roles": "USAGE",
            "read-only": "READ",
            "read-write": "READ, WRITE"
        },
        "stream": {
            "read-only": "SELECT",
            "read-write": "SELECT"
        },
        "table": {
            "read-only": "SELECT",
            "read-write": "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES"
        },
        "view": {
            "read-only": "SELECT",
            "read-write": "SELECT",
            "etl-role": "CREATE"
        }
    }

    return metrics


def permission_statements(schema, role, perm_type):
    statements = []

    for db_object, permissions in permission_metrics().items():
        if perm_type in permissions:
            statements.append(
                f"grant {permissions[perm_type].lower()} on all {db_object}s in schema {schema} to role {role}")
            statements.append(
                f"grant {permissions[perm_type].lower()} on future {db_object}s in schema {schema} to role {role}")

    return statements


def all_roles_permission_statements(db, schema, role):
    statements = []

    statements.append(f"grant usage on database {db} to role {role}")
    statements.append(f"grant usage on schema {schema} to role {role}")

    statements.extend(permission_statements(schema, role, 'all-roles'))

    return statements


def etl_role_permission_statements(schema, role):
    statements = []

    for db_object, permissions in permission_metrics().items():
        if 'etl-role' in permissions:
            statements.append(f"grant create {db_object} on schema {schema} to role {role}")

    return statements


def read_only_permission_statements(db, role):
    return permission_statements(db, role, 'read-only')


def read_write_permission_statements(db, role):
    return permission_statements(db, role, 'read-write')


def wip_specific_permission_statements(schema, role):
    statements = []

    for db_object, permissions in permission_metrics().items():
        statements.append(f"grant create {db_object} on schema {schema} to role {role}")

    return statements


def change_mgmt_db_permission_statements(change_mgmt_db, role):
    statements = [
        f"grant all on database {change_mgmt_db} to role {role}",
        f"grant all on all schemas in database {change_mgmt_db} to role {role}",
        f"grant all on all tables in database {change_mgmt_db} to role {role}",

        f"grant usage, monitor on all schemas in database {change_mgmt_db} to role {role}",

        f"grant usage on all procedures in database {change_mgmt_db} to role {role}",
        f"grant usage on future procedures in database {change_mgmt_db} to role {role}"
    ]

    return statements


def future_permission_statements(schema, role, perm_type):
    statements = []

    for db_object, permissions in permission_metrics().items():
        if perm_type in permissions:
            statements.append(
                f"grant {permissions[perm_type].lower()} on future {db_object}s in schema {schema} to role {role}")

    return statements


def all_core_roles_permission_statements(schema, role):
    return future_permission_statements(schema, role, 'all-roles')


def read_only_core_permission_statements(schema, role):
    return future_permission_statements(schema, role, 'read-only')


def read_write_core_permission_statements(schema, role):
    return future_permission_statements(schema, role, 'read-write')


$$
;
