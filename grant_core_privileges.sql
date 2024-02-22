CREATE OR REPLACE PROCEDURE grant_core_privileges(ENV STRING, SUFFIX STRING, USERWAREHOUSE STRING, ENABLEWIP STRING)
  returns string not null
  language python
  runtime_version = '3.8'
  packages = ('snowflake-snowpark-python')
  handler = 'grant_core_privileges_py'
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


def grant_core_privileges_py(snowpark_session, env: str, suffix: str, userwarehouse: str, enablewip: str):
    import logging, sys
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    core_policy = {
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
        core_policy['MGSSFCOREDATAENG'] = core_policy['MGSSFCOREETL']

    for role, policy in core_policy.items():
        role = f'{role}{env}'
        sf_role = role

        statements.extend(warehouse_permission_statements(userwarehouse, sf_role))

        for zone, privs in policy.items():
            sf_database = f'{zone}_{suffix}'
            statements.extend(zone_permission_statements(sf_database, sf_role))

            if 'ETL' in privs:
                statements.extend(etl_permission_statements(sf_database, sf_role))

            if 'READ_ONLY' in privs:
                statements.extend(read_permission_statements(sf_database, sf_role))

            if 'READ_WRITE' in privs:
                statements.extend(read_permission_statements(sf_database, sf_role))
                statements.extend(write_permission_statements(sf_database, sf_role))

                if enablewip.lower() == 'true':
                    statements.extend(wip_specific_permission_statements(sf_database, sf_role))
                    statements.extend(change_mgmt_db_permission_statements(build_change_mgmt_db_name(suffix), sf_role))

    # Execute all statements
    result = exec_stmts(snowpark_session, statements)

    return f"{result}\nPrivileges granted successfully"


def build_change_mgmt_db_name(suffix):
    return f"DL_CHANGE_MGMT_{suffix}"


def warehouse_permission_statements(wh, role):
    statements = [f"grant usage on warehouse {wh} to role {role}"]

    return statements


def zone_permission_statements(db, role):
    statements = [
        f"grant usage on database {db} to role {role}",
        f"grant usage on all stages in database {db} to role {role}",
        f"grant usage on future stages in database {db} to role {role}",
        f"grant usage on all file formats in database {db} to role {role}",
        f"grant usage on future file formats in database {db} to role {role}",
        f"grant usage on all procedures in database {db} to role {role}",
        f"grant usage on future procedures in database {db} to role {role}",
        f"grant usage on all functions in database {db} to role {role}",
        f"grant usage on future functions in database {db} to role {role}"
    ]

    return statements


def etl_permission_statements(db, role):
    statements = [f"grant create view on all schemas in database {db} to role {role}"]

    return statements


def read_permission_statements(db, role):
    statements = [
        f"grant usage on all schemas in database {db} to role {role}",
        f"grant usage on future schemas in database {db} to role {role}",
        f"grant select on all tables in database {db} to role {role}",
        f"grant select on future tables in database {db} to role {role}",
        f"grant select on all external tables in database {db} to role {role}",
        f"grant select on future external tables in database {db} to role {role}",
        f"grant select on all views in database {db} to role {role}",
        f"grant select on future views in database {db} to role {role}",
        f"grant read on all stages in database {db} to role {role}",
        f"grant read on future stages in database {db} to role {role}",
        f"grant select on all streams in database {db} to role {role}",
        f"grant select on future streams in database {db} to role {role}",
        f"grant select on all materialized views in database {db} to role {role}",
        f"grant select on future materialized views in database {db} to role {role}",
        f"grant select on all dynamic tables in database {db} to role {role}",
        f"grant select on future dynamic tables in database {db} to role {role}"
    ]

    return statements


def write_permission_statements(db, role):
    statements = [
        f"grant insert, update, delete, truncate, references on all tables in database {db} to role {role}",
        f"grant insert, update, delete, truncate, references on future tables in database {db} to role {role}",
        f"grant insert, update, delete, truncate, references on all external tables in database {db} to role {role}",
        f"grant insert, update, delete, truncate, references on future external tables in database {db} to role {role}",
        f"grant monitor, operate on all tasks in database {db} to role {role}",
        f"grant monitor, operate on future tasks in database {db} to role {role}",
        f"grant operate on all dynamic tables in database {db} to role {role}",
        f"grant operate on future dynamic tables in database {db} to role {role}"
    ]

    return statements


def wip_specific_permission_statements(db, role):
    statements = [
        f"grant create schema on database {db} to role {role}",
        f"grant create table on all schemas in database {db} to role {role}",
        f"grant create external table on all schemas in database {db} to role {role}",
        f"grant create dynamic table on all schemas in database {db} to role {role}",
        f"grant create file format on all schemas in database {db} to role {role}"
    ]

    return statements


def change_mgmt_db_permission_statements(change_mgmt_db, role):
    statements = [
        f"grant all on database {change_mgmt_db} to role {role}",
        f"grant usage, monitor on all schemas in database {change_mgmt_db} to role {role}",
        f"grant all on all schemas in database {change_mgmt_db} to role {role}",
        f"grant all on all tables in database {change_mgmt_db} to role {role}",
        f"grant usage on all procedures in database {change_mgmt_db} to role {role}",
        f"grant usage on future procedures in database {change_mgmt_db} to role {role}"
    ]

    return statements

$$
;

