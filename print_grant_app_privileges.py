from grant_app_privileges import  grant_app_privileges_py

result = grant_app_privileges_py(None, env='DEV', suffix='WIP', userwarehouse='COMPUTE_DEVCORE', app_name='REFDATA',
                                 schema_name='HCE', app_zones=['RAW', 'TRUSTED'], enablewip='TRUE')

print(result)
