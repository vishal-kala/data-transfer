from grant_core_privileges import grant_core_privileges_py

result = grant_core_privileges_py(None, env='DEV', suffix='WIP', userwarehouse='COMPUTE_DEVCORE', enablewip='TRUE')

print(result)
