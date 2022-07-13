#!/usr/bin/python3

from ansible.module_utils.basic import *
from jsonmerge import merge
import requests
import json
import urllib3

def update_secret(data, secret_url, session, module):
    vault_data_body = '{"data":' + json.dumps(data) + "}"
    try:
        post_data = session.post(secret_url, data=vault_data_body)
    except:
        module.fail_json(msg="faild to update secret: " + str(post_data.text))

    if post_data.status_code == 200:
        module.exit_json(changed=True, found=True)

    else:
        module.fail_json(msg="faild to update secret: " + str(post_data.text))


def main():

    module = AnsibleModule(
        argument_spec={
            'vault_url': {'required': True},
            'auth_method': {'default': 'ldap', 'choices': ['token', 'ldap',]},
            'user': {'type': 'str'},
            'token': {'type': 'str', 'no_log': True},
            'password': {'type': 'str', 'no_log': True},
            'mount_point': {'required': True},
            'secret_path': {'required': True},
            'data': {'type': 'dict', 'default': {} },
            'validate_certs': {'type': 'bool', 'default': True, 'choices': [False, True]},
            'state': {'default': 'present', 'choices': ['present', 'absent']}
            },
        supports_check_mode=True
    )

    api_version = "v1"
    vault_url = module.params['vault_url']
    if vault_url.endswith('/'):
        vault_url=vault_url[:-1]

    auth_method = module.params['auth_method']
    token = module.params['token']
    user = module.params['user']
    password = module.params['password']
    mount_point = module.params['mount_point']
    secret_path = module.params['secret_path']
    if secret_path.startswith('/'):
        secret_path=secret_path[1:]

    data = module.params['data']
    validate_certs = module.params['validate_certs']
    state = module.params['state']

    api_url = vault_url + '/' + api_version

    session = requests.Session()
    session.verify = validate_certs

    if validate_certs == False:
        from urllib3.exceptions import InsecureRequestWarning
        urllib3.disable_warnings()

    if auth_method == 'ldap':
        url_token = api_url + '/auth/ldap/login/' + user
        auth = session.post(url_token, json={ 'password': password })

        if auth.status_code != 200:
            module.fail_json(msg="authentication failed: " + str(auth.text))

        token = auth.json()['auth']['client_token']

    session.headers.update({'X-Vault-Token': token})

    url_get = api_url + '/' + mount_point + '/data/' + secret_path
    get_vault = session.get(url_get)

    if get_vault.status_code == 200:
        data_in_vault = json.loads(get_vault.text)['data']['data']
        final_data = merge(data_in_vault, data)

        if final_data == data_in_vault:
            module.exit_json(changed=False, found=True)
        else:
            update_secret(final_data, url_get, session, module)

    elif get_vault.status_code == 404:
        update_secret(data, url_get, session, module)

    else:
        module.fail_json(msg="faild to get data from vault: " + str(get_vault.text))

main()
