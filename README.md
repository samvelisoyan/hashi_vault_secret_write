# hashi_vault_secret_write

An Ansible module that helps to create update and remove secrets in hashi Vault

Requirements
------------
### Ansible User Prerequisites

can be used by 'non-root' user as well

### Versions requarments

* Python 3


## Parameters

| Parameter | required | Choices/Defaults | Description |
|-----------|----------|---------------|-------------|
| vault_url | True |  | URL to vault service. |
| auth_method | False | ldap ← (default) <br /> token | Authentication method to be used. |
| user | False | | Authentication user name. |
| password | False | | Authentication password. |
| token | False | | vault token. |
| mount_point | True | | vault mount point |
| secret_path | True | | query you are making. |
| data | False | | A dictionary to be serialized to JSON and then sent as the request body. |
| validate_certs | False | False <br /> True ← (default) | validate certificate |
| state | False | presen ← (default) <br /> absent | If *absent*, secret will be deleted, if *presen* secret will be created |


### Exanple

```yaml
---
- hosts: localhost
  tasks:
    - name: Test that my module works
      hashi_vault_secret_write:
        vault_url: 'https://vault.com'
        validate_certs: true
        token: 's.m9dxLiYQRgL2DBjd7cqILZwZ'
        secret_path: 'test/secret'
        mount_point: 'secret'
        data:
          test: "test_value"
          test_key: '78'
```

Author Information
------------------
