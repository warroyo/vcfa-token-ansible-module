#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: vcfa auth 

short_description: this module authenticates with vcfa
version_added: "1.0.0"

description: this module authenticates with vcfa using a token and returns an access token that can be used in downstream api connections such as a kubeconfig. 

options:
    vcfa_host:
        description: The VCFA host URL
        required: true
        type: str
    token:
        description: The refresh token for authentication
        required: true
        type: str
    tenant:
        description: The tenant name
        required: true
        type: str
    insecure:
        description: Skip TLS verification
        required: false
        type: bool
        default: false
    ca_cert_path:
        description: Path to CA certificate
        required: false
        type: str
        default: null

author:
    - Your Name (@warroyo)
'''

EXAMPLES = r'''
# Authenticate with VCFA
- name: Get access token from VCFA
  vcfa_auth:
    vcfa_host: "vcfa.example.com"
    token: "your_api_token"
    tenant: "your_org"
    insecure: false
    ca_cert_path: "/path/to/ca.crt"
'''

RETURN = r'''
access_token:
    description: The obtained access token
    type: str
    returned: always
    sample: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
token_type:
    description: The type of token returned
    type: str
    returned: always
    sample: 'Bearer'
expires_in:
    description: Token expiration time in seconds
    type: int
    returned: always
    sample: 3600
'''

import json
import urllib.parse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from ansible.module_utils.basic import AnsibleModule


class Token:
    def __init__(self, access_token=None, token_type=None, expires_in=None, refresh_token=None):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token


def create_http_client(ca_cert_path=None, skip_tls_verify=False, timeout=0):
    """Create an HTTP client with optional CA certificate and TLS verification settings"""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Configure SSL verification
    if skip_tls_verify:
        session.verify = False
    elif ca_cert_path:
        session.verify = ca_cert_path
    
    return session


def get_access_token(tm_endpoint, api_token, ca_cert_path=None, skip_tls_verify=False):
    """Get access token using refresh token"""
    try:
        data = {
            'refresh_token': api_token,
            'grant_type': 'refresh_token'
        }
        
        http_client = create_http_client(ca_cert_path, skip_tls_verify)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = http_client.post(
            tm_endpoint,
            data=urllib.parse.urlencode(data),
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 403:
            return None, "Failed to authenticate. Please provide valid token"
        elif response.status_code != 200:
            return None, "Failed to authenticate. Please provide valid details or check the provided token type"
        
        # Parse response
        try:
            token_data = response.json()
            token = Token(
                access_token=token_data.get('access_token'),
                token_type=token_data.get('token_type'),
                expires_in=token_data.get('expires_in'),
                refresh_token=token_data.get('refresh_token')
            )
            return token, None
        except json.JSONDecodeError as e:
            return None, f"Could not unmarshal auth token: {str(e)}"
            
    except requests.exceptions.RequestException as e:
        return None, f"Failed to authenticate: {str(e)}"


def run_module():
    module_args = dict(
        vcfa_host=dict(type='str', required=True),
        token=dict(type='str', required=True),
        tenant=dict(type='str', required=True),
        insecure=dict(type='bool', required=False, default=False),
        ca_cert_path=dict(type='str', required=False, default=None)
    )

    result = dict(
        changed=False,
        access_token='',
        token_type='',
        expires_in=0
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    host = module.params['vcfa_host']
    token = module.params['token']
    tenant = module.params['tenant']
    insecure = module.params['insecure']
    ca_cert_path = module.params['ca_cert_path']

    tm_endpoint = f"https://{host}/tm/oauth/tenant/{tenant}/token"
    
    try:
        token_obj, error = get_access_token(tm_endpoint, token, ca_cert_path, insecure)
        
        if error:
            module.fail_json(msg=error, **result)
        
        if token_obj:
            result['changed'] = True
            result['access_token'] = token_obj.access_token
            result['token_type'] = token_obj.token_type
            result['expires_in'] = token_obj.expires_in
            result['message'] = 'Successfully obtained access token'
        else:
            module.fail_json(msg='Failed to obtain access token', **result)

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()