#!/usr/bin/env python

# (c) 2024, Bitwarden <hello@bitwarden.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: organization
author:
  - Bitwarden (@bitwarden) <hello@bitwarden.com>
version_added: "1.1.0"
short_description: Query an organization from Bitwarden Secrets Manager
description:
  - This lookup returns details about a Bitwarden organization, such as its name,
    as visible to the machine account.
options:
  _terms:
    description: Organization ID to query
    required: True
  access_token:
    description: Access token to use
    default: $BWS_ACCESS_TOKEN
    env:
      - name: BWS_ACCESS_TOKEN
    required: True
    type: string
  base_url:
    description: Base url to use. If provided, api_url and identity_url will be ignored.
    default: https://vault.bitwarden.com
    required: False
    type: string
  api_url:
    description: API url to use. If provided, identity_url must also be provided.
    default: https://api.bitwarden.com
    required: False
    type: string
  identity_url:
    description: Identity url to use. If provided, api_url must also be provided.
    default: https://identity.bitwarden.com
    required: False
    type: string
  state_file_dir:
    description: Directory to store state file for authentication.
    default: ~/.config/bitwarden-sm-ansible
    required: False
    type: string
"""

EXAMPLES = """
- name: Query an organization
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.organization', '<your-organization-id>') }}"
- name: Get the organization name
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.organization', '<your-organization-id>').name }}"
"""

RETURN = """
_list:
  description: Organization details as a dictionary
  type: list
  elements: dict
"""

import os
from pathlib import Path
import uuid

from ansible.errors import AnsibleError, AnsibleLookupError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

try:
    from bitwarden_sdk import (
        BitwardenClient,
        DeviceType,
        client_settings_from_dict,
    )
except ImportError as bitwarden_sdk:
    BW_SDK_IMPORT_ERROR = bitwarden_sdk
else:
    BW_SDK_IMPORT_ERROR = None

if BW_SDK_IMPORT_ERROR:
    raise AnsibleError(
        "The bitwarden.secrets.organization plugin requires the following python modules: 'bitwarden-sdk'."
    )

INVALID_ORGANIZATION_ID_ERROR: str = "Invalid organization ID, '{}'. The organization ID must be a UUID"
ORGANIZATION_LOOKUP_ERROR: str = (
    "The requested organization could not be found: '{}'. "
    "Please ensure your bitwarden-sdk version supports organizations().get() "
    "and the machine account can access the organization. Original error: {}"
)
LOGIN_ACCESS_TOKEN_ERROR: str = "Failed to login with access token: '{}'"
DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING: str = (
    "Using older access_token_login() method. Please update to the latest version of bitwarden-sdk."
)


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs) -> list[dict]:
        self.set_options(var_options=variables, direct=kwargs)

        if not terms:
            raise AnsibleError("No organization_id provided")
        organization_id = terms[0]
        if not is_valid_uuid(organization_id):
            raise AnsibleError(INVALID_ORGANIZATION_ID_ERROR.format(organization_id))

        api_url = self.get_option("api_url")
        identity_url = self.get_option("identity_url")
        api_url, identity_url = self.get_urls(self.get_option("base_url"), api_url, identity_url)

        access_token = self.get_option("access_token") or os.getenv("BWS_ACCESS_TOKEN")
        state_file_dir = self.get_option("state_file_dir")

        client: BitwardenClient = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": api_url,
                    "deviceType": DeviceType.SDK,
                    "identityUrl": identity_url,
                    "userAgent": "bitwarden/sm-ansible",
                }
            )
        )

        try:
            state_dir = Path(os.path.expanduser(state_file_dir))
            state_dir.mkdir(parents=True, exist_ok=True)
            state_file = str(state_dir / "organization-lookup")
        except OSError as e:
            raise AnsibleError(f"Could not create state file directory: {e}") from e

        try:
            try:
                client.auth().login_access_token(access_token, state_file)
            except AttributeError:
                display.warning(DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING)
                client.access_token_login(access_token, state_file)
        except Exception as e:
            raise AnsibleLookupError(LOGIN_ACCESS_TOKEN_ERROR.format(e)) from e

        try:
            organization = client.organizations().get(organization_id)
            data = organization.to_dict()
            return [data.get("data", data)]
        except Exception as e:
            raise AnsibleLookupError(ORGANIZATION_LOOKUP_ERROR.format(organization_id, e)) from e

    @staticmethod
    def get_urls(base_url: str = None, api_url: str = None, identity_url: str = None) -> tuple:
        if base_url is not None:
            base_url = str(base_url).strip().rstrip("/")
        if api_url is not None:
            api_url = str(api_url).strip().rstrip("/")
        if identity_url is not None:
            identity_url = str(identity_url).strip().rstrip("/")
        if base_url and base_url != "https://vault.bitwarden.com":
            return (f"{base_url}/api", f"{base_url}/identity")
        return (api_url or "https://api.bitwarden.com", identity_url or "https://identity.bitwarden.com")
