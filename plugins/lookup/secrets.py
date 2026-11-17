#!/usr/bin/env python

# (c) 2024, Bitwarden <hello@bitwarden.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: secrets
author:
  - Bitwarden (@bitwarden) <hello@bitwarden.com>
version_added: "1.1.0"
short_description: List secrets from Bitwarden Secrets Manager
description:
  - This lookup lists secrets accessible to the machine account in Bitwarden Secrets Manager,
    optionally filtered by project.
options:
  organization_id:
    description: Organization ID to list secrets from.
    required: True
    type: string
  project_id:
    description: Only return secrets belonging to this project.
    required: False
    type: string
  field:
    description: Field to return from each secret. Use 'all' to return full secret identifiers as dictionaries.
    default: all
    required: False
    type: string
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
- name: List all secrets for an organization
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.secrets', organization_id='<your-organization-id>') }}"
- name: List secret keys for a project
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.secrets', organization_id='<your-organization-id>', project_id='<project-id>', field='key') }}"
"""

RETURN = """
_list:
  description: List of secret identifiers (or the selected field of each secret)
  type: list
"""

import os
from urllib.parse import urlparse
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
        "The bitwarden.secrets.secrets plugin requires the following python modules: 'bitwarden-sdk'."
    )

BITWARDEN_BASE_URL: str = "https://vault.bitwarden.com"
BITWARDEN_API_URL: str = "https://api.bitwarden.com"
BITWARDEN_IDENTITY_URL: str = "https://identity.bitwarden.com"

INVALID_ORGANIZATION_ID_ERROR: str = "Invalid organization ID, '{}'. The organization ID must be a UUID"
INVALID_PROJECT_ID_ERROR: str = "Invalid project ID, '{}'. The project ID must be a UUID"
INVALID_FIELD_ERROR: str = (
    "Invalid field: '{}'. Update this value to be one of the following: "
    "id, key, projectId, or 'all'"
)
INVALID_URL_ERROR: str = (
    "URL must start with http:// or https://, the provided {} URL is: '{}'"
)
LIST_SECRETS_ERROR: str = "Failed to list secrets: '{}'"
DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING: str = (
    "Using older access_token_login() method. Please update to the latest version of bitwarden-sdk."
)


def is_url(url: str) -> bool:
    try:
        result: urlparse = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except ValueError:
        return False


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def is_valid_field(field: str) -> bool:
    return field in ["id", "key", "projectId", "all"]


def filter_secrets(secrets: list, project_id: str = None) -> list:
    if project_id is None:
        return secrets
    return [s for s in secrets if s.get("projectId") == project_id]


def extract_field(secrets: list, field: str) -> list:
    if field == "all":
        return secrets
    return [s.get(field) for s in secrets]


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs) -> list:
        self.set_options(var_options=variables, direct=kwargs)

        organization_id = self.get_option("organization_id")
        if not organization_id or not is_valid_uuid(organization_id):
            raise AnsibleError(INVALID_ORGANIZATION_ID_ERROR.format(organization_id))

        project_id = self.get_option("project_id")
        if project_id is not None and not is_valid_uuid(project_id):
            raise AnsibleError(INVALID_PROJECT_ID_ERROR.format(project_id))

        field = self.get_option("field") or "all"
        if not is_valid_field(field):
            raise AnsibleError(INVALID_FIELD_ERROR.format(field))

        api_url = self.get_option("api_url")
        identity_url = self.get_option("identity_url")
        api_url, identity_url = self.get_urls(self.get_option("base_url"), api_url, identity_url)
        self.validate_urls(api_url, identity_url)

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
            from pathlib import Path

            state_dir = Path(os.path.expanduser(state_file_dir))
            state_dir.mkdir(parents=True, exist_ok=True)
            state_file = str(state_dir / "secrets-listing")
        except OSError as e:
            raise AnsibleError(f"Could not create state file directory: {e}") from e

        try:
            try:
                client.auth().login_access_token(access_token, state_file)
            except AttributeError:
                display.warning(DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING)
                client.access_token_login(access_token, state_file)
        except Exception as e:
            raise AnsibleLookupError(f"Failed to login with access token: '{e}'") from e

        try:
            response = client.secrets().list(organization_id)
            secrets: list = response.to_dict()["data"]
        except Exception as e:
            raise AnsibleLookupError(LIST_SECRETS_ERROR.format(e)) from e

        secrets = filter_secrets(secrets, project_id)
        return extract_field(secrets, field)

    @staticmethod
    def get_urls(base_url: str = None, api_url: str = None, identity_url: str = None) -> tuple:
        if base_url is not None:
            base_url = str(base_url).strip().rstrip("/")
        if api_url is not None:
            api_url = str(api_url).strip().rstrip("/")
        if identity_url is not None:
            identity_url = str(identity_url).strip().rstrip("/")
        if base_url and base_url != BITWARDEN_BASE_URL:
            return (f"{base_url}/api", f"{base_url}/identity")
        return (api_url or BITWARDEN_API_URL, identity_url or BITWARDEN_IDENTITY_URL)

    @staticmethod
    def validate_urls(api_url, identity_url) -> None:
        for url, url_type in [(api_url, "API"), (identity_url, "Identity")]:
            if not is_url(url):
                raise AnsibleError(INVALID_URL_ERROR.format(url_type, url))
