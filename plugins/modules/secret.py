#!/usr/bin/env python

# (c) 2024, Bitwarden <hello@bitwarden.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: secret
short_description: Create, update, or delete secrets in Bitwarden Secrets Manager
description:
  - Manage secrets in Bitwarden Secrets Manager using a machine account access token.
version_added: "1.1.0"
author:
  - Bitwarden (@bitwarden) <hello@bitwarden.com>
options:
  state:
    description: Whether the secret should exist.
    default: present
    choices: [present, absent]
    type: str
  key:
    description: Key (name) of the secret. Required unless secret_id is provided with state=absent.
    type: str
  value:
    description: Value of the secret. Required when creating a new secret.
    type: str
  note:
    description: Note of the secret.
    type: str
  project_id:
    description: Project the secret belongs to. Required when creating a new secret.
    type: str
  secret_id:
    description: ID of an existing secret to update or delete.
    type: str
  organization_id:
    description: Organization ID. Required when deleting by key instead of secret_id.
    type: str
  access_token:
    description: Access token to use.
    default: $BWS_ACCESS_TOKEN
    env:
      - name: BWS_ACCESS_TOKEN
    required: True
    type: str
  base_url:
    description: Base url to use. If provided, api_url and identity_url will be ignored.
    default: https://vault.bitwarden.com
    type: str
  api_url:
    description: API url to use. If provided, identity_url must also be provided.
    default: https://api.bitwarden.com
    type: str
  identity_url:
    description: Identity url to use. If provided, api_url must also be provided.
    default: https://identity.bitwarden.com
    type: str
  state_file_dir:
    description: Directory to store state file for authentication.
    default: ~/.config/bitwarden-sm-ansible
    type: str
"""

EXAMPLES = """
- name: Create a secret
  bitwarden.secrets.secret:
    state: present
    key: api_key
    value: "{{ api_key }}"
    note: "Managed by Ansible"
    project_id: "{{ project_id }}"

- name: Update an existing secret by ID
  bitwarden.secrets.secret:
    state: present
    secret_id: "{{ secret_id }}"
    value: "{{ new_value }}"

- name: Delete a secret by ID
  bitwarden.secrets.secret:
    state: absent
    secret_id: "{{ secret_id }}"
"""

RETURN = """
secret:
  description: Details of the managed secret
  type: dict
  returned: always
changed:
  description: Whether the secret was modified
  type: bool
  returned: always
"""

import os
from pathlib import Path
import uuid

from ansible.module_utils.basic import AnsibleModule
from ansible.utils.display import Display

display = Display()

try:
    from bitwarden_sdk import (
        BitwardenClient,
        DeviceType,
        client_settings_from_dict,
    )
except ImportError:
    BitwardenClient = None

BITWARDEN_BASE_URL = "https://vault.bitwarden.com"
BITWARDEN_API_URL = "https://api.bitwarden.com"
BITWARDEN_IDENTITY_URL = "https://identity.bitwarden.com"

DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING = (
    "Using older access_token_login() method. Please update to the latest version of bitwarden-sdk."
)


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False


def build_client(api_url: str, identity_url: str) -> "BitwardenClient":
    return BitwardenClient(
        client_settings_from_dict(
            {
                "apiUrl": api_url,
                "deviceType": DeviceType.SDK,
                "identityUrl": identity_url,
                "userAgent": "bitwarden/sm-ansible",
            }
        )
    )


def login(client, access_token: str, state_file: str) -> None:
    try:
        client.auth().login_access_token(access_token, state_file)
    except AttributeError:
        display.warning(DEPRECATED_ACCESS_TOKEN_LOGIN_WARNING)
        client.access_token_login(access_token, state_file)


def get_urls(base_url, api_url, identity_url):
    if base_url is not None:
        base_url = str(base_url).strip().rstrip("/")
    if api_url is not None:
        api_url = str(api_url).strip().rstrip("/")
    if identity_url is not None:
        identity_url = str(identity_url).strip().rstrip("/")
    if base_url and base_url != BITWARDEN_BASE_URL:
        return (f"{base_url}/api", f"{base_url}/identity")
    return (api_url or BITWARDEN_API_URL, identity_url or BITWARDEN_IDENTITY_URL)


def run_module():
    module_args = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        key=dict(type="str", default=None),
        value=dict(type="str", default=None, no_log=True),
        note=dict(type="str", default=None, no_log=True),
        project_id=dict(type="str", default=None),
        secret_id=dict(type="str", default=None),
        organization_id=dict(type="str", default=None),
        access_token=dict(type="str", default=None, no_log=True),
        base_url=dict(type="str", default=None),
        api_url=dict(type="str", default=None),
        identity_url=dict(type="str", default=None),
        state_file_dir=dict(type="str", default="~/.config/bitwarden-sm-ansible"),
    )

    result = dict(changed=False, secret=dict())

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if BitwardenClient is None:
        module.fail_json(msg="The bitwarden.secrets.secret module requires the 'bitwarden-sdk' python package.")

    state = module.params["state"]
    key = module.params["key"]
    value = module.params["value"]
    note = module.params["note"]
    project_id = module.params["project_id"]
    secret_id = module.params["secret_id"]
    organization_id = module.params["organization_id"]

    for param, name in [(secret_id, "secret_id"), (project_id, "project_id"), (organization_id, "organization_id")]:
        if param is not None and not is_valid_uuid(param):
            module.fail_json(msg=f"Invalid {name}, '{param}'. The {name} must be a UUID")

    if state == "present":
        if secret_id is None and (key is None or value is None or project_id is None):
            module.fail_json(msg="Creating a secret requires key, value, and project_id.")
        if secret_id is None and not is_valid_uuid(project_id):
            module.fail_json(msg=f"Invalid project_id, '{project_id}'. The project_id must be a UUID")
    else:
        if secret_id is None and (key is None or organization_id is None):
            module.fail_json(msg="Deleting by key requires key and organization_id. Alternatively, provide secret_id.")

    api_url, identity_url = get_urls(module.params["base_url"], module.params["api_url"], module.params["identity_url"])
    client = build_client(api_url, identity_url)

    access_token = module.params["access_token"] or os.getenv("BWS_ACCESS_TOKEN")
    try:
        state_dir = Path(os.path.expanduser(module.params["state_file_dir"]))
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = str(state_dir / "secret-module")
    except OSError as e:
        module.fail_json(msg=f"Could not create state file directory: {e}", **result)

    try:
        login(client, access_token, state_file)
    except Exception as e:
        module.fail_json(msg=f"Failed to login with access token: '{e}'", **result)

    secrets_api = client.secrets()

    try:
        if state == "present":
            if secret_id is not None:
                existing = secrets_api.get(secret_id).to_dict()["data"]
                new_key = key if key is not None else existing["key"]
                new_value = value if value is not None else existing["value"]
                new_note = note if note is not None else existing["note"]
                changed = (
                    new_key != existing["key"]
                    or new_value != existing["value"]
                    or new_note != existing["note"]
                )
                if changed and not module.check_mode:
                    secrets_api.update(secret_id, new_key, new_value, new_note)
                result["secret"] = dict(
                    id=secret_id, key=new_key, projectId=existing["projectId"]
                )
            else:
                existing_secrets = secrets_api.list(organization_id).to_dict()["data"]
                matches = [
                    s
                    for s in existing_secrets
                    if s.get("key") == key and s.get("projectId") == project_id
                ]
                if matches:
                    existing = secrets_api.get(matches[0]["id"]).to_dict()["data"]
                    changed = existing["value"] != value or existing["note"] != (note or existing["note"])
                    if changed and not module.check_mode:
                        secrets_api.update(existing["id"], key, value, note or existing["note"])
                    result["secret"] = dict(id=existing["id"], key=key, projectId=project_id)
                else:
                    changed = True
                    if not module.check_mode:
                        created = secrets_api.create(project_id, key, value, note).to_dict()["data"]
                        result["secret"] = dict(
                            id=created["id"], key=key, projectId=project_id
                        )
                    else:
                        result["secret"] = dict(key=key, projectId=project_id)
            result["changed"] = changed
        else:
            if secret_id is not None:
                existing = secrets_api.get(secret_id).to_dict()["data"]
                result["secret"] = dict(id=secret_id, key=existing["key"])
                if not module.check_mode:
                    secrets_api.delete([secret_id])
                result["changed"] = True
            else:
                existing_secrets = secrets_api.list(organization_id).to_dict()["data"]
                matches = [
                    s
                    for s in existing_secrets
                    if s.get("key") == key and s.get("projectId") == project_id
                ]
                result["secret"] = dict(key=key, projectId=project_id)
                if matches:
                    if not module.check_mode:
                        secrets_api.delete([s["id"] for s in matches])
                    result["changed"] = True
    except Exception as e:
        module.fail_json(msg=f"Failed to manage secret: '{e}'", **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
