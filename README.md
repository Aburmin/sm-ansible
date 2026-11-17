# Bitwarden Secrets Manager Collection

Securely retrieve secrets from Bitwarden Secrets Manager and use them in your Ansible playbooks.

## Getting started

### Install dependencies

The Bitwarden Secrets Manager Collection requires the `bitwarden-sdk` package. You can install it by
running the following command:

```bash
pip install bitwarden-sdk
```

### Install the collection

You can install the Bitwarden Secrets Manager Collection by running:

```bash
ansible-galaxy collection install bitwarden.secrets
```

### Update your playbook

Before running your playbook, you need to set the `BWS_ACCESS_TOKEN` environment variable:

```bash
# the line below will prevent lines with leading spaces from being saved to bash history
export HISTCONTROL=ignorespace

# the space in the line below keeps your access token out of bash history
 export BWS_ACCESS_TOKEN=<your_access_token>
```

Alternatively, you may supply the access token as a parameter to the `bitwarden.secrets.lookup`
plugin:

<!-- prettier-ignore -->
> [!Note]\
> We are using a `vars_prompt` to avoid storing the access token in the playbook. While
> there are many ways to pass the access token to the lookup plugin, we recommend against storing it
> in the playbook itself.

For more information on how to use the Bitwarden Secrets Manager Collection, see the
[documentation](https://bitwarden.com/help/ansible-integration).

### Run your playbook

Once you've updated your playbook to use the Bitwarden Secrets Manager lookup plugin, you can run it
with the `ansible-playbook` command:

```bash
ansible-playbook <path_to_your_playbook.yml>
```

#### macOS

If your Ansible controller is running macOS, you may need to set the following environment variable
to avoid an error related to fork safety:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

See
[running on macos as a control node](https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#running-on-macos-as-a-control-node)
and [this GitHub issue](https://github.com/ansible/ansible/issues/49207) for more details.

## Querying organizations and listing secrets

List the secrets a machine account can access, optionally filtered by project:

```yaml
- name: List secret keys for a project
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.secrets', organization_id='<your-organization-id>', project_id='<project-id>', field='key') }}"
```

Query organization details:

```yaml
- name: Query an organization
  ansible.builtin.debug:
    msg: "{{ lookup('bitwarden.secrets.organization', '<your-organization-id>') }}"
```

## Creating, updating, and deleting secrets

The `bitwarden.secrets.secret` module manages secrets with a machine account access token. It
supports check mode and will not modify secrets when run with `--check`:

```yaml
- name: Create or update a secret
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
```

See `examples/manage_secrets.yml` for a complete example.
