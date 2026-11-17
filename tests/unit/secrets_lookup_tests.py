# (c) 2024, Bitwarden <hello@bitwarden.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "lookup")))

from secrets import filter_secrets, extract_field, is_valid_field, is_valid_uuid  # noqa: E402


SECRETS = [
    {"id": "a", "key": "db_password", "projectId": "p1"},
    {"id": "b", "key": "api_key", "projectId": "p1"},
    {"id": "c", "key": "smtp_password", "projectId": "p2"},
]


def test_is_valid_uuid():
    assert is_valid_uuid("9165d7a8-2c22-476e-8add-b0d50162c5cc")
    assert not is_valid_uuid("not-a-uuid")
    assert not is_valid_uuid(None)


def test_is_valid_field():
    assert is_valid_field("id")
    assert is_valid_field("key")
    assert is_valid_field("projectId")
    assert is_valid_field("all")
    assert not is_valid_field("value")
    assert not is_valid_field("bogus")


def test_filter_secrets_by_project():
    assert filter_secrets(SECRETS, "p1") == SECRETS[:2]
    assert filter_secrets(SECRETS, "p2") == [SECRETS[2]]
    assert filter_secrets(SECRETS, None) == SECRETS
    assert filter_secrets(SECRETS, "p3") == []


def test_extract_field():
    assert extract_field(SECRETS, "key") == ["db_password", "api_key", "smtp_password"]
    assert extract_field(SECRETS, "id") == ["a", "b", "c"]
    assert extract_field(SECRETS, "all") == SECRETS
