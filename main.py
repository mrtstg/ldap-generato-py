import yaml
import sys
import os
import time
import hashlib
import logging
from typing import Any, Optional, Dict, Union, List

logging.basicConfig(level=logging.INFO)

FILES_BUFFERS: Dict[str, str] = {}
FILES_FOLDER = "files"
if len(sys.argv) > 1:
    FILES_FOLDER = sys.argv[1]

with open("config.yaml", "r", encoding="utf-8") as file:
    CONFIG = yaml.safe_load(file.read())

DC: str = CONFIG["dc"]
LDAP_OBJECT = Dict[str, Union[str, List[str], List[int], int]]


def write_to_file(filename: str, content: str):
    if filename not in FILES_BUFFERS:
        FILES_BUFFERS[filename] = content
    else:
        FILES_BUFFERS[filename] += content


def dump_files():
    for file, content in FILES_BUFFERS.items():
        with open(os.path.join(FILES_FOLDER, file), "w") as file:
            file.write(content)


def generate_dn(
    data: LDAP_OBJECT,
    dn_field: Optional[str] = None,
    ou: Optional[str] = None,
    dn_value: Optional[Any] = None,
) -> str:
    output: str = "dn: "
    if dn_field is not None:
        if dn_value is None:
            output += "%(dn_f)s=%(dn_v)s," % {"dn_f": dn_field, "dn_v": data[dn_field]}
        else:
            output += "%s=%s," % (dn_field, dn_value)

    if ou is not None:
        output += "ou=%s," % ou

    output += ",".join([f"dc={key}" for key in DC.split(".")]) + "\n"
    return output


def generate_migration(dn: str, migration_data: List[dict]) -> str:
    output = ""
    for m_id, migration in enumerate(migration_data, 1):
        if m_id != 1:
            output += "-\n"
        else:
            output += "changetype: modify\n"
        m_type: str = migration["type"]
        field: str = migration["field"]
        output += f"{m_type}: {field}\n"
        if m_type != "delete":
            value: Any = migration[field]
            output += f"{field}: {value}\n"
    return dn + output


def represent_as_ldap_object(
    dn: str,
    data: LDAP_OBJECT,
) -> str:
    output: str = f"{dn}"
    for key, value in data.items():
        if isinstance(value, list):
            for v in value:
                output += "%s: %s\n" % (key, v)
        else:
            output += "%s: %s\n" % (key, value)
    return output


if CONFIG["createBaseFields"]:
    logging.info("Generating base fields...")
    base_fields: List[str] = CONFIG["baseFieldsList"]
    for field in base_fields:
        if field == "dcObject":
            dc_data = {
                "objectClass": ["top", "dcObject", "organization"],
                "o": DC,
                "dc": "ldap",
            }
            obj = represent_as_ldap_object("", dc_data) + "\n"
        elif field == "admin":
            admin_data = {
                "objectClass": ["simpleSecurityObject", "organizationalRole"],
                "cn": "admin",
                "description": "LDAP admin",
            }
            dn = generate_dn(admin_data, "cn")
            obj = (
                represent_as_ldap_object(
                    dn,
                    admin_data,
                )
                + "\n"
            )
        elif field == "groups":
            groups_ou_data = {
                "ou": "Groups",
                "objectClass": ["top", "organizationalUnit"],
            }
            dn = generate_dn(groups_ou_data, ou="Groups")
            obj = (
                represent_as_ldap_object(
                    dn,
                    groups_ou_data,
                )
                + "\n"
            )
        elif field == "users":
            users_ou_data = {
                "ou": "Users",
                "objectClass": ["top", "organizationalUnit"],
            }
            dn = generate_dn(users_ou_data, ou="Users")
            obj = (
                represent_as_ldap_object(
                    dn,
                    users_ou_data,
                )
                + "\n"
            )
        else:
            logging.error("Unexpected base field option: %s" % field)
            raise Exception("Not implemented!")
        write_to_file("base_objects.ldif", obj)

logging.info("Generating users...")
MIGRATE_SAMBA: bool = CONFIG["samba"]["migrate"]
SAMBA_DOMAIN_SID: str = CONFIG["samba"]["sid"]
GROUP_MEMBERSHIPS: Dict[str, List[str]] = {}
USERS_DATA: Dict[str, Dict[str, Any]] = {}
USERS_GROUPS: Dict[str, List[str]] = {}
for index, (user_uid, user_name) in enumerate(CONFIG["users"]["userNames"].items()):
    USERS_DATA[user_uid] = {
        "uid": user_uid,
        "cn": user_name,
        "sn": user_name.split(" ")[1],
        "uidNumber": CONFIG["users"]["numerateUidFrom"] + index,
        "gidNumber": CONFIG["users"]["numerateGidFrom"] + index,
        "homeDirectory": "/home/%s" % user_uid,
        "loginShell": "/bin/bash",
    }
    for d_k, d_v in CONFIG["users"]["defFields"].items():
        USERS_DATA[user_uid][d_k] = d_v

    USERS_GROUPS[user_uid] = CONFIG["users"]["defGroups"] + (
        CONFIG["users"]["addToGroup"][user_uid]
        if user_uid in CONFIG["users"]["addToGroup"]
        else []
    )

    if user_uid in CONFIG["users"]["customFields"]:
        for key, value in CONFIG["users"]["customFields"][user_uid].items():
            USERS_DATA[user_uid][key] = value

    for u, g in CONFIG["users"]["customGroups"].items():
        USERS_GROUPS[u] = g

    for group_cn in USERS_GROUPS[user_uid]:
        if group_cn not in GROUP_MEMBERSHIPS:
            GROUP_MEMBERSHIPS[group_cn] = []

        GROUP_MEMBERSHIPS[group_cn].append(
            "uid=%s,ou=Users,%s"
            % (user_uid, ",".join([f"dc={key}" for key in DC.split(".")]))
        )

    if MIGRATE_SAMBA:
        password_hash: str = hashlib.new(
            "md4", USERS_DATA[user_uid]["userPassword"].encode("UTF-16LE")
        ).hexdigest()
        user_sid: str = (
            SAMBA_DOMAIN_SID + "-" + str(USERS_DATA[user_uid]["uidNumber"] * 2 + 1000)
        )
        user_dn: str = generate_dn(USERS_DATA[user_uid], "uid", "Users")
        write_to_file(
            "samba.ldif",
            generate_migration(
                user_dn,
                [
                    {
                        "type": "add",
                        "field": "objectClass",
                        "objectClass": "sambaSamAccount",
                    },
                    {"type": "add", "field": "sambaSID", "sambaSID": user_sid},
                    {
                        "type": "add",
                        "field": "sambaPasswordHistory",
                        "sambaPasswordHistory": "00000000000000000000000000000000000000000000000000000000",
                    },
                    {
                        "type": "add",
                        "field": "sambaNTPassword",
                        "sambaNTPassword": password_hash,
                    },
                    {
                        "type": "add",
                        "field": "sambaPwdLastSet",
                        "sambaPwdLastSet": int(time.time()),
                    },
                    {"type": "add", "field": "sambaAcctFlags", "sambaAcctFlags": "[U]"},
                ],
            )
            + "\n",
        )

for group_cn in CONFIG["groups"]["cns"]:
    if group_cn not in GROUP_MEMBERSHIPS:
        raise Exception("Group of names must have members!")
    group_data = {
        "cn": group_cn,
        "objectClass": "groupOfNames",
        "member": GROUP_MEMBERSHIPS[group_cn],
    }
    if group_cn == CONFIG["samba"]["groupCn"]:
        group_data["objectClass"] = ["sambaGroupMapping", "posixGroup"]
        group_data["gidNumber"] = CONFIG["samba"]["groupGid"]
    group_dn = generate_dn(group_data, "cn", "Groups")
    write_to_file(
        "groups.ldif",
        represent_as_ldap_object(group_dn, group_data) + "\n",
    )

for user_data_object in USERS_DATA.values():
    user_dn = generate_dn(user_data_object, "uid", "Users")
    write_to_file(
        "users.ldif",
        represent_as_ldap_object(user_dn, user_data_object) + "\n",
    )

dump_files()
