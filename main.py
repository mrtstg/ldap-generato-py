import yaml
import sys
import os
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


def represent_as_ldap_object(
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
            obj = (
                represent_as_ldap_object(
                    {
                        "objectClass": ["top", "dcObject", "organization"],
                        "o": DC,
                        "dc": "ldap",
                    }
                )
                + "\n"
            )
        elif field == "admin":
            obj = (
                represent_as_ldap_object(
                    {
                        "objectClass": ["simpleSecurityObject", "organizationalRole"],
                        "cn": "admin",
                        "description": "LDAP admin",
                    },
                    dn_field="cn",
                )
                + "\n"
            )
        elif field == "groups":
            obj = (
                represent_as_ldap_object(
                    {"ou": "Groups", "objectClass": ["top", "organizationalUnit"]},
                    ou="Groups",
                )
                + "\n"
            )
        elif field == "users":
            obj = (
                represent_as_ldap_object(
                    {"ou": "Users", "objectClass": ["top", "organizationalUnit"]},
                    ou="Users",
                )
                + "\n"
            )
        else:
            logging.error("Unexpected base field option: %s" % field)
            raise Exception("Not implemented!")
        write_to_file("base_objects.ldif", obj)

logging.info("Generating groups...")
GROUP_DATA: Dict[str, dict] = {}
for group_id, group_cn in enumerate(
    CONFIG["groups"]["cns"], CONFIG["groups"]["numerateFrom"]
):
    GROUP_DATA[group_cn] = {
        "cn": group_cn,
        "objectClass": ["posixGroup", "groupOfMembers"],
        "gidNumber": group_id,
    }

logging.info("Generating users...")
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

for user_data_object in USERS_DATA.values():
    write_to_file(
        "users.ldif",
        represent_as_ldap_object(user_data_object, dn_field="uid", ou="Users") + "\n",
    )

logging.info("Generating member list...")
for uid, groups in USERS_GROUPS.items():
    for group in groups:
        if "member" not in GROUP_DATA[group]:
            GROUP_DATA[group]["member"] = []

        GROUP_DATA[group]["member"].append(
            "uid=%s,ou=Users,%s"
            % (uid, ",".join([f"dc={p}" for p in CONFIG["dc"].split(".")]))
        )

for group in GROUP_DATA.values():
    write_to_file("groups.ldif", represent_as_ldap_object(group, "cn", "Groups") + "\n")
dump_files()
