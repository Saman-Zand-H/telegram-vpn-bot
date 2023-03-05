import random, string, json, base64
from codecs import encode
from logging import getLogger
import sys, hashlib, shutil, subprocess, shlex
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from collections import deque
from models import TrojanUsers, TrojanBase
from v2ray_util.global_setting.stats_ctr import Loader, StatsFactory
from v2ray_util.util_core.group import Trojan, Vmess, Vless, Mtproto, Socks
from v2ray_util.util_core.writer import NodeWriter
from v2ray_util.util_core.selector import GroupSelector, CommonSelector
from v2ray_util.util_core.utils import is_email, random_email, xtls_flow
from itertools import chain, groupby
from operator import attrgetter

from typing import List


def random_str(length=7):
    return "".join(random.choices(string.ascii_letters, k=length))


def generate_password(username: str):
    digit = [str(ord(i) + 13) for i in username]
    return f"{username.lower()}{''.join(digit)}{encode(username.lower(), 'rot13')}"


def generate_trojan_str(password, domain="whiteelli.tk", port=443, name="FreeConf"):
    return (
        f"trojan://{password}@{domain}:{port}?"
        "security=tls&headerType=none&type=tcp&"
        f"sni={domain}#{name}"
    )


logger = getLogger(__name__)


class TrojanBackend:
    def __init__(
        self,
        host: str = "vpn-mysql-do-user-13215775-0.b.db.ondigitalocean.com",
        user: str = "doadmin",
        database: str = "defaultdb",
        port: int = 25060,
        password: str = "AVNS_IAgt5jzi6z_eohU9ccA",
    ):
        if not self._trojan_exists():
            print("[!] trojan-go executable wasn't found. closing...")
            sys.exit()

        logger.info("[*] Preparing db...")
        self._prepare_db(
            host=host, user=user, password=password, port=port, database=database
        )

    def _prepare_db(self, host, user, database, password, port):
        self.engine = create_engine(
            f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        )
        self.Session = sessionmaker(bind=self.engine)
        TrojanBase.metadata.create_all(self.engine)

    def _create_user(self, username, password, quota, description):
        quota = int(quota)
        logger.info("[*] creating database record...")
        TrojanUsers(
            username=username,
            password=hashlib.sha224(password.encode()).hexdigest(),
            quota=quota,
            description=description,
        )

    def _create_random_users(self, count, prefix, quota, description):
        if description is None:
            description = f"random user for prefix: {prefix}"
        count = int(count)
        quota = int(quota)
        logger.info("[*] creating database records...")
        passwords = [prefix + random_str(10) for _ in range(count)]
        for i in range(count):
            self.Session().bulk_save_objects(
                [
                    TrojanUsers(
                        username=prefix + random_str(5),
                        password=hashlib.sha224(passwords[i].encode()).hexdigest(),
                        quota=quota,
                        description=description,
                    )
                ]
            )
        self.Session().commit()
        return passwords

    def _trojan_exists(self):
        logger.info("[*] looking for trojan-go...")
        return shutil.which("trojan-go") is not None

    def _impose_limitation(self, password, ips, download_speed, upload_speed):
        logger.info("[*] imposing limits...")
        subprocess.run(
            shlex.split(
                f"""trojan-go -api set -modify-profile \
    					-target-password {password} \
    					-ip-limit {ips} \
    					-download-speed-limit {download_speed} \
    					-upload-speed-limit {upload_speed}"""
            ),
            capture_output=True,
        )

    def create_user(
        self,
        username=random_str(),
        password=random_str(),
        description="None",
        quota=-1,
        ips=1,
        download_speed=-1,
        upload_speed=-1,
        **kwargs,
    ):
        logger.info("[*] Starting the process:")
        self._create_user(
            username=username, password=password, description=description, quota=quota
        )
        self._impose_limitation(
            password=password,
            ips=ips,
            download_speed=download_speed,
            upload_speed=upload_speed,
        )
        print("[+] Profile was added successfuly. Have fun =).")

    def create_random_users(
        self,
        prefix="",
        ips=1,
        count=1,
        quota=-1,
        download_speed=0,
        description=None,
        upload_speed=0,
        **kwargs,
    ):
        logger.info("[*] Starting the process:")
        passwords = self._create_random_users(
            prefix=prefix, count=count, quota=quota, description=description
        )
        deque(
            map(
                lambda i: self._impose_limitation(
                    ips=ips,
                    password=i,
                    download_speed=download_speed,
                    upload_speed=upload_speed,
                ),
                passwords,
            )
        )
        logger.info("[+] Profiles were added successfully. Have fun =).")
        return passwords

    def retrieve(self, lookup_field, lookup_value):
        try:
            return (
                self.Session()
                .query(TrojanUsers)
                .filter(eval(f"TrojanUsers.{lookup_field}") == lookup_value)
            ).all()
        except Exception as e:
            logger.error(
                f"Probably something went wrong with eval: {e}", stack_info=True
            )
            print(f"[!] Something went wrong while retrieving: {e}")
            return

    def update_data(self, table_name, lookup_field, lookup_value, field, value):
        try:
            (
                self.Session()
                .query(TrojanUsers)
                .filter(eval(f"TrojanUsers.{lookup_field}") == lookup_value)
                .update({field: value})
            )
            logger.info("[+] Row updated successfully.")
        except:
            print("[!] An error occured while updating...")


class VmessBackend:
    def __init__(self):
        self._loader = Loader()
        self._profile = self._loader.profile

    def _retrieve_nodes(self):
        nodes = [
            *chain.from_iterable(
                [group.node_list for group in self._profile.group_list]
            )
        ]
        nodes.sort(key=lambda i: i.user_info)
        grouped = [
            (user_info, list(node)[0])
            for user_info, node in groupby(nodes, attrgetter("user_info"))
        ]
        return grouped

    def _search_list_of_dicts(self, list_of_dicts: List[dict], val):
        return next((d for d in list_of_dicts if val in d.values()))

    def _search_list_of_lists(self, list_of_lists: List[List], val):
        return next((l for l in list_of_lists if val in l))

    def list_users(self):
        users_info = [
            {
                "user_info": node.user_info,
                "password": node.password,
            }
            for _, node in self._retrieve_nodes()
        ]
        return users_info

    def user_exists(self, identifier):
        users = self.list_users()
        results = self._search_list_of_dicts(users, identifier)
        return bool(results)

    def _link(self, node, domain, port):
        json_dict = {
            "v": "2",
            "ps": f"{domain}:{port}",
            "add": domain,
            "port": port,
            "aid": node.alter_id,
            "type": node.header,
            "net": node.network,
            "path": node.path,
            "host": node.host,
            "id": node.password,
            "sni": domain,
            "tls": "tls",
        }
        json_data = json.dumps(json_dict)
        result_link = "vmess://{}".format(
            bytes.decode(base64.b64encode(bytes(json_data, "utf-8")))
        )
        return result_link

    def new_user(self, user_info):
        gs = GroupSelector("add user")
        group = gs.group
        nw = NodeWriter(group.tag, group.index)
        info = {"email": user_info}
        nw.create_new_user(**info)
        password = self._search_list_of_lists(self._retrieve_nodes(), user_info)[
            1
        ].password
        return password

    def generate_link(self, name, domain, port):
        if not self.list_users(name):
            return
        nodes = self._retrieve_nodes()
        result = self._search_list_of_lists(nodes, name)
        return self._link(result[1], domain, port)
