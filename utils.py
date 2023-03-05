import random, string
from codecs import encode
from logging import getLogger
import sys, hashlib, shutil, subprocess, shlex
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from collections import deque
from models import TrojanUsers, TrojanBase


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


class TrojanDatabase:
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
            f"mysql+mysqlclient://{user}:{password}@{host}:{port}/{database}")
        self.Session = sessionmaker(bind=self.engine)
        TrojanBase.metadata.create_all(self.engine)

    def _create_user(self, username, password, quota, description):
        quota = int(quota)
        logger.info("[*] creating database record...")
        TrojanUsers(
            username=username,
            password=hashlib.sha224(password.encode()).hexdigest(),
            quota=quota,
            description=description
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
                        username=prefix+random_str(5),
                        password=hashlib.sha224(passwords[i].encode()).hexdigest(),
                        quota=quota,
                        description=description
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
                .filter(eval(f"TrojanUsers.{lookup_field}")==lookup_value)
            ).all()
        except Exception as e:
            logger.error(f"Probably something went wrong with eval: {e}",
                         stack_info=True)
            print(f"[!] Something went wrong while retrieving: {e}")
            return
        
    def update_data(self, table_name, lookup_field, lookup_value, field, value):
        try:
            (
                self.Session()
                .query(TrojanUsers)
                .filter(eval(f"TrojanUsers.{lookup_field}")==lookup_value)
                .update({field: value})
            )
            logger.info("[+] Row updated successfully.")
        except:
            print("[!] An error occured while updating...")
