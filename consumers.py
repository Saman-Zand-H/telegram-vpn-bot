#!/usr/bin/python3.10
##### For usage on other servers.
import pika, json, os
from v2ray_util.util_core.writer import NodeWriter
from v2ray_util.util_core.selector import GroupSelector
from v2ray_util.util_core.loader import Loader


class CustomWriter(NodeWriter):
    def create_new_user(self, kw):
        if self.part_json['protocol'] == 'vmess':
            email_info = ""
            user = {
                "alterId": 0,
                "id": "ae1bc6ce-e575-4ee2-85f1-350a0aa506cb"
            }
            if "email" in kw and kw["email"] != "":
                user.update({"email":kw["email"]})
                email_info = ", email: " + kw["email"]
            password = kw["password"]
            user["id"]=str(password)
            self.part_json["settings"]["clients"].append(user)
            print("{0} uuid: {1}, alterId: 32{2}".format("add user success!", password, email_info))
        self.save()


pika_credentials = pika.PlainCredentials(username="djsadmin",
                                         password=os.environ.get("RABBIT_PASSWORD"),
                                         erase_on_connect=True)
connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=os.environ.get("SERVER_IP"),
        port=5672,
        virtual_host="tel_broker",
        credentials=pika_credentials
    ))
channel = connection.channel()

def vmess_consumer(ch, method, properties, body):
    try:
        body = json.loads(body)
        match body.get("type"):
            case "new":
                user_info = body["user_info"]
                password = body["password"]
                gs = GroupSelector("add user")
                group = gs.group
                nw = CustomWriter(group.tag, group.index)
                try:
                    nw.create_new_user(kw={"email": user_info, "password": password})
                    print("[+] User created.")
                except:
                    ...
                
            case "delete":
                profile = Loader().profile
                user_number = body["user_number"]
                group = profile.group_list[0]
                client_index = None
                for index, node in enumerate(group.node_list):
                    if node.user_number == user_number:
                        client_index = index
                        break
                nw = NodeWriter()
                if client_index is not None:
                    try:
                        nw.del_user(group, client_index)
                        print("[+] User deleted.")
                    except:
                        ...
                
    except json.JSONDecodeError:
        ...


if __name__ == "__main__":
    channel.basic_consume("vmess_queue",
                          vmess_consumer,
                          True)
    print("[+] Cosumer is about to set up...")
    channel.start_consuming()
