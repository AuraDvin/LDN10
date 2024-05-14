#!/bin/python3
import signal
from datetime import datetime
import json
import ssl

signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading


IP = "localhost"
PORT = 1235
CERTIFIKATI = "./certificates/"

ip_family = socket.AF_INET
HEADER_LENGTH = 2
MAX_LOGIN_LEN = 14


def setup_SSL_context():
    # uporabi samo TLS, ne SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # certifikat je obvezen
    context.verify_mode = ssl.CERT_REQUIRED
    # nalozi svoje certifikate
    context.load_cert_chain(
        certfile=CERTIFIKATI + "server.crt", keyfile=CERTIFIKATI + "privateServer.key"
    )
    # nalozi certifikate CAjev, ki jim zaupas
    # (samopodp. cert. = svoja CA!)
    context.load_verify_locations(CERTIFIKATI + "clients.pem")
    # nastavi SSL CipherSuites (nacin kriptiranja)
    context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    return context


def receive_fixed_length_msg(sock, msglen):
    message = b""
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b"":
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(
        sock, HEADER_LENGTH
    )  # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    message_length = struct.unpack("!H", header)[0]  # pretvori dolzino sporocila v int

    message = None
    if message_length > 0:  # ce je vse OK
        message = receive_fixed_length_msg(sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode(
        "utf-8"
    )  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = (
        header + encoded_message
    )  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    sock.sendall(message)


def send_from_user(sock_to, message, is_broadcast=False):
    global clients, users
    msg_prefix = "FROM: " + users[client_addr] + datetime.now().strftime("@%H-%M ")
    message = msg_prefix + message
    if is_broadcast:
        for client in clients:
            send_message(client[0], message)
        return
    send_message(sock_to, message)


def broadcast_message(from_addr, message, is_system, time):
    global clients, users
    for client in clients:
        dict_msg = dict(message=message)
        dict_msg["user"] = "System" if is_system else users[from_addr]
        dict_msg["time"] = time
        send_message(client[0], json.dumps(dict_msg))


# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock, client_addr):
    global clients

    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[system] we now have " + str(len(clients)) + " clients")

    if client_addr not in users:
        users[client_addr] = "user_" + str(len(clients) - 1)
        print(f"No username found, you're {users[client_addr]} now :D")

    try:
        while True:  # neskoncna zanka
            msg_received = json.loads(receive_message(client_sock))
            dont_broadcast = False

            if not msg_received:  # ce obstaja sporocilo
                break

            time = msg_received["time"]
            msg_received = msg_received["message"]
            # user doesn't matter here because we have the IP and port

            if msg_received.startswith("/"):
                dont_broadcast = not handle_command(
                    msg_received, time, client_sock, client_addr
                )

            print(
                time
                + " ["
                + users[client_addr]
                + ", "
                + client_addr[0]
                + ":"
                + str(client_addr[1])
                + "] : "
                + msg_received
            )

            if dont_broadcast:
                continue

            # send_from_user(client_sock, None, msg_received, True)
            broadcast_message(client_addr, msg_received, False, time)

    except ConnectionResetError:
        print(users[client_addr] + " is gone")
        del users[client_addr]
        pass

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove((client_sock, client_addr))

    print(
        datetime.now().strftime("@%H:%M ")
        + "[system] we now have "
        + str(len(clients))
        + " clients"
    )
    client_sock.close()


def handle_command(message, time, client_sock, client_addr):
    """
    Handle the message that starts with a "/" -> command
    :return: 0 for a private message (server to 1 client), 1 for public message
    """
    global users

    command = message.split(" ")[0][1:]
    args = message.split(" ")[1:]

    match command:
        case "nick":
            if not len(args):

                send_message(
                    client_sock,
                    json.dumps(
                        dict(
                            message="""That's a stupid username! (empty string)
                Try /nick {username}
                Warning: dont use spaces, max length is 10 characters """,
                            user="System",
                            time=time,
                        )
                    ),
                )
                return 0

            new_nick = "".join(args)[:MAX_LOGIN_LEN]

            if new_nick in users.values():
                send_message(
                    client_sock,
                    json.dumps(
                        dict(
                            message="This username is taken! (try a different one)",
                            user="System",
                            time=time,
                        )
                    ),
                )
                return 0

            if len(new_nick) < 3:
                send_message(
                    client_sock,
                    json.dumps(
                        dict(
                            message="Your new nick is TOO SHORT, minimum 3 characters :)",
                            user="System",
                            time=time,
                        )
                    ),
                )
                return 0

            users[client_addr] = new_nick
            send_message(
                client_sock,
                json.dumps(
                    dict(
                        message=f"_privately_ Nickname changed to {users[client_addr]}",
                        user="System",
                        time=time,
                    )
                ),
            )
            return 0
        # case _:
        #     return 1
        case "w" | "msg" | "whisper" | "dm" | "pm":
            if len(args) < 2:
                send_message(
                    client_sock,
                    json.dumps(
                        dict(
                            message="""Who am I sending to and what?
                /w <username> <msg>
                Other names for whisper are whisper, msg and w""",
                            user="System",
                            time=time,
                        )
                    ),
                )
                return 0
            other_user = args[0][:MAX_LOGIN_LEN]
            try:
                other_user_addr = list(users.keys())[
                    list(users.values()).index(other_user)
                ]
                other_client_sock = [
                    client[0] for client in clients if client[1] == other_user_addr
                ][0] or None
                if client_sock is not None:
                    send_message(
                        other_client_sock,
                        json.dumps(
                            dict(
                                message="__privately__ " + " ".join(args[1:]),
                                user=users[client_addr],
                                time=time,
                            )
                        ),
                    )
                    # "@" + time + "FROM:" + users[client_addr] + ";_privately_ " + " ".join(args[1:])
                return 0
            except Exception:
                send_message(
                    client_sock,
                    json.dumps(
                        dict(
                            message=f"""Couldn't find that user {other_user}
                Check the spelling or contact administrator for support
                (They may be offline)
                """,
                            user="System",
                            time=time,
                        )
                    ),
                )
                return 0
        case _:
            send_message(
                client_sock,
                json.dumps(
                    dict(
                        message=f"""Unknown command! /{command}
            known commands are: whisper, nick
            """,
                        user="System",
                        time=time,
                    )
                ),
            )
            return 1


# kreiraj socket
# server_socket = socket.socket(ip_family, socket.SOCK_STREAM)
server_addr = (IP, PORT)
my_ssl_ctx = setup_SSL_context()
server_socket = my_ssl_ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
)
server_socket.bind(server_addr)
server_socket.listen(1)


# cakaj na nove odjemalce
print("[system] listening ...")
clients = set()
users = dict()
clients_lock = threading.Lock()

while True:
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        client_sock, client_addr = server_socket.accept()

        cert = client_sock.getpeercert()
        for sub in cert["subject"]:
            for key, value in sub:
                # v commonName je ime uporabnika
                if key == "commonName":
                    user = value

        print("Connected by:", client_addr, "User in cert: ", user)

        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr))
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()
