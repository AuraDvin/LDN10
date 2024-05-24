import socket
import struct
import sys
import threading
import json
import ssl
from datetime import datetime

PORT = 1235
SERVER_IP = "localhost"
ip_family = socket.AF_INET
HEADER_LENGTH = 2

CERTIFIKATI = "certificates/"
IME = "janez"
private_key = "privateJanez"

def init():
    global IME, private_key
    choose_user = [
        ["janez.crt", "privateJanez.key"],
        ["timo.crt", "privateTimo.key"],
        ["micka.crt", "privateMicka.key"]
    ]
    for i, k in enumerate(choose_user):
        print(f"[{i}] {k[0][:k[0].find('.')]}")
    choice = input()
    try:
        decision = int(choice)
        IME, private_key = choose_user[decision]
    except Exception as e:
        decision = 0
        IME, private_key = choose_user[decision]

def setup_SSL_context():
    # uporabi samo TLS, ne SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # certifikat je obvezen
    context.verify_mode = ssl.CERT_REQUIRED
    # nalozi svoje certifikate
    context.load_cert_chain(
        certfile=CERTIFIKATI + IME,
        keyfile=CERTIFIKATI + private_key
    )
    # nalozi certifikate CAjev (samopodp. cert.= svoja CA!)
    context.load_verify_locations(CERTIFIKATI + "server.crt")
    # nastavi SSL CipherSuites (nacin kriptiranja)
    context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    return context

def receive_fixed_length_msg(user_sock, msglen):
    message = b""
    while len(message) < msglen:
        chunk = user_sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b"":
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message

def receive_message(your_sock):
    # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    header = receive_fixed_length_msg(your_sock, HEADER_LENGTH)  # Throws fatal errror

    # pretvori dolzino sporocila v int
    message_length = struct.unpack("!H", header)[0]

    message = None
    if message_length > 0:  # ce je vse OK
        # print(f"Message recieved! message length: {message_length}\n")
        # print(struct.unpack("!H", header))
        message = receive_fixed_length_msg(
            your_sock, message_length
        )  # preberi sporocilo
        message = message.decode("utf-8")

    return json.loads(message)

def send_message(your_sock, message):
    # This is where I will try replacing the string with a json string
    current_time = datetime.now().strftime("@%H-%M ")

    mes_dict = dict(message=message)
    mes_dict["time"] = current_time
    mes_dict["user"] = ""
    # print(json.dumps(mes_dict))

    message = json.dumps(mes_dict)

    # message = current_time + message
    # message = datetime.now().strftime('%H-%M') + " " + message

    encoded_message = message.encode(
        "utf-8"
    )  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = (
            header + encoded_message
    )  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    your_sock.sendall(message)

# message_receiver funkcija tece v loceni niti
def message_receiver():
    global sock

    while True:
        msg_received = receive_message(sock)

        # msg_time = msg_received[1:msg_received.index("FROM:") - 1]
        # user_from = msg_received[msg_received.index("FROM:") + len("FROM:"):msg_received.find(";")]

        # msg_from = msg_time + " [" + user_from + "]: "
        # msg_actual = msg_received[msg_received.find(";") + 1:]

        # print("raw: ", end="")
        # print(msg_received)

        msg_from = msg_received["user"]
        msg_time = msg_received["time"]
        msg_actual = msg_received["message"]
        # print("actual: ", end="")
        # print(msg_actual)

        if len(msg_received) > 0:  # ce obstaja sporocilo
            print(msg_time + " <" + msg_from + ">: " + msg_actual)
            # print(msg_from + msg_actual)  # izpisi

# povezi se na streznik
print("[system] connecting to chat server ...")
init()
my_ssl_ctx = setup_SSL_context()
sock = my_ssl_ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((SERVER_IP, PORT))
print("[system] connected!")



# zazeni message_receiver funkcijo v loceni niti
thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

# počakaj, da uporabnik nekaj natipka in poslji na streznik
while True:
    try:
        msg_send = input()
        if not not len(msg_send):  # ne pošiljaj praznih sporočil
            send_message(sock, msg_send)
    except KeyboardInterrupt:
        sys.exit()
