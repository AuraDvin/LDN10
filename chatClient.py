#!/bin/python3
import socket
import struct
import sys
import threading
import json
from datetime import datetime

PORT = 1235
SERVER_IP = "localhost"
ip_family = socket.AF_INET
HEADER_LENGTH = 2

def receive_fixed_length_msg(user_sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = user_sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b'':
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
        message = receive_fixed_length_msg(your_sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return json.loads(message)

def send_message(your_sock, message):
 
    # This is where I will try replacing the string with a json string
    current_time = datetime.now().strftime('@%H-%M ')
    
    mes_dict = dict(message=message)
    mes_dict["time"] = current_time
    mes_dict["user"] = zacetni_nick
    print(json.dumps(mes_dict))

    message = json.dumps(mes_dict)

    # message = current_time + message
    # message = datetime.now().strftime('%H-%M') + " " + message

    encoded_message = message.encode("utf-8")  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
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

        msg_from = msg_received["user"]
        msg_time = msg_received["time"]
        msg_actual = msg_received["message"]


        if len(msg_received) > 0:  # ce obstaja sporocilo
            print(msg_time + " <" + msg_from + ">: " + msg_actual)
            # print(msg_from + msg_actual)  # izpisi

# povezi se na streznik
print("[system] connecting to chat server ...")
sock = socket.socket(ip_family, socket.SOCK_STREAM)
sock.connect((SERVER_IP, PORT))
print("[system] connected!")

zacetni_nick = input("Vpisi uporabnisko ime: ")
send_message(sock, "/nick " + zacetni_nick)  # serverju pošlje ime

# zazeni message_receiver funkcijo v loceni niti
thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

# počakaj, da uporabnik nekaj natipka in poslji na streznik
while True:
    try:
        msg_send = input()
        if not not len(msg_send):  # ne pošiljaj praznih sporočil
            
            mes_dict = dict(message=msg_send)
            mes_dict["time"] = datetime.now().strftime("%H-%M")
            mes_dict["user"] = zacetni_nick
            print(json.dumps(mes_dict))

            send_message(sock, msg_send)
    except KeyboardInterrupt:
        sys.exit()
