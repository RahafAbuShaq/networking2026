#dealer
import socket
import struct
import threading
import time
import sys
import signal
import random

# Assignment constants
UDP_DISCOVERY_PORT = 13122
MAGIC_COOKIE = 0xabcddcba
MSG_OFFER = 0x2
MSG_REQUEST = 0x3
#--- for playing:
SUITS = ["H", "D", "C", "S"]  # 0..3 = HDCS
MSG_PAYLOAD = 0x4
# results
RES_NOT_OVER = 0x0
RES_TIE      = 0x1
RES_LOSS     = 0x2
RES_WIN      = 0x3

shutdown_flag = threading.Event()

#If shorter than 32 characters: pad with 0x00, If longer: truncate to 32 bytes

def fixed_name_32(name: str) -> bytes:
    b = name.encode("utf-8", errors="ignore")[:32]
    #ljust doning the padding with 32 auto:
    return b.ljust(32, b"\x00")
def parse_name_32(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
def recv_exact(conn: socket.socket, n: int) -> bytes:
    #Read exactly n bytes from a TCP socket 
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client disconnected while reading")
        buf += chunk
    return buf

def broadcast_offers(broadcast_socket: socket.socket, tcp_port: int, server_name: str):
    """
    Offer packet format (39 bytes):
      cookie(4) + type(1) + tcp_port(2) + server_name(32)
    """
    name_32 = fixed_name_32(server_name)
    #sending bytes not objects 
    print("DEBUG: broadcasting tcp_port =", tcp_port)

    offer = struct.pack("!IBH32s", MAGIC_COOKIE, MSG_OFFER, tcp_port, name_32)

    while not shutdown_flag.is_set():
        try:
            broadcast_socket.sendto(offer, ("<broadcast>", UDP_DISCOVERY_PORT))
            # print(f"Broadcasted offer: tcp_port={tcp_port}, name={server_name}")
            time.sleep(1.0)
        except Exception as e:
            print(f"Error broadcasting offer: {e}")
            

def handle_client(conn: socket.socket, addr):
    print(f"[TCP] client connected from {addr}")
    try:
        data = recv_exact(conn, 38)
        cookie, mtype, rounds, name_32 = struct.unpack("!IBB32s", data)

        if cookie != MAGIC_COOKIE or mtype != MSG_REQUEST:
            print("[TCP] invalid request (bad cookie/type)")
            return

        client_name = parse_name_32(name_32)
        print(f"[TCP] Request received: rounds={rounds}, client_name='{client_name}'")

        for i in range(rounds):
            play_one_round(conn)

    except Exception as e:
        print(f"[TCP] error: {e}")
    finally:
        conn.close()
        print(f"[TCP] closed {addr}")

def start_server():
    signal.signal(signal.SIGINT, lambda sig, frame: shutdown_flag.set())

    server_name = input("Server team name: ").strip() or "ServerTeam"

    # TCP socket just to reserve a port for now 
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(("0.0.0.0", 0))  # pick a free port
    #“Up to 5 clients can wait to be accepted if they connect at the same time.”
    tcp_socket.listen(5)
    tcp_port = tcp_socket.getsockname()[1]

    # UDP broadcast socket
    #socket.AF_INET-> adress IPV4, socket.SOCK_DGRAM -> datagram socket
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #how the socket behaves
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Print IP
    try:
        server_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        server_ip = "0.0.0.0"
    print(f"Server started, listening on IP {server_ip}")
    print(f"Broadcasting offers on UDP port {UDP_DISCOVERY_PORT}...")

    print(f"Server started, listening on IP {server_ip}, TCP port {tcp_port}")
    print(f"Broadcasting offers on UDP port {UDP_DISCOVERY_PORT}...")

    #start broadcasting:
    t = threading.Thread(
        target=broadcast_offers,
        args=(broadcast_socket, tcp_port, server_name),
        daemon=True
    )
    t.start()

    #accept clients (
    while not shutdown_flag.is_set():
        try:
            tcp_socket.settimeout(1.0)  # so we can check shutdown_flag periodically
            conn, addr = tcp_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue

    print("Shutting down...")
    broadcast_socket.close()
    tcp_socket.close()
    
#----------------------------------------------------------------------------------
#deck making:def make_deck():
def make_deck():
    deck = [(rank, suit) for suit in range(4) for rank in range(1, 14)]
    random.shuffle(deck)
    return deck

def card_value(rank: int) -> int:
    if rank == 1:
        return 11
    if 2 <= rank <= 10:
        return rank
    return 10

def hand_sum(hand):
    return sum(card_value(rank) for (rank, suit) in hand)

# Server payload: 9 bytes
def pack_payload_server(result: int, rank: int, suit: int) -> bytes:
    # cookie(4) + type(1) + result(1) + rank(2) + suit(1)
    return struct.pack("!IBBHB", MAGIC_COOKIE, MSG_PAYLOAD, result, rank, suit)

# Client payload: 10 bytes -> the client must say hit/stand
def recv_client_decision(conn: socket.socket) -> str:
    data = recv_exact(conn, 10)
    cookie, mtype, decision = struct.unpack("!IB5s", data)
    if cookie != MAGIC_COOKIE or mtype != MSG_PAYLOAD:
        raise ValueError("bad client payload cookie/type")
    return decision.decode("ascii")

def play_one_round(conn: socket.socket):
    deck = make_deck()
    player = [deck.pop(), deck.pop()]
    dealer = [deck.pop(), deck.pop()]

    # Send 2 player cards (not over)
    for (rank, suit) in player:
        conn.sendall(pack_payload_server(RES_NOT_OVER, rank, suit))

    # Send dealer's first card (not over)
    conn.sendall(pack_payload_server(RES_NOT_OVER, dealer[0][0], dealer[0][1]))

    # Player turn
    while True:
        p_sum = hand_sum(player)
        if p_sum > 21:
            # player busts -> final result immediately (send dealer hidden card as final message)
            conn.sendall(pack_payload_server(RES_LOSS, dealer[1][0], dealer[1][1]))
            return

        decision = recv_client_decision(conn)  # "Hittt" or "Stand"
        if decision == "Stand":
            break
        if decision != "Hittt":
            # treat invalid as Stand
            break

        # Hit: deal one card
        card = deck.pop()
        player.append(card)
        # still not over (result 0x0)
        conn.sendall(pack_payload_server(RES_NOT_OVER, card[0], card[1]))

    # Reveal dealer hidden card first
    conn.sendall(pack_payload_server(RES_NOT_OVER, dealer[1][0], dealer[1][1]))

    # Dealer hits until >= 17
    while hand_sum(dealer) < 17:
        card = deck.pop()
        dealer.append(card)
        conn.sendall(pack_payload_server(RES_NOT_OVER, card[0], card[1]))

    # Decide winner
    p = hand_sum(player)
    d = hand_sum(dealer)

    if d > 21:
        result = RES_WIN
    elif p > d:
        result = RES_WIN
    elif p < d:
        result = RES_LOSS
    else:
        result = RES_TIE

    # Send final result (include dealer last card)
    last_rank, last_suit = dealer[-1]
    conn.sendall(pack_payload_server(result, last_rank, last_suit))
    
    
#----------------------------------------------------------------------------------------
if __name__ == "__main__":
    start_server()
