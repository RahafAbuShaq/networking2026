#player
import socket
import struct
import threading
import time
import sys

import socket
import struct

UDP_DISCOVERY_PORT = 13122
MAGIC_COOKIE = 0xabcddcba
MSG_OFFER = 0x2
MSG_REQUEST = 0x3
MSG_PAYLOAD = 0x4

#--- for playing:
SUITS = ["H", "D", "C", "S"]  # 0..3 = HDCS
RANKS = {1: "A", 11: "J", 12: "Q", 13: "K"}

RES_NOT_OVER = 0x0
RES_TIE      = 0x1
RES_LOSS     = 0x2
RES_WIN      = 0x3


def parse_name_32(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

def fixed_name_32(name: str) -> bytes:
    b = name.encode("utf-8", errors="ignore")[:32]
    return b.ljust(32, b"\x00")

def pack_request(rounds: int, client_name: str) -> bytes:
    # Request format: cookie(4) + type(1) + rounds(1) + name(32) = 38 bytes
    if not (1 <= rounds <= 255):
        raise ValueError("rounds must be 1..255")
    return struct.pack("!IBB32s", MAGIC_COOKIE, MSG_REQUEST, rounds, fixed_name_32(client_name))

def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server disconnected")
        buf += chunk
    return buf

def main():
    client_name = input("Client team name: ").strip() 
    rounds = int(input("How many rounds? ").strip() )
    #udp process:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #attach this socket to a local IP + port, so it can receive packets
    s.bind(("", UDP_DISCOVERY_PORT))
    print(f"Client started, listening for offer requests...")

    while True:
        #blocks until a UDP packet arrives and returns the packet bytes 
        # plus the sender’s (IP, port), reading up to 2048 bytes.
        data, (ip, port) = s.recvfrom(2048)
        # Offer must be exactly 39 bytes
        if len(data) != 39:
            continue
        try:
            cookie, mtype, tcp_port, name_32 = struct.unpack("!IBH32s", data)
        except struct.error:
            continue

        if cookie != MAGIC_COOKIE or mtype != MSG_OFFER:
            continue
        print(f"received offer from {ip}")
        
        #starting TCP connection:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("DEBUG connecting to:", ip, tcp_port)

        tcp.connect((ip, tcp_port))
        print("Connected via TCP")
        #sending request message to the server, that the clint wants to play with a spiciic number of rounds
        req = pack_request(rounds, client_name)
        tcp.sendall(req)
        print(f"Sent request: rounds={rounds}, name='{client_name}'")

        #start palying--------
        
        
        
        wins = losses = ties = 0

        # Play rounds
        for round_i in range(1, rounds + 1):
            print(f"\n=== Round {round_i} ===")

            player_hand = []
            dealer_visible = []
            # Protocol from our server: sends 2 player cards, then 1 dealer card initially (all RES_NOT_OVER)
            for _ in range(3):
                result, rank, suit = unpack_server_payload(recv_exact(tcp, 9))
                if result != RES_NOT_OVER:
                    # shouldn't happen during initial dealing
                    pass
                if len(player_hand) < 2:
                    player_hand.append((rank, suit))
                    print("You got:", card_str(rank, suit))
                else:
                    dealer_visible.append((rank, suit))
                    print("Dealer shows:", card_str(rank, suit))

            # Player decisions loop
            while True:
                p_sum = sum(card_value(r) for (r, _) in player_hand)
                print("Your sum =", p_sum)

                if p_sum > 21:
                    print("You bust!")
                    break

                # Ask user
                choice = input("Hit or Stand? ").strip().lower()
                decision = "Hittt" if choice.startswith("h") else "Stand"
                tcp.sendall(pack_decision(decision))

                if decision == "Stand":
                    break

                # If Hit: server will send one card (RES_NOT_OVER) OR could send final immediately in some cases
                result, rank, suit = unpack_server_payload(recv_exact(tcp, 9))
                player_hand.append((rank, suit))
                print("You got:", card_str(rank, suit))

                # If server ended the round here (rare in our flow), handle it:
                if result != RES_NOT_OVER:
                    break

            # Now wait until server sends final result payload (it may send several NOT_OVER first)
            final_result = None
            while final_result is None:
                result, rank, suit = unpack_server_payload(recv_exact(tcp, 9))
                if result == RES_NOT_OVER:
                    print("Card:", card_str(rank, suit))
                else:
                    final_result = result
                    print("Final card:", card_str(rank, suit))

            if final_result == RES_WIN:
                print("✅ You WIN!")
                wins += 1
            elif final_result == RES_LOSS:
                print("❌ You LOSE!")
                losses += 1
            else:
                print("🤝 TIE!")
                ties += 1
        print(f"\n=== Summary ===\nWins: {wins}, Losses: {losses}, Ties: {ties}")
        tcp.close()
        return
        
#-------------------------------------------------
#play the game:
def pack_decision(decision5: str) -> bytes:
    # Client payload: 10 bytes
    # cookie(4) + type(1) + decision(5)
    if decision5 not in ("Hittt", "Stand"):
        raise ValueError("decision must be 'Hittt' or 'Stand'")
    return struct.pack("!IB5s", MAGIC_COOKIE, MSG_PAYLOAD, decision5.encode("ascii"))

def unpack_server_payload(data9: bytes):
    # Server payload: 9 bytes
    # cookie(4) + type(1) + result(1) + rank(2) + suit(1)
    cookie, mtype, result, rank, suit = struct.unpack("!IBBHB", data9)
    if cookie != MAGIC_COOKIE or mtype != MSG_PAYLOAD:
        raise ValueError("bad server payload cookie/type")
    return result, rank, suit

def card_value(rank: int) -> int:
    if rank == 1:
        return 11
    if 2 <= rank <= 10:
        return rank
    return 10

def card_str(rank: int, suit: int) -> str:
    r = RANKS.get(rank, str(rank))
    s = SUITS[suit] if 0 <= suit < 4 else "?"
    return f"{r}{s}"



#-------------------------------------------------

if __name__ == "__main__":
    main()
