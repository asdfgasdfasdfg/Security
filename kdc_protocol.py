from cryptography.fernet import Fernet
import time
import json

class KDC:
    def __init__(self):
        self.keys = {
            "A": Fernet.generate_key(),
            "B": Fernet.generate_key()
        }

    def generate_session_key(self):
        return Fernet.generate_key()

    def handle_request(self, encrypted_request, sender):
        decrypted_request = Fernet(self.keys[sender]).decrypt(encrypted_request).decode()
        request = json.loads(decrypted_request)
        receiver = request["receiver"]
        print(f"KDC: {sender} requested to communicate with {receiver}.")

        session_key = self.generate_session_key()
        encrypted_for_sender = Fernet(self.keys[sender]).encrypt(
            json.dumps({"R1": session_key.decode(), "receiver": receiver, "valid_until": time.time() + 600}).encode()
        )
        encrypted_for_receiver = Fernet(self.keys[receiver]).encrypt(
            json.dumps({"R1": session_key.decode(), "sender": sender, "valid_until": time.time() + 600}).encode()
        )
        print(f"KDC: Session key (R1) generated and encrypted for {sender} and {receiver}.")
        return encrypted_for_sender, encrypted_for_receiver


class Participant:
    def __init__(self, name, key):
        self.name = name
        self.key = Fernet(key)
        self.session_key = None

    def send_request(self, kdc, receiver):
        request = {
            "receiver": receiver,
            "timestamp": time.time()
        }
        encrypted_request = self.key.encrypt(json.dumps(request).encode())
        print(f"{self.name}: Request sent to KDC to communicate with {receiver}.")
        return kdc.handle_request(encrypted_request, self.name)

    def receive_session_key(self, encrypted_key):
        decrypted_key = json.loads(self.key.decrypt(encrypted_key).decode())
        self.session_key = Fernet(decrypted_key["R1"].encode())
        print(f"{self.name}: Session key (R1) received and decrypted.")

    def send_message(self, message, receiver):
        encrypted_message = self.session_key.encrypt(message.encode())
        print(f"{self.name} → {receiver.name}: {encrypted_message}")
        return encrypted_message

    def receive_message(self, encrypted_message):
        decrypted_message = self.session_key.decrypt(encrypted_message).decode()
        print(f"{self.name}: Message received: {decrypted_message}")


if __name__ == "__main__":
    kdc = KDC()
    A = Participant("A", kdc.keys["A"])
    B = Participant("B", kdc.keys["B"])

    encrypted_for_A, encrypted_for_B = A.send_request(kdc, "B")
    A.receive_session_key(encrypted_for_A)
    B.receive_session_key(encrypted_for_B)

    encrypted_message = A.send_message("Hello, B!", B)
    B.receive_message(encrypted_message)

"""
실행 결과:
A: Request sent to KDC to communicate with B.
KDC: A requested to communicate with B.
KDC: Session key (R1) generated and encrypted for A and B.
A: Session key (R1) received and decrypted.
B: Session key (R1) received and decrypted.
A → B: b'gAAAAABnSZ29yLSR3ljMERdpi8WFe5syODU6U8idnsiXwM4D38kBUZ9qAMTPM6WC9wzS20SGSQYtCo3YE7uNv8Cl_8CXgafm1A=='
B: Message received: Hello, B!
"""
