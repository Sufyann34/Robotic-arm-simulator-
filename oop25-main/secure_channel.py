from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class SecureChannel:
    def __init__(self, receiver_private_key, receiver_public_key):
        self.receiver_private_key = receiver_private_key
        self.receiver_public_key = receiver_public_key

    def send(self, data: bytes) -> bytes:
        # Encrypt receiver public key
        return self.receiver_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def receive(self, encrypted_data: bytes) -> bytes:
        # Decrypt receiversprivate key
        return self.receiver_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
