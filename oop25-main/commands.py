import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class Command:
    def __init__(self, command_type, data):
        self.command_type = command_type
        self.data = data

    def to_json(self):
        return json.dumps({
            "command_type": self.command_type,
            "data": self.data
        }).encode()

    @staticmethod
    def from_json(json_bytes):
        command_dict = json.loads(json_bytes.decode())
        cmd_type = command_dict["command_type"]
        cmd_data = command_dict["data"]
        if cmd_type in COMMAND_TYPES:
            if cmd_type == "MOVE":
                return MoveCommand(cmd_data["angle"])
            return COMMAND_TYPES[cmd_type]()  # For PICKUP, PLACE
        return Command(cmd_type, cmd_data)

    def encrypt(self, public_key):
        encrypted = public_key.encrypt(
            self.to_json(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    @staticmethod
    def decrypt(encrypted_command, private_key):
        decrypted = private_key.decrypt(
            encrypted_command,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return Command.from_json(decrypted)

    def __repr__(self):
        return f"<Command type={self.command_type}, data={self.data}>"

# === Subclasses for specific commands ===
class MoveCommand(Command):
    def __init__(self, angle):
        super().__init__("MOVE", {"angle": angle})

class PickUpCommand(Command):
    def __init__(self):
        super().__init__("PICKUP", {})

class PlaceCommand(Command):
    def __init__(self):
        super().__init__("PLACE", {})

# === Command type mapping for restoration ===
COMMAND_TYPES = {
    "MOVE": MoveCommand,
    "PICKUP": PickUpCommand,
    "PLACE": PlaceCommand
}
