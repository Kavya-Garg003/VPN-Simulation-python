import hashlib

def generate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

def verify_hash(message, received_hash):
    calculated_hash = hashlib.sha256(message.encode()).hexdigest()
    return calculated_hash == received_hash