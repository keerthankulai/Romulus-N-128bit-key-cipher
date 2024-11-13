import socket
import os
import binascii
import time  # For generating time-based randomness

KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
BLOCK_SIZE = 16


def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def tweakable_block_cipher(key, nonce, input_data):
    output_data = bytearray(len(input_data))
    for i in range(len(input_data)):
        output_data[i] = input_data[i] ^ key[i % KEY_SIZE] ^ nonce[i % NONCE_SIZE]
    return bytes(output_data)


def generate_tag(key, nonce, associated_data, ciphertext):
    combined_data = pad(associated_data + ciphertext, BLOCK_SIZE)
    tag = tweakable_block_cipher(key, nonce, combined_data)
    return tag[:TAG_SIZE]


def romulus_encrypt(key, nonce, associated_data, plaintext):
    padded_plaintext = pad(plaintext, BLOCK_SIZE)
    ciphertext = tweakable_block_cipher(key, nonce, padded_plaintext)
    tag = generate_tag(key, nonce, associated_data, ciphertext)
    return ciphertext, tag


def generate_random_key(size):
    return os.urandom(size)


def generate_random_nonce(size):
    return os.urandom(size)


def main():
    try:
        intruder_host = 'localhost'  # Intruder's IP
        intruder_port = 12345



        # Generate a random key for encryption (only once)
        key = generate_random_key(KEY_SIZE)
        print("Client-Side")
        while True:
            # Generate a new random nonce for each session
            nonce = generate_random_nonce(NONCE_SIZE)
            # Get associated data and message input from user
            associated_data_input = input("Enter Associated Data: ").encode()

            # Add randomness (timestamp) to the associated data to ensure it's unique every time
            random_salt = os.urandom(8)  # Add randomness using random 8 bytes or use timestamp
            associated_data = associated_data_input + random_salt

            # Get plaintext message input from user

            plaintext = input("Enter the Message: ").encode()

            # Encrypt data
            ciphertext, tag = romulus_encrypt(key, nonce, associated_data, plaintext)

            # Data to send
            data = {
                'key': binascii.hexlify(key).decode(),
                'nonce': binascii.hexlify(nonce).decode(),
                'associated_data': binascii.hexlify(associated_data).decode(),
                'ciphertext': binascii.hexlify(ciphertext).decode(),
                'tag': binascii.hexlify(tag).decode()
            }

            # Connect to the intruder and send data
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Connecting to server......")
                s.connect((intruder_host, intruder_port))
                s.sendall(str(data).encode())
                print("Data sent successfully.")

            # Ask if the user wants to send another message
            continue_sending = input("Do you want to send another message? (y/n): ")
            if continue_sending.lower() != 'y':
                break

    except Exception as e:
        print(f"An error occurred in the client: {e}")


if __name__ == "__main__":
    main()
