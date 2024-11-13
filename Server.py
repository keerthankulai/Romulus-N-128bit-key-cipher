import socket
import binascii
from ast import literal_eval

KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16
BLOCK_SIZE = 16


def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def unpad(data, block_size):
    padding_length = data[-1]
    if padding_length > block_size:
        raise ValueError("Invalid padding.")
    return data[:-padding_length]


def tweakable_block_cipher(key, nonce, input_data):
    output_data = bytearray(len(input_data))
    for i in range(len(input_data)):
        output_data[i] = input_data[i] ^ key[i % KEY_SIZE] ^ nonce[i % NONCE_SIZE]
    return bytes(output_data)


def generate_tag(key, nonce, associated_data, ciphertext):
    combined_data = pad(associated_data + ciphertext, BLOCK_SIZE)
    tag = tweakable_block_cipher(key, nonce, combined_data)
    return tag[:TAG_SIZE]


def romulus_decrypt(key, nonce, associated_data, ciphertext, tag):
    # Perform the decryption on the modified ciphertext
    padded_plaintext = tweakable_block_cipher(key, nonce, ciphertext)

    # Recompute the tag based on the ciphertext and associated data
    computed_tag = generate_tag(key, nonce, associated_data, ciphertext)

    # Check if the computed tag matches the received tag
    if computed_tag != tag:
        return False, b""

    # If the tag matches, attempt to unpad the decrypted data
    try:
        plaintext = unpad(padded_plaintext, BLOCK_SIZE)
    except ValueError:
        # Handle padding errors (possibly due to tampered ciphertext)
        return False, b""

    return True, plaintext


def main():
    try:
        server_host = 'localhost'
        server_port = 12346

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((server_host, server_port))
            s.listen()
            print("Server is listening for connections...")

            while True:
                conn, addr = s.accept()  # Accept new client connection
                with conn:
                    print(f"Connection successful from {addr}.")

                    while True:  # Continue receiving and processing multiple messages
                        data = conn.recv(1024).decode()  # Receive the message from the intruder

                        if not data:  # Break if no data is received (client disconnects)
                            break

                        print("Data received from Intruder:", data)

                        try:
                            # Convert received data from string to dictionary
                            data_dict = literal_eval(data)

                            key = binascii.unhexlify(data_dict['key'])
                            nonce = binascii.unhexlify(data_dict['nonce'])
                            associated_data = binascii.unhexlify(data_dict['associated_data'])
                            ciphertext = binascii.unhexlify(data_dict['ciphertext'])
                            tag = binascii.unhexlify(data_dict['tag'])

                            # Debugging the decrypted data
                            print(f"Key (hex): {data_dict['key']}")
                            print(f"Nonce (hex): {data_dict['nonce']}")
                            print(f"Associated Data (hex): {data_dict['associated_data']}")
                            print(f"Ciphertext (hex): {data_dict['ciphertext']}")
                            print(f"Tag (hex): {data_dict['tag']}")

                            # Call the decryption function to check tag integrity
                            result, decrypted = romulus_decrypt(key, nonce, associated_data, ciphertext, tag)

                            if result:
                                print("Decrypted text:", decrypted.decode())
                                print("Tag verification succeeded.")
                            else:
                                print("Tag verification failed: Data may have been tampered.")
                        except Exception as e:
                            print(f"Error processing data: {e}")
                print("Waiting for a new connection...")  # Ready for next intruder connection
    except Exception as e:
        print(f"An error occurred in the server: {e}")


if __name__ == "__main__":

    main()
