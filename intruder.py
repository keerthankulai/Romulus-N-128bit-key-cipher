import socket
from ast import literal_eval
import binascii

def main():
    try:
        intruder_host = 'localhost'
        intruder_port = 12345
        server_host = 'localhost'
        server_port = 12346

        # Create and bind the intruder socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as intruder_socket:
            intruder_socket.bind((intruder_host, intruder_port))
            intruder_socket.listen()
            print("Intruder is listening for connections...")

            while True:
                conn, addr = intruder_socket.accept()  # Accept incoming connection
                with conn:
                    print(f"Connected by client at {addr}")

                    while True:  # Keep listening for multiple messages
                        data = b""
                        while True:
                            chunk = conn.recv(1024)  # Receive message in chunks
                            data += chunk  # Append the received chunk
                            if len(chunk) < 1024:  # If the chunk is smaller than the buffer size, it's the last part
                                break

                        if not data:  # If no data is received, break the loop
                            break

                        # Decode the entire received data
                        data = data.decode()

                        try:
                            # Convert received data from string to dictionary
                            data_dict = literal_eval(data)
                            print("Received data:", data_dict)

                            # Convert hex values to bytes
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

                            # Optionally modify the data here, excluding the tag
                            modify = input("Would you like to modify the message? (y/n): ")
                            if modify.lower() == 'y':
                                new_key = input("Enter key value (hex): ").strip()
                                data_dict['key'] = new_key

                                new_nonce = input("Enter nonce value (hex): ").strip()
                                data_dict['nonce'] = new_nonce

                                new_associated_data = input("Enter associated data value(hex): ").strip()
                                data_dict['associated_data'] = new_associated_data

                                new_plaintext = input("Enter ciphertext value (hex): ").strip()
                                data_dict['ciphertext'] = new_plaintext

                            # Extract the tag from the original message and keep it unchanged
                            tag = data_dict['tag']

                            # Forward modified or original data (with original tag) to the server
                            data_dict['tag'] = tag  # Ensure the original tag is forwarded
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                                server_socket.connect((server_host, server_port))
                                server_socket.sendall(str(data_dict).encode())
                                print("Data forwarded to server.")

                        except binascii.Error as e:
                            print(f"Error with hex data conversion: {e}")
                        except ValueError as e:
                            print(f"Error with padding/unpadding or cryptographic operation: {e}")
                        except Exception as e:
                            print(f"Unexpected error: {e}")

                print("Waiting for a new client connection...")  # Ready for new connections
    except Exception as e:
        print(f"An error occurred in the intruder: {e}")

if __name__ == "__main__":

    main()
