import base64

def main():
    try: 
        with open("data.txt", "r") as file:
            encoded_string = file.read()
        
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode("utf-8")
        print(f"Decoded string: {decoded_string}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
