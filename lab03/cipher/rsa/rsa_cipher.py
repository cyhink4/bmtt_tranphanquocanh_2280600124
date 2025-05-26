# rsa_cipher.py
import sys
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox

# Add the parent directory to the path to access ui module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from ui.rsa import Ui_MainWindow
import requests

class RSACipher:
    def __init__(self):
        self.keys_dir = os.path.join(os.path.dirname(__file__), 'keys')
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
        self.private_key_path = os.path.join(self.keys_dir, 'private_key.pem')
        self.public_key_path = os.path.join(self.keys_dir, 'public_key.pem')
        
    def generate_keys(self, key_size=2048):
        """Tạo cặp khóa RSA"""
        try:
            # Tạo private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Lấy public key từ private key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Lưu keys vào file
            with open(self.private_key_path, 'wb') as f:
                f.write(private_pem)
                
            with open(self.public_key_path, 'wb') as f:
                f.write(public_pem)
                
            return True, "Keys generated successfully"
        except Exception as e:
            return False, f"Error generating keys: {str(e)}"
    
    def load_private_key(self):
        """Tải private key từ file"""
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            raise Exception(f"Error loading private key: {str(e)}")
    
    def load_public_key(self):
        """Tải public key từ file"""
        try:
            with open(self.public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            raise Exception(f"Error loading public key: {str(e)}")
    
    def load_keys(self):
        """Load both private and public keys and return them"""
        try:
            private_key = self.load_private_key()
            public_key = self.load_public_key()
            return private_key, public_key
        except Exception as e:
            raise Exception(f"Error loading keys: {str(e)}")

    def encrypt(self, message, key=None, use_public_key=True):
        """Mã hóa message - updated to support both API and UI usage"""
        try:
            if key is not None:
                # API usage - key is provided directly
                if hasattr(key, 'encrypt'):
                    # It's a public key object
                    message_bytes = message.encode('utf-8')
                    ciphertext = key.encrypt(
                        message_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    return ciphertext
                else:
                    raise Exception("Invalid key provided for encryption")
            else:
                # UI usage - load key from file
                if use_public_key:
                    key = self.load_public_key()
                else:
                    key = self.load_private_key().public_key()
                    
                # Chuyển message thành bytes
                message_bytes = message.encode('utf-8')
                
                # Mã hóa
                ciphertext = key.encrypt(
                    message_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Encode base64 để dễ hiển thị (for UI)
                return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            raise Exception(f"Error encrypting: {str(e)}")
    
    def decrypt(self, ciphertext, key=None, use_private_key=True):
        """Giải mã ciphertext - updated to support both API and UI usage"""
        try:
            if key is not None:
                # API usage - key and ciphertext are provided directly
                if hasattr(key, 'decrypt'):
                    # It's a private key object, ciphertext is bytes
                    plaintext = key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    return plaintext.decode('utf-8')
                else:
                    raise Exception("Invalid key provided for decryption")
            else:
                # UI usage - load key from file, ciphertext is base64
                if use_private_key:
                    key = self.load_private_key()
                else:
                    raise Exception("Can only decrypt with private key")
                    
                # Decode base64
                ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
                
                # Giải mã
                plaintext = key.decrypt(
                    ciphertext_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"Error decrypting: {str(e)}")
    
    def sign(self, message, key=None):
        """Ký số message - updated to support both API and UI usage"""
        try:
            if key is not None:
                # API usage - key is provided directly
                if hasattr(key, 'sign'):
                    # It's a private key object
                    message_bytes = message.encode('utf-8')
                    signature = key.sign(
                        message_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return signature
                else:
                    raise Exception("Invalid key provided for signing")
            else:
                # UI usage - load key from file
                private_key = self.load_private_key()
                message_bytes = message.encode('utf-8')
                
                signature = private_key.sign(
                    message_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            raise Exception(f"Error signing: {str(e)}")
    
    def verify(self, message, signature, key=None):
        """Xác thực chữ ký - updated to support both API and UI usage"""
        try:
            if key is not None:
                # API usage - key and signature are provided directly
                if hasattr(key, 'verify'):
                    # It's a public key object, signature is bytes
                    message_bytes = message.encode('utf-8')
                    key.verify(
                        signature,
                        message_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return True
                else:
                    raise Exception("Invalid key provided for verification")
            else:
                # UI usage - load key from file, signature is base64
                public_key = self.load_public_key()
                message_bytes = message.encode('utf-8')
                signature_bytes = base64.b64decode(signature.encode('utf-8'))
                
                public_key.verify(
                    signature_bytes,
                    message_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
        except Exception as e:
            return False

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.btn_gen_keys.clicked.connect(self.call_api_gen_keys)
        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui.btn_sign.clicked.connect(self.call_api_sign)
        self.ui.btn_verify.clicked.connect(self.call_api_verify)

    def call_api_gen_keys(self):
        url = "http://127.0.0.1:5000/api/rsa/generate_keys"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText(data["message"])
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {str(e)}")

    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/encrypt"
        payload = {
            "message": self.ui.text_plaintext.toPlainText(),
            "key_type": "public"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.text_ciphertext.setText(data["encrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {str(e)}")

    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/decrypt"
        payload = {
            "ciphertext": self.ui.text_ciphertext.toPlainText(),
            "key_type": "private"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.text_plaintext.setText(data["decrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {str(e)}")

    def call_api_sign(self):
        url = "http://127.0.0.1:5000/api/rsa/sign"
        payload = {
            "message": self.ui.text_info.toPlainText()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.text_sign.setText(data["signature"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Signed Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {str(e)}")

    def call_api_verify(self):
        url = "http://127.0.0.1:5000/api/rsa/verify"
        payload = {
            "message": self.ui.text_info.toPlainText(),
            "signature": self.ui.text_sign.toPlainText()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if data["is_verified"]:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Successfully")
                    msg.exec_()
                else:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Fail")
                    msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())
