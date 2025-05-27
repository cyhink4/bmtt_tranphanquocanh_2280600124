from flask import Flask, request, jsonify
from cipher.rsa import  RSACipher
from cipher.ecc import ECCCipher

app = Flask(__name__)

#RSA CIPHER ALGORITHM
rsa_cipher = RSACipher()
#ECC CIPHER ALGORITHM
ecc_cipher = ECCCipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json
    message = data['message']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})
    encrypted_message = rsa_cipher.encrypt(message, key)
    import base64
    encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    return jsonify({'encrypted_message': encrypted_b64})

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json
    ciphertext_b64 = data['ciphertext']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})
    import base64
    ciphertext = base64.b64decode(ciphertext_b64)
    decrypted_message = rsa_cipher.decrypt(ciphertext, key)
    return jsonify({'decrypted_message': decrypted_message})

@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = rsa_cipher.load_keys()
    signature = rsa_cipher.sign(message, private_key)
    import base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return jsonify({'signature': signature_b64})

@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify_signature():
    data = request.json
    message = data['message']
    signature_b64 = data['signature']
    _, public_key = rsa_cipher.load_keys()
    import base64
    signature = base64.b64decode(signature_b64)
    is_verified = rsa_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})

# ECC CIPHER ALGORITHM ENDPOINTS
@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'ECC Keys generated successfully'})

@app.route("/api/ecc/sign", methods=["POST"])
def ecc_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = ecc_cipher.load_keys()
    signature = ecc_cipher.sign(message, private_key)
    import base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return jsonify({'signature': signature_b64})

@app.route("/api/ecc/verify", methods=["POST"])
def ecc_verify_signature():
    data = request.json
    message = data['message']
    signature_b64 = data['signature']
    _, public_key = ecc_cipher.load_keys()
    import base64
    signature = base64.b64decode(signature_b64)
    is_verified = ecc_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})

#main function
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
