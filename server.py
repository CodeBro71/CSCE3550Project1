import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify
import datetime

# generate keys
rsa_keys = rsa.generate_private_key(65537, 1024)

# serialize keys
public_key = rsa_keys.public_key().public_bytes( serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
private_key = rsa_keys.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

# flask for http and server handling
app = Flask(__name__)

# route and function for /auth
@app.route("/auth", methods = ["POST"])
def auth():
    payload_data = {
            "Username": "root",
            "Password": "123442069",
            "exp" : datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes = 10)
    }
    header = {}

    # expired case
    if request.args.get("expired") is not None:   
        header = {"kid": "expired"}

    # unexpired case
    else:
        payload_data["exp"] += datetime.timedelta(minutes = 20) 
        header = {"kid": "unexpired"}

    # return signed token
    return jsonify({"token": jwt.encode(payload_data, private_key, "RS256", header)})

# route and function for verifying
# for some reason, despite kid matching 'valid' tokens, they still cannot be found in the jwks
# I think this might have to do with my keys or misunderstanding of the rs256 algorithm and standards
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    jwks = {
        "keys": [
            {
                "alg": "RS256",
                "kid": "unexpired",
                "kty": "RSA",
                "use": "sig",
                "n": str(rsa_keys.public_key().public_numbers().n),
                "e": str(rsa_keys.public_key().public_numbers().e),
                "k": base64.urlsafe_b64encode(public_key).decode("utf-8")
            }
        ]
    }
    return jsonify(jwks)

# run server on port 8080 (on localhost)
if __name__ == "__main__":
    app.run(port = 8080)