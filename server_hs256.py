import jwt
import base64
import os
from flask import Flask, request, jsonify
import datetime

# generate a key and encode it for jsonification (is this serialization?)
secret_key = os.urandom(32)
encoded_key = base64.urlsafe_b64encode(secret_key).decode('utf-8')

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
    return jsonify({"token": jwt.encode(payload_data, secret_key, "HS256", header)})

@app.route('/.well-known/jwks.json', methods=['GET'])
def verify():
     # The jwks
    jwks_data = {
        "keys": [
            {
                "kty":"oct",
                "k": encoded_key,
                "alg":"HS256",
                "kid":"unexpired",
                "use": "sig"
            }
        ]
    }
    return jsonify(jwks_data)


if __name__ == "__main__":
    app.run(port = 8080)