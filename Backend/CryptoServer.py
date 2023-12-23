import sys
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client
import random
import ast
import numpy as np

from DiffieHellman import (
    generate_key_pair_diffie,
    diffie_hellman_key_exchange,
    generate_session_key_diffie,
)

from ElGamal import (
    elgamal_encrypt,
    elgamal_decrypt,
    generate_keypair_gamal,
    generate_gamal_prime,
    generate_gamal_primitive_root,
)

from ClassicalAlgorithms import caesar_encrypt, caesar_decrypt
from DES import des_encrypt, des_decrypt
from AES import AES
from rc4 import rc4_encrypt, rc4_decrypt
from rsa import rsa_encrypt, rsa_decrypt, generate_keypair_rsa

SUPABASE_URL = "https://osbdcpugryrgxfdxzkom.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9zYmRjcHVncnlyZ3hmZHh6a29tIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMzE4MTUwNiwiZXhwIjoyMDE4NzU3NTA2fQ.sVDveU0ZI9tewFy8hIYCYG37MFhQCWER3r1HJXYUhuw"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


private_key = ""
table_name = "Public Repo"

current_chat_session_data = {}
curr_user = -1


app = Flask(__name__)
CORS(app)


def get_receiver_public_key(algorithm):
    global curr_user

    if curr_user == current_chat_session_data["person1"]:
        return current_chat_session_data[f"person2_{algorithm}_public_key"]

    return current_chat_session_data[f"person1_{algorithm}_public_key"]


def get_private_key(algorithm):
    try:
        return int(
            open(
                f"./Backend/private_keys/{curr_user}_{current_chat_session_data['id']}_{algorithm}_private_key.txt",
                "r",
                encoding="utf-8",
            ).read()
        )
    except Exception as e:
        return open(
            f"./Backend/private_keys/{curr_user}_{current_chat_session_data['id']}_{algorithm}_private_key.txt",
            "r",
            encoding="utf-8",
        ).read()


def get_symmetric_key():
    print(current_chat_session_data)
    print(curr_user)

    receiver_public_key = get_receiver_public_key("diffie")
    sender_private_key = get_private_key("diffie")

    key = generate_session_key_diffie(
        sender_private_key,
        receiver_public_key,
        current_chat_session_data["diffie_p"],
    )

    return key


@app.route("/rsa_decrypt", methods=["POST"])
def process_rsa_decrypt():
    try:
        data = request.get_json()
        data["encryptedMesssage"] = ast.literal_eval(data["encryptedMesssage"])
        reveiver_private_key = ast.literal_eval(get_private_key("rsa"))

        if "encryptedMesssage" in data:
            decrypted_message = rsa_decrypt(
                data["encryptedMesssage"],
                reveiver_private_key,
            )
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/rsa_encrypt", methods=["POST"])
def process_rsa_encrypt():
    try:
        data = request.get_json()
        receiver_public_key = ast.literal_eval(get_receiver_public_key("rsa"))

        if "value" in data:
            encrypted_message = str(rsa_encrypt(data["value"], receiver_public_key))
            encrypted_message += "/rsa"
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/gamal_decrypt", methods=["POST"])
def process_gamal_decrypt():
    try:
        data = request.get_json()
        key = str(get_symmetric_key())
        print(key)
        data["encryptedMesssage"] = ast.literal_eval(data["encryptedMesssage"])

        print(len(data["encryptedMesssage"]))
        reveiver_private_key = get_private_key("gamal")

        print(reveiver_private_key, current_chat_session_data["gamal_p"])

        if "encryptedMesssage" in data:
            decrypted_message = elgamal_decrypt(
                data["encryptedMesssage"],
                reveiver_private_key,
                current_chat_session_data["gamal_p"],
            )
            print(decrypted_message)
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/gamal_encrypt", methods=["POST"])
def process_gamal_encrypt():
    try:
        data = request.get_json()

        receiver_public_key = get_receiver_public_key("gamal")
        prime = current_chat_session_data["gamal_p"]
        generator = current_chat_session_data["gamal_g"]
        print(receiver_public_key, prime, generator)

        if "value" in data:
            encrypted_message = str(
                elgamal_encrypt(data["value"], receiver_public_key, prime, generator)
            )
            encrypted_message += "/gamal"
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/des_decrypt", methods=["POST"])
def process_des_decrypt():
    try:
        data = request.get_json()
        key = str(get_symmetric_key())
        print(key)
        data["encryptedMesssage"] = ast.literal_eval(data["encryptedMesssage"])

        if "encryptedMesssage" in data:
            decrypted_message = des_decrypt(data["encryptedMesssage"], key)
            print(decrypted_message)
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/des_encrypt", methods=["POST"])
def process_des_encrypt():
    try:
        data = request.get_json()
        key = str(get_symmetric_key())
        print(key)

        if "value" in data:
            encrypted_message = str(des_encrypt(data["value"], key))
            encrypted_message += "/des"
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/aes_decrypt", methods=["POST"])
def process_aes_decrypt():
    try:
        data = request.get_json()
        key = str(get_symmetric_key())
        print(key)

        data["encryptedMesssage"] = int_list = [
            int(x) for x in data["encryptedMesssage"].strip("[]").split()
        ]
        data["encryptedMesssage"] = bytes(data["encryptedMesssage"])
        data["encryptedMesssage"] = np.frombuffer(
            data["encryptedMesssage"], dtype=np.uint8
        )

        aes = AES(128, text=data["encryptedMesssage"], key=key, mode="decrypt")

        if "encryptedMesssage" in data:
            decrypted_message = aes.encrypt()
            decrypted_message = "".join(chr(p) for p in decrypted_message)
            print(decrypted_message)
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/aes_encrypt", methods=["POST"])
def process_aes_encrypt():
    try:
        data = request.get_json()
        key = str(get_symmetric_key())
        print(key)
        aes = AES(128, text=data["value"], key=key, mode="encrypt")
        if "value" in data:
            encrypted_message = str(aes.encrypt())
            encrypted_message += "/aes"
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/rc4_encrypt", methods=["POST"])
def process_rc4_encrypt():
    try:
        data = request.get_json()
        key = get_symmetric_key()
        print(key)

        if "value" in data:
            encrypted_message = str(rc4_encrypt(data["value"], key))
            encrypted_message += "/rc4"
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/rc4_decrypt", methods=["POST"])
def process_rc4_decrypt():
    try:
        data = request.get_json()
        key = get_symmetric_key()
        print(key)
        data["encryptedMesssage"] = ast.literal_eval(data["encryptedMesssage"])
        if "encryptedMesssage" in data:
            decrypted_message = rc4_decrypt(data["encryptedMesssage"], key)
            print(decrypted_message)
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/caesar_encrypt", methods=["POST"])
def process_caesar_encrypt():
    try:
        data = request.get_json()
        key = get_symmetric_key()
        print(key)

        if "value" in data:
            encrypted_message = caesar_encrypt(data["value"], key)
            return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/caesar_decrypt", methods=["POST"])
def process_caesar_decrypt():
    try:
        data = request.get_json()
        key = get_symmetric_key()
        print(key)

        if "encryptedMesssage" in data:
            decrypted_message = caesar_decrypt(data["encryptedMesssage"], key)
            print(decrypted_message)
            return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": e}), 400


@app.route("/generatekeys", methods=["POST"])
def save_chat_in_db():
    global current_chat_session_data
    global curr_user

    try:
        data = request.get_json()
        if "chat_id" not in data or "curr_user" not in data:
            raise ValueError("Invalid request payload")

        response = (
            supabase.table(table_name)
            .select("*")
            .eq("id", data["chat_id"])
            .limit(1)
            .execute()
        )
        current_chat_session_data = response.data[0] if len(response.data) else []
        curr_user = data["curr_user"]

        print(current_chat_session_data)

        if len(response.data) < 1:
            curr_user = data["curr_user"]
            prime, generator = diffie_hellman_key_exchange()
            person_public_key, person_private_key = generate_key_pair_diffie(
                prime, generator
            )

            prime_gamal = generate_gamal_prime()
            generator_gamal = generate_gamal_primitive_root(prime_gamal)
            person_private_key_gamal, person_public_key_gamal = generate_keypair_gamal(
                prime_gamal, generator_gamal
            )
            person_public_key_rsa, person_private_key_rsa = generate_keypair_rsa()

            db_response = (
                supabase.table(table_name)
                .insert(
                    {
                        "id": data["chat_id"],
                        "person1": data["curr_user"],
                        "person1_diffie_public_key": person_public_key,
                        "person1_gamal_public_key": person_public_key_gamal,
                        "person1_rsa_public_key": str(person_public_key_rsa),
                        "diffie_p": prime,
                        "diffie_g": generator,
                        "gamal_p": prime_gamal,
                        "gamal_g": generator_gamal,
                    }
                )
                .execute()
            )
            current_chat_session_data = db_response.data[0]

            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_diffie_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key))

            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_gamal_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key_gamal))

            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_rsa_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key_rsa))

            return jsonify(
                {
                    "success": True,
                    "message": "Keys for first person were saved successfully",
                }
            )
        elif len(response.data) >= 1 and response.data[0]["person2"] is not None:
            return jsonify({"success": True, "message": "Keys already exist"})
        elif (
            len(response.data) >= 1
            and response.data[0]["person2"] is None
            and response.data[0]["person1"] != data["curr_user"]
        ):
            response = response.data[0]
            curr_user = data["curr_user"]
            person_public_key, person_private_key = generate_key_pair_diffie(
                response["diffie_p"], response["diffie_g"]
            )
            person_private_key_gamal, person_public_key_gamal = generate_keypair_gamal(
                response["gamal_p"], response["gamal_g"]
            )
            person_public_key_rsa, person_private_key_rsa = generate_keypair_rsa()

            db_response = (
                supabase.table(table_name)
                .update(
                    {
                        "person2": data["curr_user"],
                        "person2_diffie_public_key": person_public_key,
                        "person2_gamal_public_key": person_public_key_gamal,
                        "person2_rsa_public_key": str(person_public_key_rsa),
                    }
                )
                .eq("id", data["chat_id"])
                .execute()
            )

            current_chat_session_data = db_response.data[0]
            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_diffie_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key))

            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_gamal_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key_gamal))

            with open(
                f"./Backend/private_keys/{data['curr_user']}_{data['chat_id']}_rsa_private_key.txt",
                "w",
                encoding="utf-8",
            ) as f:
                f.write(str(person_private_key_rsa))

            return jsonify(
                {
                    "success": True,
                    "message": "Keys for second person were saved successfully",
                }
            )
        else:
            return jsonify(
                {
                    "success": True,
                    "message": "person already exists",
                }
            )

    except Exception as e:
        print("Error:", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/")
def home():
    return "Hello World!"


if __name__ == "__main__":
    app.run(debug=True)
