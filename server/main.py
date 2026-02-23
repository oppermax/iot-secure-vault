from flask import Flask, request, jsonify

from secure_vault import VaultServer
from secure_vault.utils import NONCE_SIZE, decrypt, nonce_from_counter

app = Flask(__name__)

CHALLENGE_SIZE = 5  # Number of keys in challenge

app.vault_server = VaultServer(vault_file_path='server/server_vault', challenge_size=CHALLENGE_SIZE)

@app.route('/handshake', methods=['POST'])
def handshake():
    data = request.get_json()
    m1 = bytes.fromhex(data.get('payload'))

    device_id = m1[NONCE_SIZE:NONCE_SIZE+2]

    device_id = int.from_bytes(device_id, 'big')

    session_id, m2 = app.vault_server.handle_handshake(m1)

    print(f"Handshake initiated by device: {device_id}")
    print(f"Session ID: {session_id}")

    return jsonify({
        'session_id': session_id.hex(),
        'payload': m2.hex(),
    })

@app.route('/challenge', methods=['POST'])
def challenge():
    data = request.get_json()
    m3 = bytes.fromhex(data.get('payload'))

    session_id = bytes.fromhex(data.get('session_id'))

    session = app.vault_server.sessions.get(session_id)
    device_id = session.device_id if session else None

    if device_id is None:
        return jsonify({'error': f'no device found for session id {session_id.hex()}'}), 400

    success, m4 = app.vault_server.verify_and_respond(session_id, m3)

    if success:
        print(f"device {device_id} authenticated successfully. connection is secure.")
        return jsonify({'payload': m4.hex()})
    else:
        print(f"device {device_id} authentication failed.")
        return jsonify({'status': 'failure'}), 401

@app.route('/data', methods=['POST'])
def data():
    data = request.get_json()
    session_id = bytes.fromhex(data.get('session_id'))
    encrypted_payload = bytes.fromhex(data.get('payload'))

    session = app.vault_server.sessions.get(session_id)
    device_id = session.device_id if session else None

    if device_id is None:
        return jsonify({'error': 'no session found. initialize handshake first'}), 400

    session_key = session.session_key
    if session_key is None:
        return jsonify({'error': 'session not authenticated'}), 400

    decrypted_payload = decrypt(encrypted_payload, session_key, nonce_from_counter(session.data_counter))

    if decrypted_payload is None:
        return jsonify({'error': 'Decryption failed'}), 400

    session.data_counter += 1

    # append the decrypted data to session data for vault update
    session.append_data(decrypted_payload)

    print(f"Received data from device {device_id}:\n{decrypted_payload.decode('utf-8', errors='ignore')}")

    return jsonify({'status': 'data received'})

@app.route('/end', methods=['POST'])
def end():
    data = request.get_json()
    session_id = bytes.fromhex(data.get('session_id'))

    session = app.vault_server.sessions.get(session_id)
    device_id = session.device_id if session else None

    if device_id is None:
        return jsonify({'error': 'no session found. initialize handshake first'}), 400

    app.vault_server.end_session(session_id)

    print(f"Session with device {device_id} ended.")

    return jsonify({'status': 'session ended'})


if __name__ == "__main__":
    app.run(host='localhost', port=7000, debug=True)