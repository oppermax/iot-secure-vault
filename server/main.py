from flask import Flask, request, jsonify

from vault import VaultServer, vault
from vault.utils import NONCE_SIZE, CHALLENGE_SIZE, decrypt

app = Flask(__name__)


app.vault_server = VaultServer(vault=vault.new_from_file('server/server_vault'))

@app.route('/handshake', methods=['POST'])
def handshake():
    data = request.get_json()
    m1 = bytes.fromhex(data.get('payload'))

    device_id = m1[NONCE_SIZE:NONCE_SIZE+2]

    device_id = int.from_bytes(device_id, 'big')

    session_id, m2 = app.vault_server.handle_handshake(m1, CHALLENGE_SIZE)

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

    device_id = app.vault_server.sessions.get(session_id, {}).get('device_id', None)

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

    device_id = app.vault_server.sessions.get(session_id, {}).get('device_id', None)

    if device_id is None:
        return jsonify({'error': 'no session found. initialize handshake first'}), 400

    session = app.vault_server.sessions[session_id]

    session_key = session.get('session_key')
    if session_key is None:
        return jsonify({'error': 'session not authenticated'}), 400

    decrypted_payload = decrypt(encrypted_payload, session_key)

    if decrypted_payload is None:
        return jsonify({'error': 'Decryption failed'}), 400

    print(f"Received data from device {device_id}:\n{decrypted_payload.decode('utf-8', errors='ignore')}")

    return jsonify({'status': 'data received'})

@app.route('/end', methods=['POST'])
def end():
    data = request.get_json()
    session_id = bytes.fromhex(data.get('session_id'))

    device_id = app.vault_server.sessions.get(session_id, {}).get('device_id', None)

    if device_id is None:
        return jsonify({'error': 'no session found. initialize handshake first'}), 400

    app.vault_server.end_session(session_id)

    print(f"Session with device {device_id} ended.")

    return jsonify({'status': 'session ended'})


if __name__ == "__main__":
    app.run(host='localhost', port=7000, debug=True)