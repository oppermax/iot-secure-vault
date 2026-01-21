import requests
from vault import vault
from vault import IoTDevice
from vault.utils import SERVER_IP, SERVER_PORT, encrypt


def handle_response(resp: requests.Response):
    try:
        resp.raise_for_status()
        data = resp.json()
        print("Server response:", data)
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e} - {resp.text}")
    except requests.exceptions.Timeout:
        print("Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except ValueError:
        print("Failed to decode JSON response")


def main():
    print("initiating client...")

    vault_obj = vault.new_from_file("client/client_vault")

    device = IoTDevice(device_id=161, vault=vault_obj)

    client = requests.session()
    resp = None # initialize so that it definitely exists in the try blocks


    print("ready for handshake?")
    if input("y/n:").lower() != 'y':
        print("exiting...")
        return

    base_url = f'http://{SERVER_IP}:{SERVER_PORT}'
    headers = {'Content-Type': 'application/json'}

    m1 = device.initiate_handshake()
    print(f"Message M1: {m1.hex()}")
    try:
        payload = {
            'payload' : m1.hex(),
            'session_id' : device.session_id.hex(),
        }
        resp = client.post(f'{base_url}/handshake', json=payload, headers=headers, timeout=5)
        handle_response(resp)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    m2 = bytes.fromhex(resp.json().get('payload'))
    print(f"Received Message M2: {m2.hex()}")
    m3 = device.respond_to_challenge(m2)
    print(f"Message M3: {m3.hex()}")
    try:
        payload = {
            'payload' : m3.hex(),
            'session_id' : device.session_id.hex()
        }
        resp = client.post(f'{base_url}/challenge', json=payload, headers=headers, timeout=5)
        handle_response(resp)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    print(resp.json())
    m4 = bytes.fromhex(resp.json().get('payload'))
    verified = device.verify_server(m4)

    if not verified:
        print("server verification failed. exiting...")
        return
    print("server verified successfully.")

    # Authenticated

    while True:
        print("ready to transmit data. type 'exit' to quit.")
        user_input = input().lower()
        if user_input == 'exit':
            print("exiting...")
            try:
                client.post(f'{base_url}/end', json={
                    'session_id' : device.session_id.hex(),
                    'device_id' : device.device_id
                }, headers=headers, timeout=5)
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")
            device.end_session()
            return

        try:
            user_input = user_input.encode("utf-8")
            payload = {
                'payload' : encrypt(user_input, device.session_key).hex(),
                'session_id' : device.session_id.hex(),
                'device_id' : device.device_id
            }
            resp = client.post(f'{base_url}/data', json=payload, headers=headers, timeout=5)
            handle_response(resp)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")









if __name__ == "__main__":
    main()