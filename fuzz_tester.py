import atheris
import sys
import requests

# Define the target URL (your Flask API endpoint)
TARGET_URL = "http://127.0.0.1:5000/test"

def fuzz_function(data):
    """Send fuzzed data to the web application."""
    fuzzed_payload = data.decode(errors='ignore')  # Convert bytes to string

    try:
        # Send the fuzzed data to the API
        response = requests.post(TARGET_URL, data=fuzzed_payload)

        # Log responses (to check for anomalies)
        print(f"Sent: {fuzzed_payload} | Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

def main():
    """Run the fuzzer with Atheris."""
    atheris.Setup(sys.argv, atheris.Fuzz)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
