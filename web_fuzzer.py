from boofuzz import *
import requests

def send_fuzz_request(url, payload):
    """Sends a request with the given payload and returns the response."""
    try:
        if not url.endswith("/"):
            url += "/" 
        #response = requests.get(url, params={"input": payload})  # Adjust parameter as needed
        response = requests.get(url, params={"input": payload})
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None
    
def generate_fuzz_payloads():
    """Returns a list of common fuzzing payloads."""
    return [
        "'", "\"", "<script>alert('XSS')</script>", "admin' --", " OR 1=1 --",
        "<img src=x onerror=alert(1)>", "../../etc/passwd", "'; DROP TABLE users; --",
        "javascript:alert(1)", "%00", "%27", "' OR '1'='1"
    ]

#class WebAppFuzzer:
    #def __init__(self, target_host, target_port=80):
    """Initialize the fuzzer with a target URL and port."""
    '''self.target_host = target_host
        self.target_port = target_port'''

    '''def run(self, endpoint="/search.php?q="):
        """Run the fuzzing process on a specific endpoint."""
        
        # Set up a session with reduced delays and timeout
        session = Session(
            target=Target(
                connection=TCPSocketConnection(self.target_host, self.target_port),
                timeout=5  # Avoid getting stuck on slow responses
            ),
            sleep_time=0.05,  # Reduce delay between requests for faster fuzzing
            fuzz_data_logger=FuzzLoggerText()
        )

        # Define a fuzzing request
        s_initialize("Request")
        s_static("GET ")
        s_string(endpoint)  # Fuzz the query string or input parameter
        s_static(" HTTP/1.1\r\nHost: " + self.target_host + "\r\n\r\n")

        # Attach the request to the session
        session.connect(s_get("Request"))

        print(f"Starting fuzzing on {self.target_host}{endpoint}")
        session.fuzz()  # Start fuzzing'''
class WebAppFuzzer:
    def __init__(self, base_url):
        self.base_url = base_url

    def run(self, endpoint, progress_callback=None):
        """Perform fuzzing and send progress updates if a callback is provided."""
        results = []
        payloads = generate_fuzz_payloads()
        total_payloads = len(payloads)
        for i, payload in enumerate(generate_fuzz_payloads()):  # Assuming fuzz payloads are generated
            response = send_fuzz_request(self.base_url + endpoint, payload)

            if response is None:
                results.append({'payload': payload, 'response_code': 'Request Failed'})
            else:
                results.append({'payload': payload, 'response_code': response.status_code})

            # Send progress updates
            if progress_callback:
                #progress_callback(i + 1, len(generate_fuzz_payloads()))
                progress_callback(i + 1, total_payloads)
        return results