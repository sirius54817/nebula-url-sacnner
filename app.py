from flask import Flask, render_template, request, jsonify
import requests
import time

app = Flask(__name__)

# Replace with your actual URLScan.io API Key
URLSCAN_API_KEY = 'e531f69c-0922-420a-bb32-e7084f6fcaaf'

def check_urlscan(url):
    """Submit the URL for scanning and retrieve the results from URLScan.io."""
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "url": url,
        "visibility": "public",  # Set to "public" or "unlisted" as required
        "tags": ["phishing_check", "demo"]
    }

    # Submit the URL for scanning
    submission_response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
    if submission_response.status_code != 200:
        return f"Error submitting URL for scan: {submission_response.status_code} - {submission_response.text}"

    # Extract UUID from response to identify the scan result
    submission_result = submission_response.json()
    result_id = submission_result.get("uuid")
    if not result_id:
        return "Error: Could not retrieve scan UUID from URLScan.io response."

    # Wait for the scan to complete
    time.sleep(10)  # Adjust wait time as needed based on scan speed

    # Retrieve the scan result
    result_url = f"https://urlscan.io/api/v1/result/{result_id}/"
    result_response = requests.get(result_url)
    if result_response.status_code == 200:
        result_data = result_response.json()
        # Check if URL was flagged as malicious
        if result_data.get("verdicts", {}).get("overall", {}).get("malicious"):
            return "Nebula flagged this URL as malicious."
        else:
            return "Nebula did not flag this URL as malicious."
    else:
        return f"Error retrieving scan result: {result_response.status_code} - {result_response.text}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form["url"]

    # Check with URLScan.io
    urlscan_check = check_urlscan(url)
    return jsonify({"result": urlscan_check})

if __name__ == "__main__":
    app.run(debug=True)
