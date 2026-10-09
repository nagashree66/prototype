# prototype
Reversible PII Sanitization &amp; Privacy Middleware For AI Agent Tools



from flask import Flask, request, render_template_string
import re, uuid, time
from cryptography.fernet import Fernet

app = Flask(__name__)

class PrivacyFirewall:
    def __init__(self):
        self.cipher = Fernet(Fernet.generate_key())
        self.token_vault = {}
        self.expiry_time = 60  # tokens expire after 60 seconds

    def _encrypt(self, value):
        return self.cipher.encrypt(value.encode())

    def _decrypt(self, value):
        return self.cipher.decrypt(value).decode()

    def _generate_token(self):
        return f"TOKEN-{uuid.uuid4().hex[:8]}"

    def mask_payload(self, payload):
        # Normalize obfuscated formats
        payload = payload.replace("[at]", "@").replace("(at)", "@")
        payload = payload.replace("[dot]", ".").replace("(dot)", ".")

        # Detect emails
        payload = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', self._replace_with_token, payload)
        # Detect phone numbers (international + local)
        payload = re.sub(r'\+?\d[\d\-\s]{7,}\d', self._replace_with_token, payload)
        # Detect ID numbers (simple example: 6+ digits)
        payload = re.sub(r'\b\d{6,}\b', self._replace_with_token, payload)

        # Spam prevention
        if len(self.token_vault) > 5:
            raise ValueError("Too much sensitive info detected — request blocked!")

        return payload

    def _replace_with_token(self, match):
        real_value = match.group(0)
        token = self._generate_token()
        encrypted_value = self._encrypt(real_value)
        self.token_vault[token] = {"value": encrypted_value, "timestamp": time.time()}
        return token

    def restore_payload(self, payload):
        for token, data in list(self.token_vault.items()):
            if time.time() - data["timestamp"] > self.expiry_time:
                del self.token_vault[token]
                continue
            real_value = self._decrypt(data["value"])
            payload = payload.replace(token, real_value)
        return payload


firewall = PrivacyFirewall()

# Simple HTML template for friendly interface
html_template = """
<!doctype html>
<html>
<head>
    <title>Privacy Firewall</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f9f9f9; }
        h1 { color: #333; }
        input, textarea { width: 100%; padding: 10px; margin: 10px 0; }
        button { padding: 10px 20px; background: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background: #45a049; }
        .result { margin-top: 20px; padding: 15px; background: #e7f3fe; border-left: 6px solid #2196F3; }
    </style>
</head>
<body>
    <h1>🔒 Privacy Firewall</h1>
    <p>Type your message below. Sensitive info like emails or phone numbers will be protected automatically.</p>
    <form method="POST">
        <textarea name="user_input" rows="4" placeholder="Enter your request..."></textarea>
        <button type="submit">Submit</button>
    </form>
    {% if masked %}
    <div class="result">
        <p><strong>Masked (safe to send):</strong> {{ masked }}</p>
        <p><strong>Restored (your original message):</strong> {{ restored }}</p>
        <p>✅ Your private info was protected before sending!</p>
    </div>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    masked = restored = None
    if request.method == "POST":
        user_input = request.form.get("user_input", "")
        try:
            masked = firewall.mask_payload(user_input)
            response = f"Message sent to {masked}"
            restored = firewall.restore_payload(response)
        except ValueError as e:
            masked = str(e)
            restored = "Request blocked for safety."
    return render_template_string(html_template, masked=masked, restored=restored)


if __name__ == "__main__":
    app.run(debug=True)
