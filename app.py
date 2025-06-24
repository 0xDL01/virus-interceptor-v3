from flask import Flask, render_template, request, url_for
import os
import re
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder="templates", static_folder="uploads")
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SCAM_APPS = {
    "anydesk": "Remote access scam tool",
    "teamviewer": "Remote desktop control used in fake support",
    "ultraviewer": "Common tool in refund scams",
    "zoho assist": "Used in phone-based scam control",
    "spynote": "Android RAT used for full phone control",
    ".apk": "APK file — often used to distribute malware",
    ".exe": "Executable — potential malware",
    "g00gle.com": "Typo phishing for Google",
    "bitprofit": "Fake crypto trading app",
    "quick support": "Imposter support scam"
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_scam_links(text):
    links = re.findall(r'(https?://[^\s]+)', text)
    if not links:
        links = [text.strip()]

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.cam', '.zip', '.review', '.ru', '.cn']
    scam_keywords = ['bonus', 'gift', 'login', 'free', 'wallet', 'investment', 'airdrop', 'crypto', 'install', 'verify', 'secure']
    typos = ['g00gle', 'amaz0n', 'faceb00k', 'whatsapp-com', 'micr0soft', 'paypa1', 'netfIix', 'paypai', 'bank-return']

    results = []
    for link in links:
        link_lower = link.lower()
        suspicious = False
        matched_tags = []

        for tld in suspicious_tlds:
            if tld in link_lower:
                suspicious = True
                matched_tags.append((tld, "Suspicious top-level domain"))

        for word in scam_keywords:
            if word in link_lower:
                suspicious = True
                matched_tags.append((word, "Scam keyword in URL"))

        for typo in typos:
            if typo in link_lower:
                suspicious = True
                matched_tags.append((typo, "Typo-squatted domain"))

        if len(link_lower.split(".")) > 4:
            suspicious = True
            matched_tags.append(("subdomain", "Too many subdomains"))

        if any(k in link_lower for k in SCAM_APPS):
            for k, v in SCAM_APPS.items():
                if k in link_lower:
                    matched_tags.append((k, v))
            suspicious = True

        if suspicious:
            results.append((link, "⚠️ Suspicious", matched_tags))
        else:
            results.append((link, "✅ Clean", []))

    return results

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    image_url = None
    if request.method == "POST":
        if 'message' in request.form:
            message = request.form["message"]
            results = detect_scam_links(message)
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = url_for('static', filename=filename)
    return render_template("index.html", results=results, image_url=image_url)

if __name__ == "__main__":
    app.run(debug=True)
