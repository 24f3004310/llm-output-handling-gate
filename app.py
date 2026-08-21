import re
import html
import urllib.parse
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-pu2jnx6.example", "app-13mshmo.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

DANGEROUS_SCHEME_REGEX = re.compile(r"(javascript|data|vbscript)\s*:", re.IGNORECASE)
SCRIPT_TAG_REGEX = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)
EVENT_HANDLER_REGEX = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
UNICODE_ESCAPE_REGEX = re.compile(r"\\u([0-9a-fA-F]{4})")

SQL_METACHAR_REGEX = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE)
SHELL_METACHAR_REGEX = re.compile(r"[;&|`<>]|\$\(|\$\{")

def make_json_response(safe: bool, reason: str, status_code: int = 200):
    """Guarantees strict HTTP 200 status and application/json headers."""
    payload = f'{{"safe": {"true" if safe else "false"}, "reason": "{reason}"}}'
    return Response(payload, status=status_code, mimetype='application/json')

def decode_output(text: str) -> str:
    try:
        decoded = urllib.parse.unquote(text)
    except Exception:
        decoded = text

    decoded = html.unescape(decoded)

    def replace_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    decoded = UNICODE_ESCAPE_REGEX.sub(replace_unicode, decoded)
    return decoded

def parse_and_validate_url(raw_url: str):
    url_str = raw_url.strip()
    if not url_str:
        return None

    if url_str.startswith("//"):
        url_str = "https:" + url_str

    parsed = urllib.parse.urlparse(url_str)

    if not parsed.scheme and not parsed.netloc:
        return None

    if parsed.scheme.lower() not in ["http", "https"]:
        return "DANGEROUS_SCHEME"

    hostname = parsed.hostname
    if hostname is None or hostname.lower() not in ALLOWED_HOSTS:
        return "EXTERNAL_EXFIL"

    return None

def check_channel_rules(channel: str, output: str):
    if channel in ["html", "markdown", "url"]:
        if DANGEROUS_SCHEME_REGEX.search(output):
            return "DANGEROUS_SCHEME"

    if channel == "html":
        if SCRIPT_TAG_REGEX.search(output):
            return "SCRIPT_TAG"
        if EVENT_HANDLER_REGEX.search(output):
            return "EVENT_HANDLER"

        urls = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', output, re.IGNORECASE)
        for u in urls:
            res = parse_and_validate_url(u)
            if res:
                return res

    elif channel == "markdown":
        urls = re.findall(r'\]\(([^)]+)\)', output)
        for u in urls:
            clean_url = u.strip().split()[0] if u.strip() else ""
            res = parse_and_validate_url(clean_url)
            if res:
                return res

    elif channel == "url":
        res = parse_and_validate_url(output)
        if res:
            return res

    elif channel == "sql":
        if SQL_METACHAR_REGEX.search(output):
            return "SQL_METACHAR"

    elif channel == "shell":
        if SHELL_METACHAR_REGEX.search(output):
            return "SHELL_METACHAR"

    return None

# Handle both trailing slash and non-trailing slash URLs
@app.route('/sanitize-output', methods=['POST', 'GET'])
@app.route('/sanitize-output/', methods=['POST', 'GET'])
def sanitize_output():
    # Handle non-POST probes cleanly
    if request.method != 'POST':
        return make_json_response(False, "INVALID_SCHEMA")

    # Safely extract JSON without throwing 400 Bad Request exceptions
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        return make_json_response(False, "INVALID_SCHEMA")

    # 1. INVALID_SCHEMA Validation
    if not isinstance(data, dict):
        return make_json_response(False, "INVALID_SCHEMA")

    channel = data.get("channel")
    output = data.get("output")

    if channel not in ALLOWED_CHANNELS or not isinstance(output, str) or len(output) > 20000:
        return make_json_response(False, "INVALID_SCHEMA")

    # 2. ENCODED_PAYLOAD Obfuscation Check
    decoded = decode_output(output)
    if decoded != output:
        decoded_violation = check_channel_rules(channel, decoded)
        if decoded_violation is not None:
            return make_json_response(False, "ENCODED_PAYLOAD")

    # 3. Raw Output Validation
    violation = check_channel_rules(channel, output)
    if violation is not None:
        return make_json_response(False, violation)

    return make_json_response(True, "SAFE")

# Global error handler to catch unexpected 500/404 errors and format as JSON
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_global_errors(e):
    return make_json_response(False, "INVALID_SCHEMA")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
