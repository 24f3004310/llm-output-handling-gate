import re
import html
import urllib.parse
from flask import Flask, request, Response

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-pu2jnx6.example", "app-13mshmo.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

DANGEROUS_SCHEME_REGEX = re.compile(r"(javascript|data|vbscript)\s*:", re.IGNORECASE)
SCRIPT_TAG_REGEX = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)
EVENT_HANDLER_REGEX = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
UNICODE_ESCAPE_REGEX = re.compile(r"\\u([0-9a-fA-F]{4})")

SQL_METACHAR_REGEX = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE)
SHELL_METACHAR_REGEX = re.compile(r"[;&|`<>]|\$\(|\$\{")

def make_json_response(safe: bool, reason: str):
    payload = f'{{"safe": {"true" if safe else "false"}, "reason": "{reason}"}}'
    return Response(payload, status=200, mimetype='application/json')

def decode_output(text: str) -> str:
    # 1. Percent-escapes
    try:
        s = urllib.parse.unquote(text)
    except Exception:
        s = text

    # 2. HTML entities (numeric &#NN;/&#xNN; and named &lt; &gt; &quot; &apos; &amp;)
    s = html.unescape(s)

    # 3. Unicode escapes (\uXXXX)
    def replace_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    s = UNICODE_ESCAPE_REGEX.sub(replace_unicode, s)
    return s

def check_url_safety(raw_url: str):
    url_str = raw_url.strip()
    if not url_str:
        return None

    # Resolve protocol-relative references (e.g., //host/path)
    if url_str.startswith("//"):
        url_str = "https:" + url_str

    parsed = urllib.parse.urlparse(url_str)

    # Relative paths (e.g. /local/page) are allowed
    if not parsed.scheme and not parsed.netloc:
        return None

    # Scheme check
    if parsed.scheme.lower() not in ["http", "https"]:
        return "DANGEROUS_SCHEME"

    # Hostname check (Strict match against assigned hosts)
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

        # Extract URLs from src="..." and href="..."
        urls = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', output, re.IGNORECASE)
        for u in urls:
            res = check_url_safety(u)
            if res:
                return res

    elif channel == "markdown":
        # Extract target URLs inside ](...)
        urls = re.findall(r'\]\(([^)]+)\)', output)
        for u in urls:
            clean_url = u.strip().split()[0] if u.strip() else ""
            res = check_url_safety(clean_url)
            if res:
                return res

    elif channel == "url":
        res = check_url_safety(output)
        if res:
            return res

    elif channel == "sql":
        if SQL_METACHAR_REGEX.search(output):
            return "SQL_METACHAR"

    elif channel == "shell":
        if SHELL_METACHAR_REGEX.search(output):
            return "SHELL_METACHAR"

    return None

@app.route('/sanitize-output', methods=['POST', 'GET'])
@app.route('/sanitize-output/', methods=['POST', 'GET'])
def sanitize_output():
    if request.method != 'POST':
        return make_json_response(False, "INVALID_SCHEMA")

    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        return make_json_response(False, "INVALID_SCHEMA")

    if not isinstance(data, dict):
        return make_json_response(False, "INVALID_SCHEMA")

    channel = data.get("channel")
    output = data.get("output")

    if channel not in ALLOWED_CHANNELS or not isinstance(output, str) or len(output) > 20000:
        return make_json_response(False, "INVALID_SCHEMA")

    # Rule 2: Obfuscation Check via 3-Stage Decoding
    decoded = decode_output(output)
    if decoded != output:
        decoded_violation = check_channel_rules(channel, decoded)
        if decoded_violation is not None:
            return make_json_response(False, "ENCODED_PAYLOAD")

    # Rule 3: Original String Validation
    violation = check_channel_rules(channel, output)
    if violation is not None:
        return make_json_response(False, violation)

    return make_json_response(True, "SAFE")

@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_errors(e):
    return make_json_response(False, "INVALID_SCHEMA")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
