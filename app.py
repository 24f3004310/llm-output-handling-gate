import re
import html
import urllib.parse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"cdn-pu2jnx6.example", "app-13mshmo.example"}
ALLOWED_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

DANGEROUS_SCHEME_REGEX = re.compile(r"(javascript|data|vbscript)\s*:", re.IGNORECASE)
SCRIPT_TAG_REGEX = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)
EVENT_HANDLER_REGEX = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
UNICODE_ESCAPE_REGEX = re.compile(r"\\u([0-9a-fA-F]{4})")

SQL_METACHAR_REGEX = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE)
SHELL_METACHAR_REGEX = re.compile(r"[;&|`<>]|\$\(|\$\{")

def decode_output(text: str) -> str:
    # 1. Percent-escapes
    try:
        decoded = urllib.parse.unquote(text)
    except Exception:
        decoded = text

    # 2. HTML entities
    decoded = html.unescape(decoded)

    # 3. Unicode escapes (\uXXXX)
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

    # Protocol-relative URLs resolution (e.g. //attacker.example/path)
    if url_str.startswith("//"):
        url_str = "https:" + url_str

    parsed = urllib.parse.urlparse(url_str)

    # Relative paths like /local/path are allowed
    if not parsed.scheme and not parsed.netloc:
        return None

    # Scheme check
    if parsed.scheme.lower() not in ["http", "https"]:
        return "DANGEROUS_SCHEME"

    # Strict Hostname Validation (Ignoring credentials/query strings)
    hostname = parsed.hostname
    if hostname is None or hostname.lower() not in ALLOWED_HOSTS:
        return "EXTERNAL_EXFIL"

    return None

def check_channel_rules(channel: str, output: str):
    # Rule: DANGEROUS_SCHEME check for text
    if channel in ["html", "markdown", "url"]:
        if DANGEROUS_SCHEME_REGEX.search(output):
            return "DANGEROUS_SCHEME"

    # HTML Channel
    if channel == "html":
        if SCRIPT_TAG_REGEX.search(output):
            return "SCRIPT_TAG"
        if EVENT_HANDLER_REGEX.search(output):
            return "EVENT_HANDLER"

        # Extract URLs from src="..." and href="..."
        urls = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', output, re.IGNORECASE)
        for u in urls:
            res = parse_and_validate_url(u)
            if res:
                return res

    # Markdown Channel
    elif channel == "markdown":
        # Extract URLs from ](...)
        urls = re.findall(r'\]\(([^)]+)\)', output)
        for u in urls:
            # Handle markdown image/link optional title wrappers
            clean_url = u.strip().split()[0] if u.strip() else ""
            res = parse_and_validate_url(clean_url)
            if res:
                return res

    # URL Channel
    elif channel == "url":
        res = parse_and_validate_url(output)
        if res:
            return res

    # SQL Channel
    elif channel == "sql":
        if SQL_METACHAR_REGEX.search(output):
            return "SQL_METACHAR"

    # Shell Channel
    elif channel == "shell":
        if SHELL_METACHAR_REGEX.search(output):
            return "SHELL_METACHAR"

    return None

@app.route('/sanitize-output', methods=['POST'])
def sanitize_output():
    data = request.get_json(silent=True)

    # 1. INVALID_SCHEMA Validation
    if not isinstance(data, dict):
        return jsonify({"safe": False, "reason": "INVALID_SCHEMA"})

    channel = data.get("channel")
    output = data.get("output")

    if channel not in ALLOWED_CHANNELS or not isinstance(output, str) or len(output) > 20000:
        return jsonify({"safe": False, "reason": "INVALID_SCHEMA"})

    # 2. ENCODED_PAYLOAD Obfuscation Check
    decoded = decode_output(output)
    if decoded != output:
        decoded_violation = check_channel_rules(channel, decoded)
        if decoded_violation is not None:
            return jsonify({"safe": False, "reason": "ENCODED_PAYLOAD"})

    # 3. Raw Output Validation
    violation = check_channel_rules(channel, output)
    if violation is not None:
        return jsonify({"safe": False, "reason": violation})

    return jsonify({"safe": True, "reason": "SAFE"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)