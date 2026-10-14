import base64
import fcntl
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from openai import OpenAI
from openai.types.responses import ResponseOutputItem

ISSUER = "https://auth.openai.com"
TOKEN_URL = f"{ISSUER}/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
AUTH_DIR = Path(__file__).resolve().parent / ".chatgpt-auth"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"

# --- Console


def grey(text: str) -> str:
    return f"\033[90m{text}\033[0m"


def green(text: str) -> str:
    return f"\033[32m{text}\033[0m"


def red(text: str) -> str:
    return f"\033[31m{text}\033[0m"


# --- Auth


def _save_credentials(path: Path, credentials: dict) -> None:
    """Atomically save credentials with owner-only permissions."""
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(credentials, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _exchange_tokens(data: dict) -> dict:
    response = httpx.post(TOKEN_URL, data=data, timeout=30)
    if not response.is_success:
        # Do not include the response body or credentials in exceptions.
        raise RuntimeError(
            f"ChatGPT token exchange failed (HTTP {response.status_code})."
        )
    tokens = response.json()
    if not tokens.get("access_token") or not tokens.get("refresh_token"):
        raise RuntimeError(
            "ChatGPT did not return the required access and refresh tokens."
        )
    if "chatgpt.tokens.use.direct" not in tokens.get("scope", "").split():
        raise RuntimeError(
            "ChatGPT plan usage was not granted. Sign in and allow plan usage."
        )
    tokens["expires_at"] = time.time() + float(tokens["expires_in"])
    return tokens


def _verify_identity(id_token: str, client_id: str, nonce: str | None = None) -> dict:
    keys = jwt.PyJWKClient(f"{ISSUER}/.well-known/jwks.json", timeout=30)
    key = keys.get_signing_key_from_jwt(id_token)
    identity = jwt.decode(
        id_token,
        key.key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=ISSUER,
        leeway=5,
        options={"require": ["sub", "exp", "iat"]},
    )
    if not isinstance(identity["sub"], str) or not identity["sub"]:
        raise RuntimeError("ChatGPT ID token has no account identity.")
    if nonce is not None and identity.get("nonce") != nonce:
        raise RuntimeError("ChatGPT ID token nonce did not match.")
    return identity


def _browser_sign_in(credentials: dict, path: Path, timeout: float) -> dict:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    callback = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Callback URLs contain authorization codes.

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path != "/auth/callback":
                self.send_error(404)
                return
            query = parse_qs(parsed.query)
            if len(query.get("state", [])) != 1 or not secrets.compare_digest(
                query["state"][0], state
            ):
                self.send_error(400, "Invalid sign-in state")
                return
            callback.update(query)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"Sign-in received. Return to the terminal to finish.")

    # An ephemeral port avoids collisions with other local apps.
    with HTTPServer(("127.0.0.1", 0), CallbackHandler) as server:
        redirect_uri = f"http://127.0.0.1:{server.server_port}/auth/callback"
        server.timeout = 1
        params = {
            "client_id": credentials.get("client_id", "dynamic_agent_client"),
            "ext_agent_host_id": credentials["ext_agent_host_id"],
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": SCOPES,
            "resource": RESOURCE,
            "state": state,
            "nonce": nonce,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
        }
        if "client_id" not in credentials:
            params["agent_name_hint"] = "Agent POC"
        elif credentials.get("id_token"):
            params["id_token_hint"] = credentials["id_token"]
        print("Continue with ChatGPT in your browser and allow ChatGPT plan usage.")
        if not webbrowser.open(f"{ISSUER}/api/accounts/authorize?{urlencode(params)}"):
            raise RuntimeError("Could not open a browser for ChatGPT sign-in.")
        deadline = time.monotonic() + timeout
        while not callback:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "ChatGPT sign-in timed out. Run the program again to retry."
                )
            server.handle_request()

    if "error" in callback:
        raise RuntimeError("ChatGPT sign-in was declined or failed.")
    if len(callback.get("code", [])) != 1:
        raise RuntimeError("ChatGPT callback did not contain one authorization code.")
    issued_ids = callback.get("client_id", [])
    if len(issued_ids) > 1:
        raise RuntimeError("ChatGPT callback contained multiple client IDs.")
    client_id = issued_ids[0] if issued_ids else credentials.get("client_id")
    if not client_id or client_id == "dynamic_agent_client":
        raise RuntimeError("ChatGPT registration did not return an issued client ID.")
    if credentials.get("client_id") and credentials["client_id"] != client_id:
        raise RuntimeError(
            "ChatGPT callback client ID did not match the saved registration."
        )
    credentials["client_id"] = client_id
    _save_credentials(
        path, credentials
    )  # Preserve registration even if the code expires.
    tokens = _exchange_tokens(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": callback["code"][0],
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "resource": RESOURCE,
        }
    )
    identity = _verify_identity(tokens["id_token"], client_id, nonce)
    if credentials.get("subject") and credentials["subject"] != identity["sub"]:
        raise RuntimeError(
            "ChatGPT signed in to a different account than the saved registration."
        )
    return {
        **credentials,
        **tokens,
        "subject": identity["sub"],
        "email": identity.get("email"),
    }


def auth(
    *, force_login: bool = False, auth_dir: Path = AUTH_DIR, timeout: float = 300
) -> str:
    """Return a ChatGPT-plan access token, signing in or refreshing as needed.

    Requires an eligible ChatGPT plan. Credentials stay in a gitignored local
    directory. Call again before subsequent API requests to refresh expired tokens.
    Set force_login=True to repeat browser consent for the saved registration.
    """
    auth_dir = Path(auth_dir)
    auth_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    auth_dir.chmod(0o700)
    path = auth_dir / "credentials.json"
    # Serialize sign-in and refresh across local processes (refresh tokens rotate).
    lock_fd = os.open(auth_dir / "auth.lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        credentials = json.loads(path.read_text()) if path.exists() else {}
        if "ext_agent_host_id" not in credentials:
            credentials["ext_agent_host_id"] = f"urn:uuid:{uuid.uuid4()}"
            _save_credentials(path, credentials)
        has_permission = (
            "chatgpt.tokens.use.direct" in credentials.get("scope", "").split()
        )
        if not force_login and has_permission and credentials.get("access_token"):
            if credentials.get("expires_at", 0) > time.time() + 60:
                return credentials["access_token"]
            if credentials.get("refresh_token"):
                tokens = _exchange_tokens(
                    {
                        "grant_type": "refresh_token",
                        "client_id": credentials["client_id"],
                        "refresh_token": credentials["refresh_token"],
                        "resource": RESOURCE,
                    }
                )
                if tokens.get("id_token"):
                    identity = _verify_identity(
                        tokens["id_token"], credentials["client_id"]
                    )
                    if identity["sub"] != credentials["subject"]:
                        raise RuntimeError(
                            "Refreshed ChatGPT identity did not match the saved account."
                        )
                credentials.update(tokens)
                _save_credentials(path, credentials)
                return credentials["access_token"]
        credentials = _browser_sign_in(credentials, path, timeout)
        _save_credentials(path, credentials)
        return credentials["access_token"]


# --- Tools


def read_file(path: str) -> str:
    print(f"📖 Read({path})")
    with open(path, "r") as f:
        return f.read()


def list_files(path: str | None = None) -> list[str]:
    """List files and directories at a path, defaulting to the current directory."""
    print(f"📂 List({path or '.'})")
    directory = Path(path) if path is not None else Path.cwd()
    return [
        entry.name + ("/" if entry.is_dir() else "")
        for entry in sorted(directory.iterdir(), key=lambda entry: entry.name)
    ]


def code_search_tool(
    pattern: str,
    path: str | None = None,
    file_type: str | None = None,
    case_sensitive: bool = False,
) -> str:
    """Search with ripgrep, optionally limiting path, extension, and case."""
    search_path = path or "."
    command = ["rg", "--line-number", "--no-heading"]
    command.append("--case-sensitive" if case_sensitive else "--ignore-case")
    if file_type:
        extension = file_type.lstrip(".")
        if not extension:
            raise ValueError("file_type must contain a file extension")
        command.extend(["--glob", f"*.{extension}"])
    # Invoke rg directly rather than through a shell.  Besides avoiding shell
    # interpretation of patterns, ``--`` allows searches for patterns beginning
    # with a dash.  rg's exit status of 1 (no matches) is a normal result.
    command.extend(["--", pattern, search_path])
    print(
        f"🔎 Search({pattern}, {search_path}"
        f"{', ' + file_type if file_type else ''}"
        f"{', case-sensitive' if case_sensitive else ''})"
    )
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout


def edit_tool(path: str, old_str: str, new_str: str) -> str:
    """Replace a unique exact match, or append/create when old_str is empty."""
    print(f"✏️ Edit({path})")
    if not path or old_str == new_str:
        raise ValueError("invalid input parameters")

    file_path = Path(path)
    try:
        with file_path.open("r", encoding="utf-8", newline="") as file:
            content = file.read()
    except FileNotFoundError:
        if old_str:
            raise
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("w", encoding="utf-8", newline="") as file:
            file.write(new_str)
        return f"Successfully created file {path}"

    if old_str:
        count = content.count(old_str)
        if count == 0:
            raise ValueError("old_str not found in file")
        if count > 1:
            raise ValueError(f"old_str found {count} times in file, must be unique")
        content = content.replace(old_str, new_str, 1)
    else:
        content += new_str

    with file_path.open("w", encoding="utf-8", newline="") as file:
        file.write(content)
    return "OK"


def bash_tool(command: str) -> str:
    """Execute a bash command and return its combined stdout and stderr."""
    print(f"💻 Bash({command})")
    result = subprocess.run(
        ["bash", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout


tool_registry = {
    ("files", "read_file"): read_file,
    ("files", "list_files"): list_files,
    ("files", "code_search_tool"): code_search_tool,
    ("files", "edit_tool"): edit_tool,
    ("shell", "bash_tool"): bash_tool,
}


def get_tools() -> list[dict]:
    return [
        {
            "type": "namespace",
            "name": "files",
            "description": "Tools for working with files.",
            "tools": [
                {
                    "type": "function",
                    "name": "read_file",
                    "description": "Read the contents of a given relative file path. Use this when you want to see what's inside a file. Do not use this with directory names.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to a file.",
                            }
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
                {
                    "type": "function",
                    "name": "list_files",
                    "description": "List files and directories at a given path. If no path is provided, lists files in the current directory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": ["string", "null"],
                                "description": "Path to a directory. Use null for the current directory.",
                            }
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
                {
                    "type": "function",
                    "name": "code_search_tool",
                    "description": "Search the current project or an optional file/directory for a code pattern or regex using ripgrep. Use this tool whenever you need to search code; do not use shell commands for code searches.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "The search pattern or regex to look for.",
                            },
                            "path": {
                                "type": ["string", "null"],
                                "description": "Optional path to search in (file or directory).",
                            },
                            "file_type": {
                                "type": ["string", "null"],
                                "description": "Optional file extension to limit search to (e.g., 'go', 'js', 'py').",
                            },
                            "case_sensitive": {
                                "type": "boolean",
                                "description": "Whether the search should be case sensitive (default: false).",
                            },
                        },
                        "required": ["pattern", "path", "file_type", "case_sensitive"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
                {
                    "type": "function",
                    "name": "edit_tool",
                    "description": "Edit a text file by replacing one unique exact match of old_str with new_str. The strings must differ. Use an empty old_str to append to an existing file or create a missing file and its parent directories.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file.",
                            },
                            "old_str": {
                                "type": "string",
                                "description": "Exact text to replace; must occur exactly once. Use an empty string to append or create.",
                            },
                            "new_str": {
                                "type": "string",
                                "description": "Replacement text, or text to append or create.",
                            },
                        },
                        "required": ["path", "old_str", "new_str"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                },
            ],
        },
        {
            "type": "namespace",
            "name": "shell",
            "description": "Tools for running shell commands.",
            "tools": [
                {
                    "type": "function",
                    "name": "bash_tool",
                    "description": "Execute a bash command and return its output. Use this to run shell commands.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The bash command to execute.",
                            }
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                }
            ],
        },
    ]


# --- Loop


def run_inference(
    llm: OpenAI,
    conversation: list,
    tools: list[dict],
    *,
    model: str = "gpt-5.6-luna",
) -> list[ResponseOutputItem]:
    """Stream one model response and return its completed output items in order.

    Prints text as it arrives. The caller appends the returned items to history
    and handles any function calls; this function does not modify conversation.
    """
    completed = False
    output_items = {}
    with llm.responses.create(
        model=model,
        input=conversation,
        tools=tools,
        store=False,
        stream=True,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="", flush=True)
            elif event.type == "response.output_item.done":
                output_items[event.output_index] = event.item
            elif event.type == "response.completed":
                completed = True
            elif event.type == "response.failed":
                raise RuntimeError(event.response.error)
            elif event.type == "response.incomplete":
                raise RuntimeError("The model response was incomplete.")
            elif event.type == "error":
                raise RuntimeError(event.message)
    print()

    if not completed:
        raise RuntimeError("The stream ended without a completed response")

    return [output_items[i] for i in sorted(output_items)]


def main():
    llm = OpenAI(api_key=auth())
    tools = get_tools()
    conversation = []

    print(grey(llm))
    print(grey("ChatGPT plan connected."))

    while True:
        try:
            user_input = input("> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user_input.strip():
            continue
        conversation.append({"role": "user", "content": user_input})

        while True:
            # print(grey(conversation))
            llm.api_key = auth()
            output_items = run_inference(llm, conversation, tools)
            conversation.extend(output_items)

            calls = [i for i in output_items if i.type == "function_call"]
            if not calls:
                break

            for call in calls:
                try:
                    args = json.loads(call.arguments)
                    func = tool_registry[(call.namespace, call.name)]
                    result = func(**args)
                    output = json.dumps({"result": result})
                except Exception as e:
                    output = json.dumps({"error": str(e)})

                print()
                conversation.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": output,
                    }
                )


if __name__ == "__main__":
    main()
