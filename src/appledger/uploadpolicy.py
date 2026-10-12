"""Which files may leave the computer in a hosted check.

Secret-bearing files (environment files, private keys, certificates, local tool settings) are
never uploaded, whatever .gitignore says. The client uses this to build the upload; the
service uses it again when unpacking, so a file that slips through is still never scanned or kept.
"""

from fnmatch import fnmatch
from pathlib import PurePosixPath

# Example and template env files hold placeholders, not secrets, and are useful to scan.
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"}

SECRET_NAME_PATTERNS = (
    ".env", ".env.*", "*.env",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.p8", "*.ppk", "*.kdbx",
    "id_rsa", "id_rsa.*", "id_dsa", "id_dsa.*", "id_ecdsa", "id_ecdsa.*", "id_ed25519", "id_ed25519.*",
    ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".htpasswd",
    "*credentials*.json", "service-account*.json", "*serviceaccount*.json",
    "secrets.y*ml", "secrets.json", "secrets.toml", ".secrets*",
    "terraform.tfstate", "terraform.tfstate.*", "*.tfvars",
    ".vault_pass*", "vault_pass*", "vault-password*", "*.passwd", "*.password", "*.pass", ".pgpass", "pgpass",
)
# Names that often, but not always, hold secrets: Ansible Vault files (encrypted, and kept in git by
# design), Kubernetes/Helm secret manifests (often only templates) and certificates (public). They are
# never uploaded, but having them in git isn't reported as a leak.
CAUTION_NAME_PATTERNS = (
    "vault.y*ml", "*-vault.y*ml", "*_vault.y*ml", "*.vault", "*secret*.y*ml",
    "*.crt", "*.cer", "*.der",
)
# Harmless helper files that often sit in secret folders (cert/, secrets/): fine to upload.
HELPER_NAMES = {".gitignore", ".gitkeep", ".keep", "readme", "readme.md", "readme.txt"}
SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".azure", ".kube", "cert", "certs", "secrets", ".secrets"}
SECRET_PATHS = (".claude/settings.local.json", ".docker/config.json", ".config/gcloud/*")


def is_secret_path(rel_path: str) -> bool:
    """True if a project-relative path (forward slashes) must never be uploaded."""
    path = PurePosixPath(rel_path)
    name = path.name.lower()
    if name in ENV_TEMPLATES or name in HELPER_NAMES or name.endswith(".pub"):
        return False
    if any(part.lower() in SECRET_DIRS for part in path.parts[:-1]):
        return True
    if any(fnmatch(name, pattern) for pattern in SECRET_NAME_PATTERNS + CAUTION_NAME_PATTERNS):
        return True
    posix = path.as_posix().lower()
    return any(fnmatch(posix, pattern) or posix.endswith("/" + pattern) for pattern in SECRET_PATHS)


def is_caution_only(rel_path: str) -> bool:
    """Never uploaded, but not reported as a leak when git tracks it (see CAUTION_NAME_PATTERNS)."""
    path = PurePosixPath(rel_path)
    name = path.name.lower()
    if any(part.lower() in SECRET_DIRS for part in path.parts[:-1]) and \
            any(fnmatch(name, p) for p in SECRET_NAME_PATTERNS):
        return False
    return any(fnmatch(name, p) for p in CAUTION_NAME_PATTERNS) and \
        not any(fnmatch(name, p) for p in SECRET_NAME_PATTERNS)


def peek(path, size=4096):
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except OSError:
        return b""


def is_encrypted_vault(path):
    """An Ansible Vault file, whatever its name. Reads only the first bytes, on this computer."""
    return peek(path, 16).startswith(b"$ANSIBLE_VAULT")


def holds_public_key_only(path):
    """A key or certificate file that contains only public material (a certificate, a public key).

    Such files are still never uploaded, but committing them isn't a leak, so no finding is raised.
    Binary keystores (.jks, .p12, .pfx) can't be told apart cheaply and count as private.
    """
    head = peek(path)
    if not head or b"PRIVATE KEY" in head or head.startswith(b"$ANSIBLE_VAULT"):
        return False
    return (b"PUBLIC KEY" in head or b"BEGIN CERTIFICATE" in head
            or head.startswith((b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-")))
