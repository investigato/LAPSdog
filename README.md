# LAPSdog

Decrypt Windows LAPS passwords from LDAP using DPAPI-NG.

## What This Does

Windows LAPS stores encrypted passwords in LDAP attributes. This tool connects to your domain controller, finds the computer objects, and decrypts those passwords using DPAPI-NG. It works with Kerberos authentication (from your environment) or NTLM with explicit credentials.

## Requirements

You need:

- Python 3.11+
- Credentials:
  - A Kerberos ticket (KRB5CCNAME environment variable)
  - Or username/password for NTLM
- LDAP read permissions for the LAPS attributes on the computer objects you want to decrypt
- The `dpapi-ng[kerberos]` package installed

## Installation

```bash
uv sync
```

This installs everything you need including `dpapi-ng`, `ldap3`, and `gssapi`.

## Usage

### With Kerberos (Recommended)

Set your Kerberos cache and run:

```bash
export KRB5CCNAME=/path/to/your/cache.ccache
python main.py --dc dc01.domain.com -b "OU=Computers,DC=domain,DC=com" -t COMPUTER-NAME
```

### With NTLM Credentials

If you don't have Kerberos tickets:

```bash
puv run main.py --dc dc01.domain.com -b "OU=Computers,DC=domain,DC=com" -t COMPUTER-NAME -u DOMAIN\\user -p password
```

### Search All Computers

Omit the `-t` flag to decrypt passwords for all computers in the search base:

```bash
uv run main.py --dc dc01.domain.com -b "OU=Computers,DC=domain,DC=com"
```

## Options

- `--dc` - Domain controller FQDN (required)
- `-b, --base` - LDAP search base DN (required)
- `-t, --target` - Computer name to decrypt passwords for (optional, searches all if omitted)
- `-u, --user` - Username for NTLM fallback (accepts `DOMAIN\user`, `user@DOMAIN`, or `user`)
- `-p, --pass` - Password for NTLM fallback
- `--debug` - Enable debug output
- `-v, --verbose-spnego` - Show SPNEGO negotiation details (especially useful if you're having trouble getting Kerberos to work)

## Output

Results come back as JSON with password data including:

- `n` - Username for the password
- `p` - The actual password
- `t` - Hex timestamp when password was set (Windows File Time format)
- `t_iso` - Actually readable timestamp in ISO format

Example:

```json
[
  {
    "attr": "msLAPS-EncryptedPassword",
    "index": 0,
    "password": {
      "n": "lab-admin",
      "p": "SomeComplexPassword123!",
      "t": "1dc476f4ee3619a",
      "t_iso": "2024-01-15T14:23:45"
    },
    "computer_dn": "CN=SERVER-01,OU=Servers,DC=domain,DC=com"
  }
]
```

## Why This Exists

LDAP administrators and security folks need to decrypt LAPS passwords sometimes. The Microsoft tools are fine but they're Windows-only. This gives you a Python script that works wherever you need it, assuming you have the right permissions and credentials.

