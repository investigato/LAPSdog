#!/usr/bin/env python3

import argparse
import json
import logging
import os
from datetime import datetime

import dpapi_ng
from ldap3 import ALL, NTLM, SASL, Connection, Server

logging.basicConfig(level=logging.INFO, format="%(message)s")

TARGET_ATTRIBUTES = [
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-Password",
    "msLAPS-EncryptedDSRMPassword",
    "msLAPS-EncryptedDSRMPasswordHistory",
]


def create_kerberos_connection(domain_controller):
    """
    Attempt to connect to LDAP using Kerberos authentication.
    Returns connection object on success, None on failure.
    """
    server = Server(domain_controller, get_info=ALL)
    try:
        connection = Connection(
            server, authentication=SASL, sasl_mechanism="GSSAPI", auto_bind=True
        )
        logging.info("[*] Kerberos authentication successful")
        return connection
    except Exception as error:
        logging.debug(f"Kerberos authentication failed: {error}")
        return None


def create_ntlm_connection(domain_controller, username, password):
    """
    Connect to LDAP using NTLM authentication with provided credentials.
    Username is normalized to DOMAIN\\user format required by NTLM.
    """
    normalized_username = normalize_username_for_ntlm(username)

    server = Server(domain_controller, get_info=ALL)
    connection = Connection(
        server,
        user=normalized_username,
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )
    logging.info("[*] NTLM authentication successful")
    return connection


def normalize_username_for_ntlm(username):
    """
    NTLM needs DOMAIN\\user format. This function handles whatever gets entered and converts it to what NTLM wants.
    """
    if "\\" in username:
        return username

    if "@" in username:
        user, domain = username.rsplit("@", 1)
        return f"{domain}\\{user}"

    return username


def get_computer_entries(ldap_connection, search_base, computer_name=None):
    if computer_name:
        search_filter = f"(&(objectClass=computer)(cn={computer_name}))"
    else:
        search_filter = "(objectClass=computer)"

    search_successful = ldap_connection.search(
        search_base=search_base,
        search_filter=search_filter,
        attributes=TARGET_ATTRIBUTES,
    )

    if not search_successful:
        search_description = (
            f"computer '{computer_name}'" if computer_name else "any computers"
        )
        raise SystemExit(f"[!] No {search_description} found in LDAP")

    return ldap_connection.entries


def strip_ldap_header(encrypted_blob):
    """
    LAPS v2 stores encrypted passwords with a 16-byte proprietary header
    followed by the actual DPAPI-NG encrypted blob. It's not needed for this.
    If you want details, keep reading. If not, just skip to the next function.
    Detailed: The first 16 bytes are used as a “prefix”.
    The fields in this prefix are:
    - Upper Date Time Stamp (4 bytes)
    - Lower Date Time Stamp (4 bytes)
    - Encrypted Buffer Size (4 bytes)
    - Flags (4 bytes)
    Reference: https://blog.xpnsec.com/lapsv2-internals/
    """
    if len(encrypted_blob) <= 16:
        return encrypted_blob

    if encrypted_blob[16] == 0x30:
        logging.debug("[*] Chucking the LAPS header, passing through the real blob")
        return encrypted_blob[16:]

    return encrypted_blob


def attempt_decryption_with_kerberos_context(encrypted_blob, domain_controller):
    """
    Attempt to decrypt using Kerberos credentials from the environment.
    The dpapi_ng library will automatically use KRB5CCNAME if available.
    """
    try:
        decrypted_data = dpapi_ng.ncrypt_unprotect_secret(
            encrypted_blob, server=domain_controller
        )
        return decrypted_data.decode("utf-16-le", errors="ignore").strip("\x00")
    except Exception as error:
        logging.debug(f"Kerberos-based decryption failed: {error}")
        return None


def attempt_decryption_with_explicit_credentials(
    encrypted_blob, domain_controller, username, password
):
    """
    Attempt to decrypt using explicitly provided credentials.
    LAPS returns UTF-16LE encoded JSON because of course it does.
    """
    try:
        decrypted_data = dpapi_ng.ncrypt_unprotect_secret(
            encrypted_blob,
            server=domain_controller,
            username=username,
            password=password,
            auth_protocol="negotiate",
        )
        return decrypted_data.decode("utf-16-le", errors="ignore").strip("\x00")
    except Exception as error:
        logging.debug(f"Credential-based decryption failed: {error}")
        return None


def decrypt_laps_password(
    encrypted_blob, domain_controller, username=None, password=None
):
    """
    Decrypt a LAPS-encrypted password blob using either Kerberos context
    from the environment or explicit credentials as fallback.
    """
    processed_blob = strip_ldap_header(encrypted_blob)

    decrypted = attempt_decryption_with_kerberos_context(
        processed_blob, domain_controller
    )

    if decrypted is not None:
        return decrypted

    if username and password:
        decrypted = attempt_decryption_with_explicit_credentials(
            processed_blob, domain_controller, username, password
        )

    return decrypted


def convert_windows_filetime_from_hex(hex_timestamp_string):
    """
    The "t" field in LAPS passwords is a hex string of Windows File Time.
    Same weird format - 100-nanosecond intervals since 1601.
    Convert hex string to sane ISO timestamp.
    """
    try:
        windows_time = int(hex_timestamp_string, 16)
        seconds_between_epochs = 11644473600
        unix_timestamp = (windows_time / 10_000_000) - seconds_between_epochs
        return datetime.fromtimestamp(unix_timestamp).isoformat()
    except (ValueError, OSError):
        return hex_timestamp_string


def make_timestamp_readable(decrypted_password_json):
    """
    The decrypted LAPS password JSON has a "t" field with a hex timestamp in Windows File Time.
    Since that's just silly, we will make it readable by converting it to ISO format and adding a "t_iso" field.
    """
    try:
        password_data = json.loads(decrypted_password_json)

        if "t" in password_data:
            hex_timestamp = password_data["t"]
            password_data["t_iso"] = convert_windows_filetime_from_hex(hex_timestamp)

        return password_data
    except json.JSONDecodeError:
        return decrypted_password_json


def configure_logging(enable_debug, verbose_spnego):
    """
    Configure logging levels for the application and third-party libraries.
    """
    if enable_debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        if not verbose_spnego:
            logging.getLogger("spnego").setLevel(logging.WARNING)
            logging.getLogger("gssapi").setLevel(logging.WARNING)


def check_kerberos_config(username=None, password=None):
    """
    Report the current Kerberos environment configuration for troubleshooting.
    If credentials are provided, we'll use NTLM.
    """
    using_ntlm = username and password

    if not using_ntlm:
        kerb_cache = os.environ.get("KRB5CCNAME")
        kerb_config = os.environ.get("KRB5_CONFIG")
        working_directory = os.getcwd()

        logging.info(f"[*] KRB5CCNAME: {kerb_cache if kerb_cache else '(not set)'}")
        logging.info(f"[*] KRB5_CONFIG: {kerb_config if kerb_config else '(not set)'}")
        logging.info(f"[*] Working directory: {working_directory}")

        if not kerb_cache:
            logging.warning(
                "[!] KRB5CCNAME is not set! Kerberos authentication may fail."
            )
            logging.info("[!] Set it with: export KRB5CCNAME=/path/to/ccache")


def create_ldap_connection(domain_controller, username=None, password=None):
    """
    Create an LDAP connection. If username and password are provided, use NTLM.
    Otherwise try Kerberos first.
    """
    if username and password:
        return create_ntlm_connection(domain_controller, username, password)

    connection = create_kerberos_connection(domain_controller)

    if connection is not None:
        return connection

    raise SystemExit(
        "[!] Failed to authenticate (Kerberos failed and no credentials provided)"
    )


def decrypt_attributes_from_entry(
    entry, domain_controller, username=None, password=None
):
    """
    Iterate through target attributes on an LDAP entry and attempt to decrypt
    or convert any binary values found.
    """
    results = []

    for attribute_name in TARGET_ATTRIBUTES:
        if attribute_name not in entry.entry_attributes:
            logging.debug(f"[*] Attribute {attribute_name} not found on entry")
            continue

        attribute_values = entry[attribute_name].raw_values

        for index, value in enumerate(attribute_values):
            if not isinstance(value, (bytes, bytearray)):
                continue

            decrypted_password = decrypt_laps_password(
                value, domain_controller, username, password
            )

            if decrypted_password is not None:
                enhanced_password_data = make_timestamp_readable(decrypted_password)

                result_entry = {
                    "attr": attribute_name,
                    "index": index,
                }

                if isinstance(enhanced_password_data, dict):
                    result_entry["password"] = enhanced_password_data
                else:
                    result_entry["plaintext"] = enhanced_password_data

                results.append(result_entry)
                logging.info(f"[+] Successfully decrypted {attribute_name}[{index}]")
            else:
                logging.info(
                    f"[-] Failed to decrypt {attribute_name}[{index}] (run with --debug for details)"
                )

    return results


def main():
    argument_parser = argparse.ArgumentParser(
        description="Decrypt Windows LAPS passwords using DPAPI-NG"
    )
    argument_parser.add_argument("--dc", required=True, help="Domain controller FQDN")
    argument_parser.add_argument(
        "-b", "--base", required=True, help="LDAP search base DN"
    )
    argument_parser.add_argument(
        "-t",
        "--target",
        help="Computer name to decrypt passwords for (if not specified, searches all computers)",
    )
    argument_parser.add_argument(
        "-u",
        "--user",
        help="Username (accepts DOMAIN\\user, user@DOMAIN, or user format)",
    )
    argument_parser.add_argument(
        "-p", "--pass", dest="password", help="Fallback password"
    )
    argument_parser.add_argument(
        "--debug", action="store_true", help="Enable debug output"
    )
    argument_parser.add_argument(
        "-v",
        "--verbose-spnego",
        action="store_true",
        help="Show SPNEGO negotiation details",
    )

    arguments = argument_parser.parse_args()

    configure_logging(arguments.debug, arguments.verbose_spnego)
    check_kerberos_config(arguments.user, arguments.password)

    ldap_connection = create_ldap_connection(
        arguments.dc, arguments.user, arguments.password
    )

    computer_entries = get_computer_entries(
        ldap_connection, arguments.base, arguments.target
    )

    if arguments.target:
        logging.info(
            f"[*] Found {len(computer_entries)} computer(s) matching '{arguments.target}'"
        )
    else:
        logging.info(f"[*] Found {len(computer_entries)} computer(s) in search base")

    all_decryption_results = []

    for entry in computer_entries:
        logging.info(f"[*] Processing computer: {entry.entry_dn}")

        decryption_results = decrypt_attributes_from_entry(
            entry, arguments.dc, arguments.user, arguments.password
        )

        if decryption_results:
            for result in decryption_results:
                result["computer_dn"] = str(entry.entry_dn)
                all_decryption_results.append(result)

    if not all_decryption_results:
        logging.info(
            "[!] No passwords were successfully decrypted. Perhaps you should check your permissions or credentials"
        )
    else:
        print(json.dumps(all_decryption_results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
