"""TLS fingerprint computation (JA3-like).

Computes a JA3-like fingerprint from the client's SSL context
cipher suite preferences and extensions.
"""

import hashlib
import ssl


def compute_ja3_fingerprint(context: ssl.SSLContext = None) -> str:
    """Compute a JA3-like TLS fingerprint.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)

    Since we're using Python's ssl module (not raw sockets), we
    approximate the fingerprint using the available cipher list.

    Returns:
        12-character hex fingerprint string
    """
    if context is None:
        context = ssl.create_default_context()

    # Get supported cipher suites
    ciphers = context.get_ciphers()
    cipher_names = sorted([c["name"] for c in ciphers])

    # Build JA3-like raw string
    # Try to detect actual max TLS version from context
    try:
        tls_version = "771" if context.maximum_version in (ssl.TLSVersion.TLSv1_3, None) else "770"
    except Exception:
        tls_version = "771"
    cipher_str = "-".join(cipher_names[:50])
    extensions = "0-10-11-13-16-23-43-45-51"
    curves = "29-23-24-25-30"
    point_formats = "0"

    ja3_raw = f"{tls_version},{cipher_str},{extensions},{curves},{point_formats}"

    # MD5 hash
    ja3_hash = hashlib.md5(ja3_raw.encode()).hexdigest()
    return ja3_hash[:12]
