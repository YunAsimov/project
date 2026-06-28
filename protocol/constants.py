"""Protocol-wide constants: version, algorithm identifiers, HKDF labels.

Keep these in one place so the report's protocol description and the code
stay in sync.
"""

PROTOCOL_VERSION = 1

# HKDF `info` label binds derived keys to this protocol/purpose.
HKDF_INFO_SESSION = b"comp5355-e2ee/session-key/v1"

# Message-type tags for the wire format (see protocol/messages.py).
MSG_REGISTER = "register"      # client -> server: username + identity pubkey
MSG_LOOKUP = "lookup"          # client -> server: request a peer's pubkey
MSG_LOOKUP_RESULT = "lookup_result"
MSG_HANDSHAKE_INIT = "hs_init"     # A -> B: ephemeral pubkey + signature
MSG_HANDSHAKE_RESP = "hs_resp"     # B -> A: ephemeral pubkey + signature
MSG_DATA = "data"              # encrypted application message
MSG_ERROR = "error"            # server -> client: control/diagnostic notice

# AEAD parameters
AEAD_KEY_LEN = 32
AEAD_NONCE_LEN = 12

# Replay protection
REPLAY_WINDOW_SIZE = 64
