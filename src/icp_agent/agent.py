import hashlib
import time
import asyncio
import cbor2
import httpx
import leb128

from icp_candid import decode
from icp_certificate.certificate import IC_ROOT_KEY, Certificate
from icp_identity import DelegateIdentity
from icp_principal import Principal
from icp_candid.candid import encode

IC_REQUEST_DOMAIN_SEPARATOR = b"\x0Aic-request"

DEFAULT_POLL_TIMEOUT_SECS = 60.0

# Exponential backoff defaults
DEFAULT_INITIAL_DELAY = 0.5   # seconds
DEFAULT_MAX_INTERVAL  = 1.0   # seconds
DEFAULT_MULTIPLIER    = 1.4

NANOSECONDS = 1_000_000_000

def _safe_str(v):
    """Decode bytes-like to utf-8 safely for error messages."""
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("utf-8", "replace")
    return str(v)


def sign_request(req, iden):
    """
    Build and CBOR-encode an envelope for an IC request, signing the request_id with the identity.
    For delegated identities, include delegation and DER public key.
    """
    request_id = to_request_id(req)
    message = IC_REQUEST_DOMAIN_SEPARATOR + request_id
    der_pubkey, sig = iden.sign(message)
    envelope = {
        "content": req,
        "sender_pubkey": der_pubkey,
        "sender_sig": sig,
    }
    if isinstance(iden, DelegateIdentity):
        envelope.update({
            "sender_pubkey": iden.der_pubkey,
            "sender_delegation": iden.delegations,
        })
    return request_id, cbor2.dumps(envelope)


def to_request_id(d):
    if not isinstance(d, dict):
        raise TypeError("request must be a dict")

    vec = []
    for k, v in d.items():
        if isinstance(v, list):
            v = encode_list(v)
        if isinstance(v, int):
            v = bytes(leb128.u.encode(v))
        if not isinstance(k, bytes):
            k = k.encode()
        if not isinstance(v, bytes):
            v = v.encode()
        h_k = hashlib.sha256(k).digest()
        h_v = hashlib.sha256(v).digest()
        vec.append(h_k + h_v)
    s = b''.join(sorted(vec))
    return hashlib.sha256(s).digest()


def encode_list(l):
    """
    Canonical list hashing fragment used inside to_request_id:
    - For each element, turn into canonical bytes:
        list -> recursive encode_list
        int  -> ULEB128
        bytes/bytearray/memoryview -> raw bytes
        str  -> utf-8
        others -> CBOR as fallback to stay stable
    - Then sha256(each_item_bytes) and concatenate.
    """
    ret = b''
    for item in l:
        if isinstance(item, list):
            v = encode_list(item)
        elif isinstance(item, int):
            v = bytes(leb128.u.encode(item))
        elif isinstance(item, (bytes, bytearray, memoryview)):
            v = bytes(item)
        elif isinstance(item, str):
            v = item.encode("utf-8")
        else:
            # fallback for unexpected types to maintain determinism
            v = cbor2.dumps(item)
        ret += hashlib.sha256(v).digest()
    return ret


# Default ingress expiry in seconds
DEFAULT_INGRESS_EXPIRY_SEC = 3 * 60

class Agent:
    def __init__(self, identity, client, nonce_factory=None,
                 ingress_expiry=DEFAULT_INGRESS_EXPIRY_SEC, root_key=IC_ROOT_KEY):
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory

    def get_principal(self):
        return self.identity.sender()

    def get_expiry_date(self):
        """Return ingress expiry in nanoseconds since epoch."""
        return time.time_ns() + int(self.ingress_expiry * 1e9)

    # ----------- HTTP endpoints -----------

    def query_endpoint(self, canister_id, data):
        raw_bytes = self.client.query(canister_id, data)
        return cbor2.loads(raw_bytes)

    async def query_endpoint_async(self, canister_id, data):
        raw_bytes = await self.client.query_async(canister_id, data)
        return cbor2.loads(raw_bytes)

    def call_endpoint(self, canister_id, data):
        return self.client.call(canister_id, data)

    async def call_endpoint_async(self, canister_id, request_id, data):
        await self.client.call_async(canister_id, request_id, data)
        return request_id

    def read_state_endpoint(self, canister_id, data):
        return self.client.read_state(canister_id, data)

    async def read_state_endpoint_async(self, canister_id, data):
        return await self.client.read_state_async(canister_id, data)

    def _encode_arg(self, arg) -> bytes:
        """
        Normalize argument to DIDL bytes:
          - If arg is None: encode([]) (empty Candid)
          - If arg is bytes-like: return bytes(arg) directly
          - Otherwise: assume it's acceptable by `icp_candid.candid.encode`
            (e.g., [{'type': Types.Text, 'value': 'hello'}]) and encode it.
        """
        if arg is None:
            return encode([])
        if isinstance(arg, (bytes, bytearray, memoryview)):
            return bytes(arg)
        # Let candid.encode decide (common case: list of typed values)
        return encode(arg)

    # ----------- High-level (ergonomic) APIs -----------

    def query(
        self,
        canister_id,
        method_name: str,
        arg=None,
        *,
        return_type=None,
        effective_canister_id=None,
    ):
        """
        High-level query (one-shot, no polling):
          - `arg` can be:
              * None -> encodes to empty DIDL (encode([]))
              * bytes/bytearray/memoryview -> used as-is
              * anything else acceptable by `icp_candid.candid.encode`
                (e.g. [{'type': Types.Nat, 'value': 42}])
          - If `return_type` is provided and reply is DIDL, it will be decoded.
        """
        didl = self._encode_arg(arg)
        return self.query_raw(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
        )

    def update(
        self,
        canister_id,
        method_name: str,
        arg=None,
        *,
        return_type=None,
        effective_canister_id=None,
        verify_certificate: bool = True,
        initial_delay: float = None,
        max_interval: float = None,
        multiplier: float = None,
        timeout: float = None,
    ):
        """
        High-level `update` call (submit + poll to completion).

        This method provides a user-friendly interface similar to the Rust and TypeScript IC Agents.
        It automatically encodes arguments (if not already bytes) and polls until the call
        reaches a terminal state ("replied" or "rejected").

        Args:
            canister_id (str | Principal): Target canister ID.
            method_name (str): The method name to call on the canister.
            arg (Any, optional):
                - If None, encodes to empty DIDL (`encode([])`).
                - If bytes/bytearray/memoryview, used as-is.
                - Otherwise, passed to `icp_candid.candid.encode()` for automatic Candid encoding.
            return_type (Any, optional): Expected return type for Candid decoding.
            effective_canister_id (str | Principal, optional): Effective ID for routing if different.
            verify_certificate (bool): Whether to verify the certificate and timestamp on responses.
            initial_delay (float, optional): Initial polling delay (seconds).
            max_interval (float, optional): Maximum polling interval (seconds).
            multiplier (float, optional): Exponential backoff multiplier.
            timeout (float, optional): Maximum total polling duration (seconds).

        Returns:
            Decoded Candid data or raw bytes (if non-DIDL reply).

        Raises:
            RuntimeError: On malformed responses or canister rejection.
            TimeoutError: If polling exceeds timeout duration.
        """
        didl = self._encode_arg(arg)

        # Prepare the call request
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": (Principal.from_str(canister_id).bytes
                            if isinstance(canister_id, str) else canister_id.bytes),
            "method_name": method_name,
            "arg": didl,
            "ingress_expiry": self.get_expiry_date(),
        }
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        # Submit call
        http_response = self.call_endpoint(effective_id, signed_cbor)
        try:
            response_obj = cbor2.loads(http_response.content)
        except Exception:
            raise RuntimeError(f"Malformed update response (non-CBOR): {http_response.content!r}")

        if not isinstance(response_obj, dict) or "status" not in response_obj:
            raise RuntimeError("Malformed update response: " + repr(response_obj))

        status = response_obj.get("status")

        # Direct replied response
        if status == "replied":
            cbor_certificate = response_obj["certificate"]
            decoded_certificate = cbor2.loads(cbor_certificate)
            certificate = Certificate(decoded_certificate)

            if verify_certificate:
                certificate.assert_certificate_valid(effective_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            certified_status = certificate.lookup_request_status(request_id)
            if isinstance(certified_status, (bytes, bytearray, memoryview)):
                certified_status = bytes(certified_status).decode("utf-8", "replace")

            if certified_status == "replied":
                reply_data = certificate.lookup_reply(request_id)
                return decode(reply_data, return_type)
            if certified_status == "rejected":
                rejection = certificate.lookup_request_rejection(request_id)
                raise RuntimeError(
                    f"Call rejected (code={rejection['reject_code']}): "
                    f"{rejection['reject_message']} [error_code={rejection.get('error_code')}]"
                )
            # Certificate not yet final — fall through to polling.

        elif status == "non_replicated_rejection":
            code = response_obj.get("reject_code")
            message = response_obj.get("reject_message")
            error = response_obj.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")

        # Handle polling for completion
        poll_kwargs = {}
        if initial_delay is not None: poll_kwargs["initial_delay"] = initial_delay
        if max_interval  is not None: poll_kwargs["max_interval"]  = max_interval
        if multiplier    is not None: poll_kwargs["multiplier"]    = multiplier
        if timeout       is not None: poll_kwargs["timeout"]       = timeout

        status_str, result = self.poll(
            effective_id,
            request_id,
            verify_certificate,
            **poll_kwargs,
        )

        if status_str == "replied":
            return decode(result, return_type)
        if status_str == "rejected":
            code = result.get("reject_code")
            message = result.get("reject_message")
            error = result.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")

        raise RuntimeError(f"Unknown final status from poll: {status_str}")

    # ----------- Query (one-shot) -----------

    def query_raw(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = self.query_endpoint(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif status == "rejected":
            raise RuntimeError("Canister rejected the call: " + (_safe_str(result.get("reject_message")) or ""))
        else:
            raise RuntimeError("Unknown status: " + repr(status))

    async def query_raw_async(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = await self.query_endpoint_async(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif status == "rejected":
            raise RuntimeError("Canister rejected the call: " + (_safe_str(result.get("reject_message")) or ""))
        else:
            raise RuntimeError("Unknown status: " + repr(status))

    # ----------- Update (call + poll) -----------

    def update_raw(self, canister_id, method_name, arg, return_type=None,
                   effective_canister_id=None, verify_certificate: bool = False):
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        http_response: httpx.Response = self.call_endpoint(effective_id, signed_cbor)
        try:
            response_obj = cbor2.loads(http_response.content)
        except Exception:
            raise RuntimeError(f"Malformed update response (non-CBOR): {http_response.content!r}")

        if not isinstance(response_obj, dict) or "status" not in response_obj:
            raise RuntimeError("Malformed update response: " + repr(response_obj))

        status = response_obj.get("status")

        if status == "replied":
            cbor_certificate = response_obj["certificate"]
            decoded_certificate = cbor2.loads(cbor_certificate)
            certificate = Certificate(decoded_certificate)

            if verify_certificate:
                certificate.assert_certificate_valid(effective_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            certified_status = certificate.lookup_request_status(request_id)
            if certified_status == "replied":
                reply_data = certificate.lookup_reply(request_id)
                return decode(reply_data, return_type)
            elif certified_status == "rejected":
                rejection = certificate.lookup_request_rejection(request_id)
                raise RuntimeError(
                    f"Call rejected (code={rejection['reject_code']}): "
                    f"{rejection['reject_message']} [error_code={rejection.get('error_code')}]"
                )
            else:
                # not yet terminal in certification; continue polling
                return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

        elif status == "accepted":
            # Not yet executed; start polling
            return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

        elif status == "non_replicated_rejection":
            code = response_obj.get("reject_code")
            message = response_obj.get("reject_message")
            error = response_obj.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")

        else:
            raise RuntimeError(f"Unknown status: {status}")

    async def update_raw_async(self, canister_id, method_name, arg, return_type=None,
                               effective_canister_id=None, verify_certificate: bool = False,
                               **kwargs):
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        _ = await self.call_endpoint_async(effective_id, request_id, signed_cbor)

        status, result = await self.poll_async(
            effective_id, request_id, verify_certificate, **kwargs
        )

        if status == "rejected":
            # result is a dict with rejection fields
            code = result.get("reject_code")
            message = result.get("reject_message")
            error = result.get("error_code", "unknown")
            raise RuntimeError(f"Rejected (code={code}): {message} [error_code={error}]")

        elif status == "replied":
            # result is raw reply bytes
            if result[:4] == b"DIDL":
                return decode(result, return_type)
            return result

        else:
            raise RuntimeError("Timeout to poll result, current status: " + str(status))

    # ----------- Read state -----------

    def read_state_raw(self, canister_id, paths):
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        raw_bytes = self.read_state_endpoint(canister_id, signed_cbor)

        # Some replicas return plain text on error; normalize message
        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        try:
            decoded_obj = cbor2.loads(raw_bytes)
        except Exception:
            # Use repr to avoid decode errors
            raise ValueError("Unable to decode cbor value: " + repr(raw_bytes))
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        return cert_dict

    async def read_state_raw_async(self, canister_id, paths):
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        raw_bytes = await self.read_state_endpoint_async(canister_id, signed_cbor)

        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        decoded_obj = cbor2.loads(raw_bytes)
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        return cert_dict

    # ----------- Request status -----------

    def request_status_raw(self, canister_id, req_id):
        paths = [
            [b"request_status", req_id],
        ]
        cert_dict = self.read_state_raw(canister_id, paths)
        certificate = Certificate(cert_dict)
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, cert_dict
        return status_bytes.decode(), cert_dict

    async def request_status_raw_async(self, canister_id, req_id):
        paths = [
            [b"request_status", req_id],
        ]
        cert_dict = await self.read_state_raw_async(canister_id, paths)
        certificate = Certificate(cert_dict)
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, cert_dict
        return status_bytes.decode(), cert_dict

    # ----------- Polling helpers -----------

    def poll_and_wait(self, canister_id, req_id, verify_certificate, return_type=None):
        status, result = self.poll(canister_id, req_id, verify_certificate)
        if status == "replied":
            return decode(result, return_type)
        elif status == "rejected":
            code = result["reject_code"]
            message = result["reject_message"]
            error = result.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")
        else:
            raise RuntimeError(f"Unknown status: {status}")

    def poll(
        self,
        canister_id,
        req_id,
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (synchronous).

        Args:
            canister_id: target canister identifier (use effective canister id)
            req_id:      request ID bytes
            verify_certificate: whether to verify the certificate
            initial_delay: initial backoff interval in seconds (default 0.5s)
            max_interval:  maximum backoff interval in seconds (default 1s)
            multiplier:    backoff multiplier (default 1.4)
            timeout:       maximum total polling time in seconds

        Returns:
            Tuple(status_str, result_bytes_or_data)
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, cert_dict = self.request_status_raw(canister_id, req_id)
            certificate = Certificate(cert_dict)

            if verify_certificate:
                certificate.assert_certificate_valid(canister_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            if status_str in ("replied", "done", "rejected"):
                break

            # Once we see Received or Processing, the request is accepted:
            # reset backoff so we don’t time out while it’s still in flight.
            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

            time.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise RuntimeError(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise RuntimeError(f"Unexpected final status in poll(): {status_str!r}")

    async def poll_async(
        self,
        canister_id,
        req_id,
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (asynchronous).
        Mirrors `poll` but uses async read_state.
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, cert_dict = await self.request_status_raw_async(canister_id, req_id)
            certificate = Certificate(cert_dict)

            if verify_certificate:
                certificate.assert_certificate_valid(canister_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            if status_str in ("replied", "done", "rejected"):
                break

            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

            await asyncio.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise RuntimeError(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise RuntimeError(f"Unexpected final status in poll_async(): {status_str!r}")