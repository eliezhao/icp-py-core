# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

"""
HTTP client for Internet Computer protocol interactions.

This module provides synchronous and asynchronous HTTP clients for communicating
with Internet Computer boundary nodes via the HTTPS API.
"""

from __future__ import annotations

from typing import Optional
import httpx
from httpx import Timeout

from icp_core.errors import TransportError

DEFAULT_TIMEOUT_SEC = 360.0
"""Default timeout for HTTP requests in seconds (6 minutes)."""

DEFAULT_TIMEOUT = Timeout(DEFAULT_TIMEOUT_SEC)
"""Default timeout object for HTTP requests."""


class Client:
    """
    HTTP client for Internet Computer protocol interactions.
    
    This client handles all HTTP communication with IC boundary nodes, including:
    - Query calls (read-only, fast)
    - Update calls (state-changing, requires consensus)
    - Read state operations (certificate retrieval)
    - Subnet-level read state operations
    
    All methods support both synchronous and asynchronous execution.
    
    **HTTP/2 Support:**
    - Asynchronous methods (`*_async`) automatically use HTTP/2 when supported
      by the boundary node, providing improved performance through multiplexing
      and header compression.
    - Synchronous methods use HTTP/1.1 (httpx sync client does not support HTTP/2).
    
    Attributes:
        url: The base URL of the IC boundary node (default: "https://ic0.app")
    
    Example:
        >>> client = Client(url="https://ic0.app")
        >>> data = client.query("canister-id", b"cbor_data")
        >>> # Async with HTTP/2 support
        >>> async_data = await client.query_async("canister-id", b"cbor_data")
    """
    
    def __init__(self, url: str = "https://ic0.app") -> None:
        """
        Initialize the HTTP client.
        
        Args:
            url: Base URL of the IC boundary node. Defaults to "https://ic0.app".
        """
        self.url = url

    # --------- sync ---------

    def query(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Send a query request to a canister (read-only, no consensus required).
        
        Queries are fast and do not modify state. They are executed by a single
        replica and do not go through consensus.
        
        Args:
            canister_id: The canister ID to query.
            data: CBOR-encoded request data.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded response bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            Uses the v3 API endpoint: `/api/v3/canister/<canister_id>/query`
        """
        endpoint = f"{self.url}/api/v3/canister/{canister_id}/query"
        headers = {"Content-Type": "application/cbor"}
        try:
            resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
            resp.raise_for_status()  # Check HTTP status code
            return resp.content
        except httpx.HTTPStatusError as e:
            raise TransportError(endpoint, e) from e
        except httpx.RequestError as e:
            raise TransportError(endpoint, e) from e

    def call(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> httpx.Response:
        """
        Send an update call to a canister (state-changing, requires consensus).
        
        Update calls modify canister state and go through consensus. The response
        contains a request ID that must be polled to get the final result.
        
        Args:
            canister_id: The canister ID to call.
            data: CBOR-encoded request data.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            HTTP response object containing the request ID.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            Uses the v3 API endpoint: `/api/v3/canister/<canister_id>/call`
            # Temporarily using v3 instead of v4
            # v4 endpoint: `/api/v4/canister/<canister_id>/call` (supports canister migrations)
        """
        endpoint = f"{self.url}/api/v3/canister/{canister_id}/call"
        headers = {"Content-Type": "application/cbor"}
        try:
            resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
            resp.raise_for_status()  # Check HTTP status code
            return resp
        except httpx.HTTPStatusError as e:
            raise TransportError(endpoint, e) from e
        except httpx.RequestError as e:
            raise TransportError(endpoint, e) from e

    def read_state(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Read state from a canister (retrieve certificate and state tree).
        
        This method retrieves a cryptographically verified certificate and state
        tree for the specified paths. The certificate can be verified to ensure
        the state is authentic.
        
        Args:
            canister_id: The canister ID to read state from.
            data: CBOR-encoded request data containing the paths to read.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded certificate and state tree bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            Uses the v3 API endpoint: `/api/v3/canister/<canister_id>/read_state`
        """
        endpoint = f"{self.url}/api/v3/canister/{canister_id}/read_state"
        headers = {"Content-Type": "application/cbor"}
        try:
            resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
            resp.raise_for_status()  # Check HTTP status code
            return resp.content
        except httpx.HTTPStatusError as e:
            raise TransportError(endpoint, e) from e
        except httpx.RequestError as e:
            raise TransportError(endpoint, e) from e

    def read_state_subnet(self, subnet_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Read state from a subnet (retrieve subnet-level certificate and state tree).
        
        This method retrieves subnet-level state information, such as subnet
        configuration, node information, and canister ranges. Unlike canister
        read_state, this does not require canister range validation.
        
        Args:
            subnet_id: The subnet ID to read state from.
            data: CBOR-encoded request data containing the paths to read.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded certificate and state tree bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            Uses the v3 API endpoint: `/api/v3/subnet/<subnet_id>/read_state`
        """
        endpoint = f"{self.url}/api/v3/subnet/{subnet_id}/read_state"
        headers = {"Content-Type": "application/cbor"}
        try:
            resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
            resp.raise_for_status()  # Check HTTP status code
            return resp.content
        except httpx.HTTPStatusError as e:
            raise TransportError(endpoint, e) from e
        except httpx.RequestError as e:
            raise TransportError(endpoint, e) from e

    def status(self, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Get the status of the IC boundary node.
        
        This method retrieves information about the boundary node, such as
        its version and supported API versions.
        
        Args:
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded status information bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            Uses the v2 API endpoint: `/api/v2/status`
        """
        endpoint = f"{self.url}/api/v2/status"
        try:
            resp = httpx.get(endpoint, timeout=timeout)
            resp.raise_for_status()  # Check HTTP status code
            return resp.content
        except httpx.HTTPStatusError as e:
            raise TransportError(endpoint, e) from e
        except httpx.RequestError as e:
            raise TransportError(endpoint, e) from e

    # --------- async ---------

    async def query_async(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Send a query request to a canister asynchronously (read-only, no consensus required).
        
        This is the async version of `query()`. See `query()` for details.
        
        Args:
            canister_id: The canister ID to query.
            data: CBOR-encoded request data.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded response bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            HTTP/2 is enabled for improved performance when supported by the boundary node.
        """
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            endpoint = f"{self.url}/api/v3/canister/{canister_id}/query"
            headers = {"Content-Type": "application/cbor"}
            try:
                resp = await client.post(endpoint, content=data, headers=headers)
                resp.raise_for_status()  # Check HTTP status code
                return resp.content
            except httpx.HTTPStatusError as e:
                raise TransportError(endpoint, e) from e
            except httpx.RequestError as e:
                raise TransportError(endpoint, e) from e

    async def call_async(self, canister_id: str, req_id: bytes, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Send an update call to a canister asynchronously (state-changing, requires consensus).
        
        This is the async version of `call()`. See `call()` for details.
        
        Args:
            canister_id: The canister ID to call.
            req_id: The request ID (returned for consistency with sync version).
            data: CBOR-encoded request data.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            The request ID (same as req_id parameter).
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            HTTP/2 is enabled for improved performance when supported by the boundary node.
            # Temporarily using v3 instead of v4
        """
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            endpoint = f"{self.url}/api/v3/canister/{canister_id}/call"
            headers = {"Content-Type": "application/cbor"}
            try:
                resp = await client.post(endpoint, content=data, headers=headers)
                resp.raise_for_status()  # Check HTTP status code
                return req_id
            except httpx.HTTPStatusError as e:
                raise TransportError(endpoint, e) from e
            except httpx.RequestError as e:
                raise TransportError(endpoint, e) from e

    async def read_state_async(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Read state from a canister asynchronously (retrieve certificate and state tree).
        
        This is the async version of `read_state()`. See `read_state()` for details.
        
        Args:
            canister_id: The canister ID to read state from.
            data: CBOR-encoded request data containing the paths to read.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded certificate and state tree bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            HTTP/2 is enabled for improved performance when supported by the boundary node.
        """
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            endpoint = f"{self.url}/api/v3/canister/{canister_id}/read_state"
            headers = {"Content-Type": "application/cbor"}
            try:
                resp = await client.post(endpoint, content=data, headers=headers)
                resp.raise_for_status()  # Check HTTP status code
                return resp.content
            except httpx.HTTPStatusError as e:
                raise TransportError(endpoint, e) from e
            except httpx.RequestError as e:
                raise TransportError(endpoint, e) from e

    async def read_state_subnet_async(self, subnet_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Read state from a subnet asynchronously (retrieve subnet-level certificate and state tree).
        
        This is the async version of `read_state_subnet()`. See `read_state_subnet()` for details.
        
        Args:
            subnet_id: The subnet ID to read state from.
            data: CBOR-encoded request data containing the paths to read.
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded certificate and state tree bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            HTTP/2 is enabled for improved performance when supported by the boundary node.
        """
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            endpoint = f"{self.url}/api/v3/subnet/{subnet_id}/read_state"
            headers = {"Content-Type": "application/cbor"}
            try:
                resp = await client.post(endpoint, content=data, headers=headers)
                resp.raise_for_status()  # Check HTTP status code
                return resp.content
            except httpx.HTTPStatusError as e:
                raise TransportError(endpoint, e) from e
            except httpx.RequestError as e:
                raise TransportError(endpoint, e) from e

    async def status_async(self, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        """
        Get the status of the IC boundary node asynchronously.
        
        This is the async version of `status()`. See `status()` for details.
        
        Args:
            timeout: Optional timeout for the request. Defaults to DEFAULT_TIMEOUT.
        
        Returns:
            CBOR-encoded status information bytes.
        
        Raises:
            TransportError: If the HTTP request fails or returns an error status code.
        
        Note:
            HTTP/2 is enabled for improved performance when supported by the boundary node.
        """
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            endpoint = f"{self.url}/api/v2/status"
            try:
                resp = await client.get(endpoint)
                resp.raise_for_status()  # Check HTTP status code
                return resp.content
            except httpx.HTTPStatusError as e:
                raise TransportError(endpoint, e) from e
            except httpx.RequestError as e:
                raise TransportError(endpoint, e) from e