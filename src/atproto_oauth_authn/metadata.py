"""Metadata retrieval functions for AT Protocol."""

import logging
import json
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
import httpx

from .security import valid_url
from .exceptions import MetadataError, SecurityError
from .metadata import get_pds_metadata, extract_auth_server, get_auth_server_metadata

logger = logging.getLogger(__name__)



      

    # errors = []

    # for auth_server in auth_servers:
    #     try:
    #         return _fetch_single_auth_server_metadata(auth_server)
    #     except SecurityError as e:
    #         error_msg = f"Security error for {auth_server}: {str(e)}"
    #         logger.error("Security check failed for auth server: %s", auth_server)
    #         errors.append(error_msg)
    #         continue
    #     except httpx.HTTPStatusError as e:
    #         error_msg = (
    #             "HTTP error occurred while retrieving auth server metadata "
    #             f"from {auth_server}: {e}"
    #         )
    #         logger.warning(error_msg)
    #         errors.append(error_msg)
    #         continue
    #     except httpx.RequestError as e:
    #         error_msg = (
    #             "Request error occurred while retrieving auth server metadata "
    #             f"from {auth_server}: {e}"
    #         )
    #         logger.warning(error_msg)
    #         errors.append(error_msg)
    #         continue
    #     except json.JSONDecodeError:
    #         error_msg = (
    #             "Failed to parse JSON response from auth server metadata "
    #             f"retrieval from {auth_server}"
    #         )
    #         logger.warning(error_msg)
    #         errors.append(error_msg)
    #         continue
    #     except MetadataError as e:
    #         logger.warning("Metadata validation failed for %s: %s", auth_server, e)
    #         errors.append(str(e))
    #         continue

    # error_msg = (
    #     "Failed to retrieve metadata from any authorization server: "
    #     f"{'; '.join(errors)}"
    # )
    # logger.error(error_msg)
    # raise MetadataError(error_msg)
