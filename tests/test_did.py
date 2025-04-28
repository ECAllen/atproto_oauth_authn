"""Tests for DID document handling functions."""

import pytest
from unittest.mock import patch, MagicMock

from atproto_oauth_authn.did import (
    retrieve_did_document,
    extract_pds_url,
    get_did_document
)
from atproto_oauth_authn.exceptions import DidDocumentError


@patch('atproto_oauth_authn.did.requests.get')
def test_retrieve_did_document(mock_get, mock_response, sample_did_document):
    """Test retrieving a DID document."""
    mock_get.return_value = mock_response(sample_did_document)
    
    result = retrieve_did_document("did:plc:abcdefghijklmnopqrstuvwxyz")
    assert result == sample_did_document
    mock_get.assert_called_once()


@patch('atproto_oauth_authn.did.requests.get')
def test_retrieve_did_document_error(mock_get, mock_response):
    """Test error handling when retrieving a DID document."""
    mock_get.return_value = mock_response({}, status_code=404)
    
    with pytest.raises(DidDocumentError):
        retrieve_did_document("did:plc:nonexistent")


def test_extract_pds_url(sample_did_document):
    """Test extracting PDS URL from a DID document."""
    pds_url = extract_pds_url(sample_did_document)
    assert pds_url == "https://example.pds.com"


def test_extract_pds_url_missing_service():
    """Test error handling when service is missing from DID document."""
    did_doc = {"id": "did:plc:abcdefghijklmnopqrstuvwxyz"}
    
    with pytest.raises(DidDocumentError):
        extract_pds_url(did_doc)


def test_extract_pds_url_missing_pds_service():
    """Test error handling when PDS service is missing from DID document."""
    did_doc = {
        "id": "did:plc:abcdefghijklmnopqrstuvwxyz",
        "service": [
            {
                "id": "#other_service",
                "type": "OtherService",
                "serviceEndpoint": "https://example.com"
            }
        ]
    }
    
    with pytest.raises(DidDocumentError):
        extract_pds_url(did_doc)


@patch('atproto_oauth_authn.did.retrieve_did_document')
def test_get_did_document(mock_retrieve, sample_did_document):
    """Test getting a DID document and extracting PDS URL."""
    mock_retrieve.return_value = sample_did_document
    
    doc, pds_url = get_did_document("did:plc:abcdefghijklmnopqrstuvwxyz")
    assert doc == sample_did_document
    assert pds_url == "https://example.pds.com"
