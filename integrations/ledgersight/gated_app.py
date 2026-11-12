"""Fail closed if a deployment omits its approval service configuration."""
from ledgersight.app import app, svc
from ledgersight.service import Denied
from document_gate import configured_client, install_document_gate

install_document_gate(app, svc, Denied, configured_client())
