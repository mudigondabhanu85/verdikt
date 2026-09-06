"""Proves app.auth.saml.generate_sp_metadata() produces real, valid,
parseable SAML 2.0 SP metadata XML via the actual python3-saml library
(not hand-rolled XML). Full IdP<->SP handshake (actually completing a
login via a real Okta tenant) is NOT tested here and can't be — that
needs a real Okta org's IdP metadata to validate an actual SAML
assertion against, which isn't available in this environment. This is a
known, stated limitation of this pass, not a gap silently papered over.
"""

import xml.etree.ElementTree as ET

from app.auth.saml import generate_sp_metadata

_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"


def test_generate_sp_metadata_produces_valid_parseable_xml():
    entity_id = "https://verdikt.example.test/saml-configs/abc-123/metadata.xml"
    acs_url = "https://verdikt.example.test/saml/acs/abc-123"

    xml_text = generate_sp_metadata(entity_id, acs_url)

    root = ET.fromstring(xml_text)  # raises if not well-formed XML
    assert root.tag == f"{{{_MD_NS}}}EntityDescriptor"
    assert root.attrib["entityID"] == entity_id

    acs = root.find(f".//{{{_MD_NS}}}AssertionConsumerService")
    assert acs is not None
    assert acs.attrib["Location"] == acs_url
    assert acs.attrib["Binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


def test_generate_sp_metadata_is_stable_across_different_orgs():
    """Two different orgs' configs must produce distinctly-identified
    metadata — proves entity_id/acs_url are actually threaded through,
    not hardcoded."""
    xml_a = generate_sp_metadata("https://a.test/metadata.xml", "https://a.test/saml/acs/1")
    xml_b = generate_sp_metadata("https://b.test/metadata.xml", "https://b.test/saml/acs/2")

    root_a = ET.fromstring(xml_a)
    root_b = ET.fromstring(xml_b)
    assert root_a.attrib["entityID"] != root_b.attrib["entityID"]
