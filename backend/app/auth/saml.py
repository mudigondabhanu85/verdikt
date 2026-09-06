"""SAML SP metadata generation (§9) — real python3-saml-backed, not
hand-rolled XML. Only metadata generation is implemented in this pass;
full assertion consumption (`/saml/acs`) needs a real Okta tenant's IdP
metadata to validate against and is explicitly out of scope here — see
app/api/routes/saml.py's docstring.
"""

from onelogin.saml2.settings import OneLogin_Saml2_Settings


class SamlMetadataError(RuntimeError):
    pass


def generate_sp_metadata(entity_id: str, acs_url: str) -> str:
    """Generates this Verdikt organization's SAML 2.0 SP metadata XML —
    the file an org's Okta admin uploads (or points a URL at) when
    creating the Okta SAML app integration (§9 step 1). The `idp` block
    below is a placeholder required by OneLogin_Saml2_Settings's schema
    even in sp_validation_only mode; it plays no role in the generated
    SP metadata itself.
    """
    settings_dict = {
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": "https://placeholder.invalid/idp",
            "singleSignOnService": {
                "url": "https://placeholder.invalid/idp/sso",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": "",
        },
    }
    settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise SamlMetadataError(f"Generated SP metadata failed validation: {errors}")
    return metadata.decode() if isinstance(metadata, bytes) else metadata
