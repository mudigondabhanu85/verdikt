package com.verdikt.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Entry point Burp discovers when this jar is loaded as an extension
 * (Extensions tab -> Add). Registers the "Send to Verdikt" context-menu
 * item (see VerdiktContextMenuProvider) that posts a selected request/
 * response exchange to Verdikt's POST /versions/{id}/traffic/manual
 * endpoint (§4).
 *
 * Connection details (API base URL, target Version id, bearer token) are
 * read from environment variables at load time rather than a settings
 * UI — a documented MVP simplification, same spirit as the macro
 * recorder's synchronous-only API route. A later pass can add a Montoya
 * SettingsPanel instead of relying on env vars.
 */
public class VerdiktExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Verdikt — Send to Verdikt");

        String baseUrl = System.getenv("VERDIKT_API_BASE_URL");
        String versionId = System.getenv("VERDIKT_VERSION_ID");
        if (baseUrl == null || versionId == null) {
            api.logging().logToError(
                "VERDIKT_API_BASE_URL and/or VERDIKT_VERSION_ID are not set. "
                    + "\"Send to Verdikt\" will log an error instead of sending "
                    + "anything until both are configured in Burp's JVM environment.");
        }

        api.userInterface().registerContextMenuItemsProvider(new VerdiktContextMenuProvider(api));
    }
}
