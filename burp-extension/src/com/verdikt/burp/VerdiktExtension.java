package com.verdikt.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Entry point Burp discovers when this jar is loaded as an extension
 * (Extensions tab -> Add). Registers the "Verdikt" suite tab (a real
 * settings UI — see VerdiktSettingsPanel — for pasting a personal API
 * token and picking a Project/Version by name, instead of editing JVM
 * environment variables) and the "Send to Verdikt" context-menu item
 * (see VerdiktContextMenuProvider) that posts a selected request/
 * response exchange to Verdikt's POST /versions/{id}/traffic/manual
 * endpoint (§4).
 *
 * Connection details are read from Burp's own persisted preferences
 * (set via the settings panel) with the original JVM-environment-variable
 * values (VERDIKT_API_BASE_URL / VERDIKT_VERSION_ID / VERDIKT_API_TOKEN)
 * as a fallback, so anyone already relying on the env-var-only MVP
 * behavior isn't broken by this change.
 */
public class VerdiktExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Verdikt — Send to Verdikt");

        api.userInterface().registerSuiteTab("Verdikt", new VerdiktSettingsPanel(api).component());

        String baseUrl = ConnectionSettings.baseUrl(api);
        String versionId = ConnectionSettings.versionId(api);
        if (baseUrl == null || versionId == null) {
            api.logging().logToOutput(
                "No Verdikt connection configured yet. Open the \"Verdikt\" tab to paste your "
                    + "API token and pick a Project/Version — \"Send to Verdikt\" will log an "
                    + "error instead of sending anything until that's done. (Falling back to "
                    + "VERDIKT_API_BASE_URL/VERDIKT_VERSION_ID/VERDIKT_API_TOKEN JVM environment "
                    + "variables if those are set instead.)");
        }

        api.userInterface().registerContextMenuItemsProvider(new VerdiktContextMenuProvider(api));
    }
}
