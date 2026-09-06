package com.verdikt.burp;

import burp.api.montoya.MontoyaApi;

/**
 * Single place resolving Verdikt connection details from Burp's
 * persisted preferences (set via {@link VerdiktSettingsPanel}), falling
 * back to the original JVM environment variables from the pre-settings-
 * panel MVP so anyone already relying on that path keeps working.
 */
final class ConnectionSettings {
    private ConnectionSettings() {}

    static String baseUrl(MontoyaApi api) {
        String value = api.persistence().preferences().getString(VerdiktSettingsPanel.PREF_BASE_URL);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return System.getenv("VERDIKT_API_BASE_URL");
    }

    static String apiToken(MontoyaApi api) {
        String value = api.persistence().preferences().getString(VerdiktSettingsPanel.PREF_API_TOKEN);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return System.getenv("VERDIKT_API_TOKEN");
    }

    static String versionId(MontoyaApi api) {
        String value = api.persistence().preferences().getString(VerdiktSettingsPanel.PREF_VERSION_ID);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return System.getenv("VERDIKT_VERSION_ID");
    }
}
