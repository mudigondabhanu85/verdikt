package com.verdikt.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Adds a "Send to Verdikt" item to Burp's request/response context menu.
 * Each selected exchange is normalized into the same request/response
 * shape app.schemas.traffic.HttpRequest/HttpResponse expects and POSTed,
 * one exchange per call, to
 * {VERDIKT_API_BASE_URL}/versions/{VERDIKT_VERSION_ID}/traffic/manual.
 */
final class VerdiktContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final HttpClient httpClient;

    VerdiktContextMenuProvider(MontoyaApi api) {
        this.api = api;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected.isEmpty()) {
            return List.of();
        }

        JMenuItem menuItem = new JMenuItem("Send to Verdikt");
        menuItem.addActionListener(actionEvent -> {
            for (HttpRequestResponse exchange : selected) {
                sendToVerdikt(exchange);
            }
        });

        List<Component> items = new ArrayList<>();
        items.add(menuItem);
        return items;
    }

    private void sendToVerdikt(HttpRequestResponse exchange) {
        String baseUrl = System.getenv("VERDIKT_API_BASE_URL");
        String versionId = System.getenv("VERDIKT_VERSION_ID");
        String token = System.getenv("VERDIKT_API_TOKEN");

        if (baseUrl == null || versionId == null) {
            api.logging().logToError(
                "Cannot send to Verdikt: VERDIKT_API_BASE_URL and/or "
                    + "VERDIKT_VERSION_ID are not set in Burp's JVM environment.");
            return;
        }

        String payload = toManualTrafficJson(exchange);
        String url = baseUrl.replaceAll("/+$", "") + "/versions/" + versionId + "/traffic/manual";

        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/json")
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(payload));
        if (token != null && !token.isEmpty()) {
            builder.header("Authorization", "Bearer " + token);
        }

        try {
            java.net.http.HttpResponse<String> response =
                httpClient.send(builder.build(), BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                api.logging().logToOutput("Sent exchange to Verdikt: " + exchange.request().url());
            } else {
                api.logging().logToError(
                    "Verdikt rejected the exchange (" + response.statusCode() + "): " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            api.logging().logToError("Failed to send exchange to Verdikt", e);
        }
    }

    private String toManualTrafficJson(HttpRequestResponse exchange) {
        HttpRequest request = exchange.request();

        Map<String, Object> requestFields = new LinkedHashMap<>();
        requestFields.put("method", request.method());
        requestFields.put("url", request.url());
        requestFields.put("headers", headerMap(request.headers()));
        String requestBody = request.bodyToString();
        if (requestBody != null && !requestBody.isEmpty()) {
            requestFields.put("body", requestBody);
        }

        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("request", requestFields);

        if (exchange.hasResponse()) {
            HttpResponse response = exchange.response();
            Map<String, Object> responseFields = new LinkedHashMap<>();
            responseFields.put("status", (int) response.statusCode());
            responseFields.put("headers", headerMap(response.headers()));
            String responseBody = response.bodyToString();
            if (responseBody != null && !responseBody.isEmpty()) {
                responseFields.put("body", responseBody);
            }
            fields.put("response", responseFields);
        } else {
            fields.put("response", Map.of());
        }

        return Json.object(fields);
    }

    private Map<String, Object> headerMap(List<HttpHeader> headers) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (HttpHeader header : headers) {
            map.put(header.name(), header.value());
        }
        return map;
    }
}
