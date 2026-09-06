package com.verdikt.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * "Verdikt" suite tab (Montoya {@code registerSuiteTab}) replacing the
 * env-var-only MVP config with a real settings UI (§4 of the build
 * spec): the analyst pastes their Verdikt personal API token once, picks
 * an existing Project + Version from live dropdowns (or creates a new
 * Project), and that's it.
 *
 * IMPORTANT — this is the whole answer to "how do we handle the app name
 * and creds": the target application's own login credentials are NEVER
 * entered here. They're configured against the chosen Project/Version
 * through the main Verdikt web app, in Verdikt's own encrypted
 * credential vault. This panel only ever handles Verdikt's own API
 * connection details (base URL + personal API token) plus which
 * Project/Version selected traffic should be filed under.
 *
 * Selections persist across Burp restarts via
 * {@code api.persistence().preferences()} (a simple per-extension
 * key-value store Burp itself manages) instead of the old JVM
 * environment variables — see {@link VerdiktExtension} and
 * {@link VerdiktContextMenuProvider} for the (env-var-fallback-preserving)
 * read side.
 */
final class VerdiktSettingsPanel extends JPanel {
    static final String PREF_BASE_URL = "verdikt.baseUrl";
    static final String PREF_API_TOKEN = "verdikt.apiToken";
    static final String PREF_VERSION_ID = "verdikt.versionId";
    static final String PREF_PROJECT_ID = "verdikt.projectId";

    private final MontoyaApi api;
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    private final JTextField baseUrlField = new JTextField(30);
    private final JPasswordField tokenField = new JPasswordField(30);
    private final JComboBox<ProjectItem> projectCombo = new JComboBox<>();
    private final JComboBox<VersionItem> versionCombo = new JComboBox<>();
    private final JTextField newProjectNameField = new JTextField(20);
    private final JLabel statusLabel = new JLabel(" ");

    private List<ProjectItem> loadedProjects = new ArrayList<>();

    VerdiktSettingsPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0;
        c.gridy = 0;
        add(new JLabel("Verdikt API base URL:"), c);
        c.gridx = 1;
        add(baseUrlField, c);

        c.gridx = 0;
        c.gridy++;
        add(new JLabel("Personal API token:"), c);
        c.gridx = 1;
        add(tokenField, c);

        c.gridx = 0;
        c.gridy++;
        JButton connectButton = new JButton("Connect / Refresh projects");
        c.gridx = 1;
        add(connectButton, c);

        c.gridx = 0;
        c.gridy++;
        add(new JLabel("Project:"), c);
        c.gridx = 1;
        add(projectCombo, c);

        c.gridx = 0;
        c.gridy++;
        add(new JLabel("Version:"), c);
        c.gridx = 1;
        add(versionCombo, c);

        c.gridx = 0;
        c.gridy++;
        add(new JLabel("New project name:"), c);
        JPanel newProjectRow = new JPanel();
        newProjectRow.setLayout(new BoxLayout(newProjectRow, BoxLayout.X_AXIS));
        newProjectRow.add(newProjectNameField);
        newProjectRow.add(Box.createHorizontalStrut(6));
        JButton createProjectButton = new JButton("+ New project");
        newProjectRow.add(createProjectButton);
        c.gridx = 1;
        add(newProjectRow, c);

        c.gridx = 0;
        c.gridy++;
        c.gridwidth = 2;
        JLabel noteLabel = new JLabel(
            "<html><i>Target application login credentials are never entered here — "
                + "configure those against the selected Project/Version in the Verdikt web app.</i></html>");
        add(noteLabel, c);

        c.gridy++;
        add(statusLabel, c);

        c.gridy++;
        JButton saveButton = new JButton("Save selection");
        add(saveButton, c);

        projectCombo.setPreferredSize(new Dimension(320, projectCombo.getPreferredSize().height));
        versionCombo.setPreferredSize(new Dimension(320, versionCombo.getPreferredSize().height));

        loadFromPreferences();

        connectButton.addActionListener(e -> refreshProjects());
        projectCombo.addActionListener(e -> refreshVersionsForSelectedProject());
        createProjectButton.addActionListener(e -> createProject());
        saveButton.addActionListener(e -> saveSelection());
    }

    private Preferences prefs() {
        return api.persistence().preferences();
    }

    private void loadFromPreferences() {
        String savedBaseUrl = prefs().getString(PREF_BASE_URL);
        String savedToken = prefs().getString(PREF_API_TOKEN);
        if (savedBaseUrl != null) {
            baseUrlField.setText(savedBaseUrl);
        }
        if (savedToken != null) {
            tokenField.setText(savedToken);
        }
    }

    private void saveSelection() {
        prefs().setString(PREF_BASE_URL, baseUrlField.getText().trim());
        prefs().setString(PREF_API_TOKEN, new String(tokenField.getPassword()));

        ProjectItem project = (ProjectItem) projectCombo.getSelectedItem();
        VersionItem version = (VersionItem) versionCombo.getSelectedItem();
        if (project != null) {
            prefs().setString(PREF_PROJECT_ID, project.id);
        }
        if (version != null) {
            prefs().setString(PREF_VERSION_ID, version.id);
        }
        setStatus("Saved. \"Send to Verdikt\" will use this project/version from now on.");
    }

    private void refreshProjects() {
        String baseUrl = baseUrlField.getText().trim();
        String token = new String(tokenField.getPassword());
        if (baseUrl.isEmpty() || token.isEmpty()) {
            setStatus("Enter a base URL and API token first.");
            return;
        }
        setStatus("Loading projects…");
        new Thread(() -> {
            try {
                String body = get(baseUrl.replaceAll("/+$", "") + "/projects", token);
                List<ProjectItem> projects = JsonLite.parseObjectArray(body).stream()
                    .map(o -> new ProjectItem(o.get("id"), o.get("name")))
                    .collect(java.util.stream.Collectors.toList());
                SwingUtilities.invokeLater(() -> {
                    loadedProjects = projects;
                    projectCombo.setModel(new DefaultComboBoxModel<>(projects.toArray(new ProjectItem[0])));
                    setStatus("Loaded " + projects.size() + " project(s).");
                    restoreSelectedProject();
                });
            } catch (Exception ex) {
                api.logging().logToError("Failed to load Verdikt projects", ex);
                SwingUtilities.invokeLater(() -> setStatus("Failed to load projects: " + ex.getMessage()));
            }
        }, "verdikt-load-projects").start();
    }

    private void restoreSelectedProject() {
        String savedProjectId = prefs().getString(PREF_PROJECT_ID);
        if (savedProjectId == null) {
            return;
        }
        for (int i = 0; i < projectCombo.getItemCount(); i++) {
            ProjectItem item = projectCombo.getItemAt(i);
            if (item.id.equals(savedProjectId)) {
                projectCombo.setSelectedIndex(i);
                break;
            }
        }
    }

    private void refreshVersionsForSelectedProject() {
        ProjectItem project = (ProjectItem) projectCombo.getSelectedItem();
        if (project == null) {
            return;
        }
        String baseUrl = baseUrlField.getText().trim();
        String token = new String(tokenField.getPassword());
        new Thread(() -> {
            try {
                String body = get(baseUrl.replaceAll("/+$", "") + "/projects/" + project.id + "/versions", token);
                List<VersionItem> versions = JsonLite.parseObjectArray(body).stream()
                    .map(o -> new VersionItem(o.get("id"), o.get("name")))
                    .collect(java.util.stream.Collectors.toList());
                SwingUtilities.invokeLater(() -> {
                    versionCombo.setModel(new DefaultComboBoxModel<>(versions.toArray(new VersionItem[0])));
                    String savedVersionId = prefs().getString(PREF_VERSION_ID);
                    if (savedVersionId != null) {
                        for (int i = 0; i < versionCombo.getItemCount(); i++) {
                            if (versionCombo.getItemAt(i).id.equals(savedVersionId)) {
                                versionCombo.setSelectedIndex(i);
                                break;
                            }
                        }
                    }
                });
            } catch (Exception ex) {
                api.logging().logToError("Failed to load Verdikt versions", ex);
            }
        }, "verdikt-load-versions").start();
    }

    private void createProject() {
        String name = newProjectNameField.getText().trim();
        String baseUrl = baseUrlField.getText().trim();
        String token = new String(tokenField.getPassword());
        if (name.isEmpty() || baseUrl.isEmpty() || token.isEmpty()) {
            setStatus("Enter a base URL, API token, and a project name first.");
            return;
        }
        setStatus("Creating project…");
        new Thread(() -> {
            try {
                java.util.Map<String, Object> fields = new java.util.LinkedHashMap<>();
                fields.put("name", name);
                post(baseUrl.replaceAll("/+$", "") + "/projects", token, Json.object(fields));
                SwingUtilities.invokeLater(() -> {
                    setStatus("Created project \"" + name + "\". Refreshing…");
                    newProjectNameField.setText("");
                    refreshProjects();
                });
            } catch (Exception ex) {
                api.logging().logToError("Failed to create Verdikt project", ex);
                SwingUtilities.invokeLater(() -> setStatus("Failed to create project: " + ex.getMessage()));
            }
        }, "verdikt-create-project").start();
    }

    private String get(String url, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .header("Authorization", "Bearer " + token)
            .GET()
            .build();
        java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new RuntimeException("HTTP " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    private String post(String url, String token, String jsonBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(15))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();
        java.net.http.HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new RuntimeException("HTTP " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    private void setStatus(String text) {
        statusLabel.setText(text);
    }

    Component component() {
        return this;
    }

    private static final class ProjectItem {
        final String id;
        final String name;

        ProjectItem(String id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public String toString() {
            return name + " — " + id;
        }
    }

    private static final class VersionItem {
        final String id;
        final String name;

        VersionItem(String id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public String toString() {
            return name + " — " + id;
        }
    }
}
