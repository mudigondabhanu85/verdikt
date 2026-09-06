# Verdikt Login Macro Recorder (standalone browser extension)

Records a login flow independently of the main Verdikt app — useful for
capturing a login macro on a machine or network segment without direct
Verdikt access, then uploading the exported file into a project
afterward. Produces the exact same macro JSON shape as Verdikt's
in-app Playwright recorder (`POST /versions/{id}/credentials/{id}/record-macro`),
so either path is replayable by the same backend code with zero changes.

## Install (unpacked, for development/local use)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable "Developer mode" (top right).
3. Click "Load unpacked" and select this `browser-extension/` directory.
4. Pin the extension for easy access.

## Recording a macro

1. Navigate to the target application's login page.
2. Click the extension icon, then "Start Recording".
3. Log in normally — fill the username/password fields, click submit,
   complete any post-login redirect. The extension records DOM clicks
   and field fills as you go (password field values are never recorded,
   only which field is the password field — same privacy discipline as
   the in-app recorder).
4. Click the extension icon again, then "Stop Recording".
5. Click "Export macro (.json)" — downloads `verdikt-login-macro.json`.

## Uploading into Verdikt

In the Verdikt web app, open the credential set this macro belongs to
and use "Upload macro" (backed by
`POST /versions/{version_id}/credentials/{credential_id}/macros/upload`,
see `backend/app/api/routes/macro_upload.py`) to attach the exported
JSON file. It becomes a normal `LoginMacro` row, replayable by
`MacroPlayer` exactly like one recorded in-app.

## Limitations

- MFA/OTP steps: pause recording manually before the OTP prompt if your
  flow requires one, complete it, then resume — the recorder captures
  whatever DOM interactions happen while it's active, the same way the
  in-app recorder handles a manual-OTP pause.
- This extension is unsigned/unpublished — "Load unpacked" only, not
  distributed via the Chrome Web Store.
