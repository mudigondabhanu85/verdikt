// Owns recording state (start/stop) and the raw step buffer. The popup
// is transient (closes when it loses focus), so state must live here,
// not in popup.js.

let recording = false;
let startUrl = null;
let rawSteps = [];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "verdikt-start-recording") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      recording = true;
      startUrl = tab.url;
      rawSteps = [];
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content-script.js"],
      });
      sendResponse({ ok: true, startUrl });
    })();
    return true; // async sendResponse
  }

  if (message.type === "verdikt-macro-step") {
    if (recording) rawSteps.push(message.step);
    return false;
  }

  if (message.type === "verdikt-stop-recording") {
    recording = false;
    sendResponse({ ok: true, startUrl, rawSteps });
    return false;
  }

  if (message.type === "verdikt-get-state") {
    sendResponse({ recording, startUrl, stepCount: rawSteps.length });
    return false;
  }

  return false;
});
