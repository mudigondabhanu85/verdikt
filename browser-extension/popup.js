// Converts the raw {action, selector, value, input_type} steps recorded
// by content-script.js into MacroStep-shaped dicts
// ({action, selector, value, field_role, url}) exactly matching
// backend/app/agents/macro.py's MacroRecorder.record() conversion, then
// applies the same _infer_field_roles() post-processing pass, so the
// exported JSON is a drop-in LoginMacro.steps value — replayable by
// MacroPlayer.replay() with zero backend changes, identical to a macro
// recorded by the in-app Playwright recorder.

function toMacroSteps(rawSteps) {
  return rawSteps.map((raw) => ({
    action: raw.action,
    selector: raw.selector,
    value: raw.value,
    field_role: raw.input_type === "password" ? "password" : null,
  }));
}

// Mirrors app/agents/macro.py's _infer_field_roles(): the fill step
// immediately preceding the password fill, on a role-less field, is
// inferred as the username field. Its recorded value is cleared too —
// never store a typed username value; replay substitutes it at run time.
function inferFieldRoles(steps) {
  const passwordIndex = steps.findIndex((s) => s.action === "fill" && s.field_role === "password");
  if (passwordIndex === -1) return steps;
  for (let i = passwordIndex - 1; i >= 0; i--) {
    if (steps[i].action === "fill" && steps[i].field_role === null) {
      steps[i] = { ...steps[i], field_role: "username", value: null };
      break;
    }
  }
  return steps;
}

function buildExportableSteps(startUrl, rawSteps) {
  const gotoStep = { action: "goto", selector: null, value: null, field_role: null, url: startUrl };
  const filledSteps = toMacroSteps(rawSteps).map((s) => ({ ...s, url: null }));
  return [gotoStep, ...inferFieldRoles(filledSteps)];
}

const statusEl = document.getElementById("status");
const startBtn = document.getElementById("start-btn");
const stopBtn = document.getElementById("stop-btn");
const exportSection = document.getElementById("export-section");
const exportBtn = document.getElementById("export-btn");

let lastRawSteps = [];
let lastStartUrl = null;

function refreshState() {
  chrome.runtime.sendMessage({ type: "verdikt-get-state" }, (state) => {
    if (!state) return;
    if (state.recording) {
      statusEl.textContent = `Recording... (${state.stepCount} steps captured)`;
      startBtn.style.display = "none";
      stopBtn.style.display = "block";
    }
  });
}

startBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "verdikt-start-recording" }, (resp) => {
    if (!resp || !resp.ok) {
      statusEl.textContent = "Could not start recording on this tab.";
      return;
    }
    statusEl.textContent = "Recording... (0 steps captured)";
    startBtn.style.display = "none";
    stopBtn.style.display = "block";
    exportSection.style.display = "none";
  });
});

stopBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "verdikt-stop-recording" }, (resp) => {
    if (!resp || !resp.ok) return;
    lastRawSteps = resp.rawSteps;
    lastStartUrl = resp.startUrl;
    statusEl.textContent = `Stopped. ${lastRawSteps.length} steps captured.`;
    stopBtn.style.display = "none";
    startBtn.style.display = "block";
    exportSection.style.display = "block";
  });
});

exportBtn.addEventListener("click", () => {
  const steps = buildExportableSteps(lastStartUrl, lastRawSteps);
  const blob = new Blob([JSON.stringify({ steps }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  chrome.downloads
    ? chrome.downloads.download({ url, filename: "verdikt-login-macro.json" })
    : window.open(url); // fallback if "downloads" permission isn't granted
});

refreshState();
