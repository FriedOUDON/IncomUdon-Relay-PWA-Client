(() => {
  const basePath = document.body.dataset.basePath || "";
  const settingsLockStorageKey = "incomudon.pwa.settings_lock.v1";
  const settingsUnlockSessionKey = "incomudon.pwa.settings_lock.unlocked.v1";
  const settingsLockPBKDF2Iterations = 310000;
  const maxSlotsRaw = Number.parseInt(document.body.dataset.multiMaxSlots || "", 10);
  const maxSlots = Math.min(10, Math.max(1, Number.isFinite(maxSlotsRaw) ? maxSlotsRaw : 4));
  const settingsKey = "incomudon.pwa.multi.controls.v1";
  const localeStorageKey = "incomudon.pwa.locale.v1";
  const messageNamespace = "incomudon-slot-";
  const targetOrigin = window.location.origin;
  const shortcutEditTimeoutMs = 30000;
  const fallbackStrings = {
    app_title: "IncomUdon Relay PWA Client",
    header_title: "Relay PWA Client",
    multi_single_channel: "Single Channel",
    multi_broadcast_ptt: "Broadcast PTT",
    multi_no_selected_connected: "No selected connected slots",
    multi_selected_connected: "{selected} selected / {connected} connected",
    multi_shortcut: "Shortcut",
    multi_set_shortcut: "Set shortcut",
    multi_edit_shortcuts: "Edit Shortcuts",
    multi_finish_shortcut_edit: "Finish Editing",
    multi_shortcuts_locked: "Shortcut changes are locked.",
    multi_shortcuts_editing: "Shortcut editing is enabled for 30 seconds. PTT transmission is disabled.",
    multi_shortcut_capture: "Press a key to assign it. Esc cancels and locks editing.",
    multi_press_key: "Press a key...",
    multi_hold_broadcast: "Hold to Broadcast ({shortcut})",
    multi_stop_all: "Stop All PTT",
    multi_receiving: "Receiving / Active Talkers",
    multi_slot: "Slot {index}",
    multi_selected: "Broadcast target",
    multi_channel: "Channel",
    multi_sender: "Sender",
    multi_connection: "Connection",
    multi_talker: "Talker",
    multi_offline: "Offline",
    multi_connecting: "Connecting",
    multi_connected: "Connected",
    multi_error: "Error",
    multi_none: "None",
    multi_hold_slot: "Hold to Talk ({shortcut})",
    multi_slot_settings: "Slot settings and cue sounds",
    multi_settings_lead: "Select a slot to edit its connection, cue sounds, and local audio files.",
    multi_open_settings: "Settings",
    multi_shared_mic_ready: "Shared microphone ready",
    multi_shared_mic_active: "Shared microphone active for {count} slot(s)",
    multi_shared_mic_error: "Shared microphone unavailable: {error}",
    multi_receiver_none: "No active remote talkers",
    multi_receiver_slot: "Slot {slot} / Channel {channel}: {talkers}",
    events: "Events",
    clear: "Clear",
    multi_log_main: "Main",
    multi_log_slot: "Slot {slot}",
    settings_lock: "Settings Lock",
    settings_master_password: "Master Password",
    settings_unlock: "Unlock Settings",
    settings_relock: "Lock Settings",
    settings_enable: "Enable Settings Lock",
    settings_disable: "Disable Settings Lock",
    settings_new_master_password: "New Master Password",
    settings_confirm_master_password: "Confirm Master Password",
    settings_disabled_message: "Settings lock is disabled for this browser.",
    settings_locked_message: "Restricted settings are locked. Enter the master password to view or change them.",
    settings_unlocked_message: "Restricted settings are unlocked in this browser.",
    settings_unlock_failed: "Master password is incorrect.",
    settings_unlock_required: "Enter the master password.",
    settings_password_mismatch: "The master password confirmation does not match.",
    settings_crypto_unavailable: "This browser cannot create a settings lock because Web Crypto is unavailable.",
    settings_disable_confirm: "Disable the settings lock on this browser?",
    settings_unlock_error: "Unable to update the settings lock: {error}",
  };
  let strings = { ...fallbackStrings };

  const ui = {
    main: document.getElementById("multiMain"),
    title: document.getElementById("multiTitle"),
    languageLabel: document.getElementById("multiLabelLanguage"),
    languageSelect: document.getElementById("multiLanguageSelect"),
    singleChannelLink: document.getElementById("singleChannelLink"),
    settingsLockCard: document.getElementById("settingsLockCard"),
    settingsLockDetails: document.getElementById("settingsLockDetails"),
    settingsLockHeading: document.getElementById("settingsLockHeading"),
    settingsLockStatus: document.getElementById("settingsLockStatus"),
    labelSettingsMasterPassword: document.getElementById("labelSettingsMasterPassword"),
    settingsMasterPassword: document.getElementById("settingsMasterPassword"),
    settingsUnlockButton: document.getElementById("settingsUnlockButton"),
    settingsRelockButton: document.getElementById("settingsRelockButton"),
    settingsDisableButton: document.getElementById("settingsDisableButton"),
    settingsUnlockForm: document.getElementById("settingsUnlockForm"),
    settingsLockSetupForm: document.getElementById("settingsLockSetupForm"),
    labelSettingsNewMasterPassword: document.getElementById("labelSettingsNewMasterPassword"),
    settingsNewMasterPassword: document.getElementById("settingsNewMasterPassword"),
    labelSettingsConfirmMasterPassword: document.getElementById("labelSettingsConfirmMasterPassword"),
    settingsConfirmMasterPassword: document.getElementById("settingsConfirmMasterPassword"),
    settingsEnableButton: document.getElementById("settingsEnableButton"),
    broadcastHeading: document.getElementById("multiBroadcastHeading"),
    broadcastSummary: document.getElementById("multiBroadcastSummary"),
    broadcastShortcutLabel: document.getElementById("multiBroadcastShortcutLabel"),
    broadcastShortcut: document.getElementById("multiBroadcastShortcut"),
    shortcutEditButton: document.getElementById("multiShortcutEdit"),
    shortcutEditStatus: document.getElementById("multiShortcutEditStatus"),
    broadcastPtt: document.getElementById("multiBroadcastPtt"),
    broadcastPttLabel: document.getElementById("multiBroadcastPttLabel"),
    stopAll: document.getElementById("multiStopAll"),
    micStatus: document.getElementById("multiMicStatus"),
    receivingHeading: document.getElementById("multiReceivingHeading"),
    receivingList: document.getElementById("multiReceivingList"),
    eventsHeading: document.getElementById("multiEventsHeading"),
    clearLog: document.getElementById("multiClearLog"),
    logBox: document.getElementById("multiLogBox"),
    slots: document.getElementById("multiSlots"),
    settingsHeading: document.getElementById("multiSettingsHeading"),
    settingsLead: document.getElementById("multiSettingsLead"),
    settingsTabs: document.getElementById("multiSettingsTabs"),
    settingsPanes: document.getElementById("multiSettingsPanes"),
  };

  const state = {
    slots: [],
    controls: loadControls(),
    locale: "en",
    captureTarget: null,
    shortcutEditEnabled: false,
    shortcutEditTimer: null,
    activeSources: new Map(),
    pressedSlots: new Set(),
    reconcileRunning: false,
    reconcileQueued: false,
    mic: null,
    micError: "",
    settingsLockConfig: loadSettingsLockConfig(),
    settingsUnlocked: false,
    settingsLockBusy: false,
  };

  state.settingsUnlocked = isSettingsUnlockSessionValid(state.settingsLockConfig);

  function t(key, params = null) {
    const source = strings[key] || fallbackStrings[key] || key;
    return source.replace(/\{(\w+)\}/g, (_, name) => (params && params[name] !== undefined ? String(params[name]) : ""));
  }

  function defaultSettingsLockConfig() {
    return {
      version: 1,
      enabled: false,
      salt: "",
      verifier: "",
      iterations: settingsLockPBKDF2Iterations,
    };
  }

  function normalizeSettingsLockConfig(raw) {
    if (!raw || raw.version !== 1 || raw.enabled !== true ||
        typeof raw.salt !== "string" || !raw.salt ||
        typeof raw.verifier !== "string" || !raw.verifier) {
      return defaultSettingsLockConfig();
    }
    const iterations = Number.parseInt(raw.iterations, 10);
    if (!Number.isFinite(iterations) || iterations < 100000 || iterations > 1000000) {
      return defaultSettingsLockConfig();
    }
    return {
      version: 1,
      enabled: true,
      salt: raw.salt,
      verifier: raw.verifier,
      iterations,
    };
  }

  function loadSettingsLockConfig() {
    try {
      return normalizeSettingsLockConfig(JSON.parse(localStorage.getItem(settingsLockStorageKey) || "null"));
    } catch (_) {
      return defaultSettingsLockConfig();
    }
  }

  function persistSettingsLockConfig(config) {
    try {
      localStorage.setItem(settingsLockStorageKey, JSON.stringify(config));
      return true;
    } catch (_) {
      return false;
    }
  }

  function clearSettingsLockConfig() {
    try {
      localStorage.removeItem(settingsLockStorageKey);
    } catch (_) {
      // Storage failures leave the current page state usable until reload.
    }
  }

  function isSettingsLockEnabled() {
    return !!(state.settingsLockConfig && state.settingsLockConfig.enabled);
  }

  function isSettingsLocked() {
    return isSettingsLockEnabled() && !state.settingsUnlocked;
  }

  function isSettingsUnlockSessionValid(config) {
    if (!config || !config.enabled) {
      return false;
    }
    try {
      const stored = JSON.parse(sessionStorage.getItem(settingsUnlockSessionKey) || "null");
      return !!stored && stored.verifier === config.verifier;
    } catch (_) {
      return false;
    }
  }

  function persistSettingsUnlockSession() {
    if (!isSettingsLockEnabled()) {
      return;
    }
    try {
      sessionStorage.setItem(settingsUnlockSessionKey, JSON.stringify({ verifier: state.settingsLockConfig.verifier }));
    } catch (_) {
      // The current page remains unlocked, but a reload will require the password again.
    }
  }

  function clearSettingsUnlockSession() {
    try {
      sessionStorage.removeItem(settingsUnlockSessionKey);
    } catch (_) {
      // Ignore session storage failures.
    }
  }

  function supportsSettingsLockCrypto() {
    return !!(window.crypto && window.crypto.subtle && typeof window.crypto.getRandomValues === "function");
  }

  function bytesToBase64(bytes) {
    let text = "";
    bytes.forEach((value) => {
      text += String.fromCharCode(value);
    });
    return btoa(text);
  }

  function base64ToBytes(value) {
    const text = atob(String(value || ""));
    const bytes = new Uint8Array(text.length);
    for (let index = 0; index < text.length; index += 1) {
      bytes[index] = text.charCodeAt(index);
    }
    return bytes;
  }

  async function deriveSettingsMasterVerifier(password, salt, iterations) {
    if (!supportsSettingsLockCrypto()) {
      throw new Error(t("settings_crypto_unavailable"));
    }
    const passwordKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(String(password)),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await window.crypto.subtle.deriveBits({
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    }, passwordKey, 256);
    return bytesToBase64(new Uint8Array(bits));
  }

  function constantTimeTextEqual(left, right) {
    const a = String(left || "");
    const b = String(right || "");
    if (a.length !== b.length) {
      return false;
    }
    let difference = 0;
    for (let index = 0; index < a.length; index += 1) {
      difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
    }
    return difference === 0;
  }

  function setSettingsLockStatus(message, isError = false) {
    if (!ui.settingsLockStatus) {
      return;
    }
    ui.settingsLockStatus.textContent = message;
    ui.settingsLockStatus.classList.toggle("error", !!isError);
  }

  function clearSettingsLockInputs() {
    [ui.settingsMasterPassword, ui.settingsNewMasterPassword, ui.settingsConfirmMasterPassword].forEach((input) => {
      if (input) {
        input.value = "";
      }
    });
  }

  function applySettingsLockState(preserveStatus = false) {
    const enabled = isSettingsLockEnabled();
    const locked = isSettingsLocked();
    document.body.classList.toggle("settings-locked", locked);

    if (ui.settingsLockCard) ui.settingsLockCard.hidden = false;
    if (ui.settingsLockDetails && locked) ui.settingsLockDetails.open = true;
    if (ui.settingsLockHeading) ui.settingsLockHeading.textContent = t("settings_lock");
    if (ui.labelSettingsMasterPassword) ui.labelSettingsMasterPassword.textContent = t("settings_master_password");
    if (ui.labelSettingsNewMasterPassword) ui.labelSettingsNewMasterPassword.textContent = t("settings_new_master_password");
    if (ui.labelSettingsConfirmMasterPassword) ui.labelSettingsConfirmMasterPassword.textContent = t("settings_confirm_master_password");
    if (ui.settingsUnlockButton) {
      ui.settingsUnlockButton.textContent = t("settings_unlock");
      ui.settingsUnlockButton.disabled = !enabled || !locked || state.settingsLockBusy;
    }
    if (ui.settingsEnableButton) {
      ui.settingsEnableButton.textContent = t("settings_enable");
      ui.settingsEnableButton.disabled = enabled || state.settingsLockBusy;
    }
    if (ui.settingsRelockButton) {
      ui.settingsRelockButton.textContent = t("settings_relock");
      ui.settingsRelockButton.hidden = !enabled || locked;
      ui.settingsRelockButton.disabled = state.settingsLockBusy;
    }
    if (ui.settingsDisableButton) {
      ui.settingsDisableButton.textContent = t("settings_disable");
      ui.settingsDisableButton.hidden = !enabled || locked;
      ui.settingsDisableButton.disabled = state.settingsLockBusy;
    }
    if (ui.settingsUnlockForm) ui.settingsUnlockForm.hidden = !enabled || !locked;
    if (ui.settingsLockSetupForm) ui.settingsLockSetupForm.hidden = enabled;
    if (ui.settingsMasterPassword) ui.settingsMasterPassword.disabled = !enabled || !locked || state.settingsLockBusy;
    [ui.settingsNewMasterPassword, ui.settingsConfirmMasterPassword].forEach((input) => {
      if (input) input.disabled = enabled || state.settingsLockBusy;
    });

    if (!preserveStatus) {
      setSettingsLockStatus(!enabled
        ? t("settings_disabled_message")
        : t(locked ? "settings_locked_message" : "settings_unlocked_message"));
    }
    syncSettingsLockToSlots();
  }

  function bindSettingsLockControls() {
    const setBusy = (busy, preserveStatus = false) => {
      state.settingsLockBusy = busy;
      applySettingsLockState(preserveStatus);
    };

    const enableSettingsLock = async () => {
      if (isSettingsLockEnabled() || state.settingsLockBusy) return;
      const password = String(ui.settingsNewMasterPassword ? ui.settingsNewMasterPassword.value : "");
      const confirmation = String(ui.settingsConfirmMasterPassword ? ui.settingsConfirmMasterPassword.value : "");
      if (!password) {
        setSettingsLockStatus(t("settings_unlock_required"), true);
        ui.settingsNewMasterPassword?.focus();
        return;
      }
      if (password !== confirmation) {
        setSettingsLockStatus(t("settings_password_mismatch"), true);
        ui.settingsConfirmMasterPassword?.focus();
        return;
      }
      if (!supportsSettingsLockCrypto()) {
        setSettingsLockStatus(t("settings_crypto_unavailable"), true);
        return;
      }

      let failed = false;
      setBusy(true);
      try {
        const salt = new Uint8Array(16);
        window.crypto.getRandomValues(salt);
        const verifier = await deriveSettingsMasterVerifier(password, salt, settingsLockPBKDF2Iterations);
        const config = {
          version: 1,
          enabled: true,
          salt: bytesToBase64(salt),
          verifier,
          iterations: settingsLockPBKDF2Iterations,
        };
        if (!persistSettingsLockConfig(config)) {
          throw new Error("browser storage is unavailable");
        }
        state.settingsLockConfig = config;
        state.settingsUnlocked = true;
        persistSettingsUnlockSession();
        clearSettingsLockInputs();
      } catch (err) {
        failed = true;
        const message = err && err.message ? err.message : String(err || "unknown error");
        setSettingsLockStatus(t("settings_unlock_error", { error: message }), true);
      } finally {
        setBusy(false, failed);
      }
    };

    const unlockSettings = async () => {
      if (!isSettingsLocked() || state.settingsLockBusy) return;
      const password = String(ui.settingsMasterPassword ? ui.settingsMasterPassword.value : "");
      if (!password) {
        setSettingsLockStatus(t("settings_unlock_required"), true);
        ui.settingsMasterPassword?.focus();
        return;
      }

      let failed = false;
      setBusy(true);
      try {
        const config = state.settingsLockConfig;
        const verifier = await deriveSettingsMasterVerifier(password, base64ToBytes(config.salt), config.iterations);
        if (!constantTimeTextEqual(verifier, config.verifier)) {
          failed = true;
          setSettingsLockStatus(t("settings_unlock_failed"), true);
          return;
        }
        state.settingsUnlocked = true;
        persistSettingsUnlockSession();
        clearSettingsLockInputs();
      } catch (err) {
        failed = true;
        const message = err && err.message ? err.message : String(err || "unknown error");
        setSettingsLockStatus(t("settings_unlock_error", { error: message }), true);
      } finally {
        setBusy(false, failed);
      }
    };

    const relockSettings = () => {
      if (!isSettingsLockEnabled() || state.settingsLockBusy) return;
      state.settingsUnlocked = false;
      clearSettingsUnlockSession();
      clearSettingsLockInputs();
      applySettingsLockState();
    };

    const disableSettingsLock = () => {
      if (!isSettingsLockEnabled() || isSettingsLocked() || state.settingsLockBusy) return;
      if (!window.confirm(t("settings_disable_confirm"))) return;
      clearSettingsLockConfig();
      clearSettingsUnlockSession();
      state.settingsLockConfig = defaultSettingsLockConfig();
      state.settingsUnlocked = false;
      clearSettingsLockInputs();
      applySettingsLockState();
    };

    ui.settingsEnableButton?.addEventListener("click", () => { enableSettingsLock().catch(() => {}); });
    ui.settingsUnlockButton?.addEventListener("click", () => { unlockSettings().catch(() => {}); });
    ui.settingsMasterPassword?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        unlockSettings().catch(() => {});
      }
    });
    ui.settingsConfirmMasterPassword?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        enableSettingsLock().catch(() => {});
      }
    });
    ui.settingsRelockButton?.addEventListener("click", relockSettings);
    ui.settingsDisableButton?.addEventListener("click", disableSettingsLock);
  }

  function bindSettingsLockStorageSync() {
    window.addEventListener("storage", (event) => {
      if (event.storageArea !== localStorage || event.key !== settingsLockStorageKey) {
        return;
      }
      state.settingsLockConfig = loadSettingsLockConfig();
      state.settingsUnlocked = isSettingsUnlockSessionValid(state.settingsLockConfig);
      clearSettingsLockInputs();
      applySettingsLockState();
    });
  }

  function normalizeLogLevel(level) {
    return level === "warn" || level === "error" ? level : "info";
  }

  function appendMultiLog(source, text, level = "info") {
    if (!text || !ui.logBox) {
      return;
    }
    const ts = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = normalizeLogLevel(level);
    line.textContent = `[${ts}][${source || t("multi_log_main")}] ${text}`;
    ui.logBox.appendChild(line);
    ui.logBox.scrollTop = ui.logBox.scrollHeight;
  }

  function normalizeShortcut(value) {
    const text = String(value || "").trim();
    if (!text) {
      return "";
    }
    const parts = text.split("+").filter(Boolean);
    const code = parts.pop();
    if (!code || /^(Control|Shift|Alt|Meta)(Left|Right)?$/.test(code)) {
      return "";
    }
    const mods = new Set(parts.map((part) => part.toLowerCase()));
    const out = [];
    if (mods.has("ctrl")) out.push("Ctrl");
    if (mods.has("alt")) out.push("Alt");
    if (mods.has("shift")) out.push("Shift");
    if (mods.has("meta")) out.push("Meta");
    out.push(code);
    return out.join("+");
  }

  function defaultSlotShortcut(index) {
    return index === 9 ? "Digit0" : `Digit${index + 1}`;
  }

  function loadControls() {
    let stored = {};
    try {
      stored = JSON.parse(localStorage.getItem(settingsKey) || "{}") || {};
    } catch (_) {
      stored = {};
    }
    const slotShortcuts = Array.isArray(stored.slotShortcuts) ? stored.slotShortcuts : [];
    const selected = Array.isArray(stored.selected) ? stored.selected : [];
    const activeSettingsSlot = Number.parseInt(stored.activeSettingsSlot, 10);
    return {
      slotShortcuts: Array.from({ length: maxSlots }, (_, index) => normalizeShortcut(slotShortcuts[index]) || defaultSlotShortcut(index)),
      selected: Array.from({ length: maxSlots }, (_, index) => selected[index] !== false),
      broadcastShortcut: normalizeShortcut(stored.broadcastShortcut) || "Shift+Digit0",
      activeSettingsSlot: Number.isInteger(activeSettingsSlot)
        ? Math.min(maxSlots - 1, Math.max(0, activeSettingsSlot))
        : 0,
    };
  }

  function persistControls() {
    try {
      localStorage.setItem(settingsKey, JSON.stringify(state.controls));
    } catch (_) {
      // Local shortcut preferences are optional.
    }
  }

  function slotFrameURL(index) {
    const url = new URL(basePath ? `${basePath}/` : "/", window.location.origin);
    url.searchParams.set("embed", "1");
    url.searchParams.set("slot", String(index + 1));
    return url.toString();
  }

  function createSlot(index) {
    const card = document.createElement("article");
    card.className = "multi-slot-card";
    card.dataset.slot = String(index + 1);

    const head = document.createElement("div");
    head.className = "multi-slot-head";
    const title = document.createElement("h2");
    title.className = "multi-slot-title";
    title.textContent = t("multi_slot", { index: index + 1 });
    const selectLabel = document.createElement("label");
    selectLabel.className = "checkbox-row multi-slot-select";
    const selected = document.createElement("input");
    selected.type = "checkbox";
    selected.checked = !!state.controls.selected[index];
    const selectedText = document.createElement("span");
    selectedText.textContent = t("multi_selected");
    selectLabel.append(selected, selectedText);
    head.append(title, selectLabel);

    const status = document.createElement("dl");
    status.className = "multi-slot-status";
    const channelPair = makeStatusPair(t("multi_channel"), "-");
    const senderPair = makeStatusPair(t("multi_sender"), "-");
    const connectionPair = makeStatusPair(t("multi_connection"), t("multi_offline"));
    const talkerPair = makeStatusPair(t("multi_talker"), t("multi_none"));
    status.append(channelPair.row, senderPair.row, connectionPair.row, talkerPair.row);

    const controls = document.createElement("div");
    controls.className = "multi-slot-controls";
    const ptt = document.createElement("button");
    ptt.className = "ptt multi-ptt";
    ptt.type = "button";
    ptt.disabled = true;
    const pttText = document.createElement("span");
    ptt.appendChild(pttText);
    const shortcut = document.createElement("button");
    shortcut.className = "ghost multi-shortcut-button";
    shortcut.type = "button";
    const settingsButton = document.createElement("button");
    settingsButton.className = "ghost multi-settings-open";
    settingsButton.type = "button";
    controls.append(ptt, shortcut, settingsButton);

    card.append(head, status, controls);
    ui.slots.appendChild(card);

    const settingsTab = document.createElement("button");
    settingsTab.className = "multi-settings-tab";
    settingsTab.type = "button";
    settingsTab.id = `multi-slot-tab-${index + 1}`;
    settingsTab.setAttribute("role", "tab");
    settingsTab.setAttribute("aria-controls", `multi-slot-panel-${index + 1}`);
    settingsTab.textContent = t("multi_slot", { index: index + 1 });

    const settingsPane = document.createElement("div");
    settingsPane.className = "multi-settings-pane";
    settingsPane.id = `multi-slot-panel-${index + 1}`;
    settingsPane.setAttribute("role", "tabpanel");
    settingsPane.setAttribute("aria-labelledby", settingsTab.id);
    settingsPane.hidden = true;
    const frame = document.createElement("iframe");
    frame.className = "multi-slot-frame";
    frame.title = `${t("multi_slot", { index: index + 1 })} ${t("multi_slot_settings")}`;
    frame.src = slotFrameURL(index);
    frame.loading = "eager";
    settingsPane.appendChild(frame);
    ui.settingsTabs.appendChild(settingsTab);
    ui.settingsPanes.appendChild(settingsPane);

    const slot = {
      index,
      card,
      selected,
      channelValue: channelPair.value,
      senderValue: senderPair.value,
      connectionValue: connectionPair.value,
      talkerValue: talkerPair.value,
      ptt,
      pttText,
      shortcut,
      settingsButton,
      settingsTab,
      settingsPane,
      frame,
      connected: false,
      channelId: 0,
      senderId: 0,
      talkers: [],
      channelLabel: "-",
      senderLabel: "-",
      talkerLabels: Object.create(null),
      selfSenderId: 0,
      talkAllowed: false,
      micVolume: 200,
      ready: false,
    };

    selected.addEventListener("change", () => {
      state.controls.selected[index] = selected.checked;
      persistControls();
      updateSlotView(slot);
      updateBroadcastView();
      queueReconcile();
    });
    shortcut.addEventListener("click", () => beginShortcutCapture({ kind: "slot", index }));
    settingsButton.addEventListener("click", () => {
      activateSettingsSlot(index, true);
      releaseKeyboardFocus();
    });
    settingsTab.addEventListener("click", () => {
      activateSettingsSlot(index);
      releaseKeyboardFocus();
    });
    bindHoldPTT(ptt, `slot:${index}`, () => [index]);
    frame.addEventListener("load", () => {
      slot.ready = true;
      postSettingsLockState(slot);
      postSlotCommand(slot, { command: "request-state" });
    });

    updateSlotView(slot);
    return slot;
  }

  function activateSettingsSlot(index, scrollIntoView = false) {
    const selectedIndex = Math.min(maxSlots - 1, Math.max(0, Number(index) || 0));
    state.controls.activeSettingsSlot = selectedIndex;
    state.slots.forEach((slot) => {
      const active = slot.index === selectedIndex;
      slot.settingsTab.classList.toggle("active", active);
      slot.settingsTab.setAttribute("aria-selected", active ? "true" : "false");
      slot.settingsTab.tabIndex = active ? 0 : -1;
      slot.settingsPane.hidden = !active;
    });
    persistControls();
    if (scrollIntoView) {
      const section = ui.settingsTabs.closest(".multi-settings-card");
      if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function makeStatusPair(label, value) {
    const row = document.createElement("div");
    const key = document.createElement("dt");
    key.textContent = label;
    const val = document.createElement("dd");
    val.textContent = value;
    row.append(key, val);
    return { row, value: val };
  }

  function postSlotCommand(slot, payload) {
    if (!slot || !slot.frame || !slot.frame.contentWindow) {
      return;
    }
    slot.frame.contentWindow.postMessage({ type: `${messageNamespace}command`, slot: slot.index + 1, ...payload }, targetOrigin);
  }

  function postSettingsLockState(slot) {
    if (!slot || !slot.frame || !slot.frame.contentWindow) {
      return;
    }
    slot.frame.contentWindow.postMessage({
      type: `${messageNamespace}settings-lock`,
      slot: slot.index + 1,
      unlocked: !isSettingsLocked(),
    }, targetOrigin);
  }

  function syncSettingsLockToSlots() {
    state.slots.forEach((slot) => postSettingsLockState(slot));
  }

  function slotChannelLabel(slot) {
    const label = String(slot && slot.channelLabel ? slot.channelLabel : "").trim();
    return label || (slot && slot.channelId > 0 ? String(slot.channelId) : "-");
  }

  function slotSenderLabel(slot) {
    const label = String(slot && slot.senderLabel ? slot.senderLabel : "").trim();
    return label || (slot && slot.senderId > 0 ? String(slot.senderId) : "-");
  }

  function slotTalkerLabel(slot, talkerId) {
    const labels = slot && slot.talkerLabels && typeof slot.talkerLabels === "object" ? slot.talkerLabels : null;
    const label = labels ? String(labels[String(talkerId)] || "").trim() : "";
    return label || String(talkerId);
  }

  function updateSlotView(slot) {
    const shortcut = state.controls.slotShortcuts[slot.index];
    slot.card.classList.toggle("selected", !!state.controls.selected[slot.index]);
    slot.card.classList.toggle("connected", slot.connected);
    slot.card.classList.toggle("talking", state.pressedSlots.has(slot.index));
    slot.selected.checked = !!state.controls.selected[slot.index];
    slot.channelValue.textContent = slotChannelLabel(slot);
    slot.senderValue.textContent = slotSenderLabel(slot);
    slot.connectionValue.textContent = slot.connected ? t("multi_connected") : (slot.ready ? t("multi_offline") : t("multi_connecting"));
    slot.connectionValue.className = slot.connected ? "ok" : "warn";
    slot.talkerValue.textContent = remoteTalkerText(slot);
    slot.ptt.disabled = !slot.connected || state.shortcutEditEnabled;
    slot.pttText.textContent = t("multi_hold_slot", { shortcut: formatShortcut(shortcut) });
    slot.shortcut.textContent = formatShortcut(shortcut);
    slot.shortcut.disabled = !state.shortcutEditEnabled;
    slot.shortcut.classList.toggle("editing", state.shortcutEditEnabled);
    slot.shortcut.setAttribute("aria-label", `${t("multi_set_shortcut")}: ${formatShortcut(shortcut)}`);
    slot.shortcut.title = state.shortcutEditEnabled ? t("multi_set_shortcut") : t("multi_shortcuts_locked");
    slot.settingsButton.textContent = t("multi_open_settings");
  }

  function remoteTalkerText(slot) {
    const talkers = Array.isArray(slot.talkers) ? slot.talkers.filter((id) => id > 0 && id !== slot.selfSenderId) : [];
    return talkers.length ? talkers.map((talkerId) => slotTalkerLabel(slot, talkerId)).join(", ") : t("multi_none");
  }

  function updateBroadcastView() {
    const selected = state.slots.filter((slot) => state.controls.selected[slot.index]);
    const connected = selected.filter((slot) => slot.connected);
    ui.broadcastSummary.textContent = connected.length
      ? t("multi_selected_connected", { selected: selected.length, connected: connected.length })
      : t("multi_no_selected_connected");
    const shortcut = state.controls.broadcastShortcut;
    ui.broadcastShortcut.textContent = formatShortcut(shortcut);
    ui.broadcastShortcut.disabled = !state.shortcutEditEnabled;
    ui.broadcastShortcut.classList.toggle("editing", state.shortcutEditEnabled);
    ui.broadcastShortcut.setAttribute("aria-label", `${t("multi_set_shortcut")}: ${formatShortcut(shortcut)}`);
    ui.broadcastShortcut.title = state.shortcutEditEnabled ? t("multi_set_shortcut") : t("multi_shortcuts_locked");
    ui.broadcastPtt.disabled = connected.length === 0 || state.shortcutEditEnabled;
    ui.broadcastPttLabel.textContent = t("multi_hold_broadcast", { shortcut: formatShortcut(shortcut) });
    renderReceivingList();
  }

  function renderReceivingList() {
    ui.receivingList.textContent = "";
    const active = state.slots.filter((slot) => slot.connected && remoteTalkerText(slot) !== t("multi_none"));
    if (active.length === 0) {
      const empty = document.createElement("p");
      empty.className = "multi-receiving-empty";
      empty.textContent = t("multi_receiver_none");
      ui.receivingList.appendChild(empty);
      return;
    }
    active.forEach((slot) => {
      const item = document.createElement("div");
      item.className = "multi-receiving-item";
      item.textContent = t("multi_receiver_slot", {
        slot: slot.index + 1,
        channel: slotChannelLabel(slot),
        talkers: remoteTalkerText(slot),
      });
      ui.receivingList.appendChild(item);
    });
  }

  function formatShortcut(shortcut) {
    const parts = normalizeShortcut(shortcut).split("+");
    const code = parts.pop() || "-";
    const displayCode = code.startsWith("Digit")
      ? code.slice(5)
      : code.startsWith("Key")
        ? code.slice(3)
        : code === "Space"
          ? "Space"
          : code;
    return [...parts, displayCode].join("+");
  }

  function resetShortcutEditTimer() {
    if (state.shortcutEditTimer) {
      window.clearTimeout(state.shortcutEditTimer);
      state.shortcutEditTimer = null;
    }
    if (!state.shortcutEditEnabled) {
      return;
    }
    state.shortcutEditTimer = window.setTimeout(() => {
      state.shortcutEditTimer = null;
      setShortcutEditEnabled(false);
    }, shortcutEditTimeoutMs);
  }

  function updateShortcutEditView() {
    const editing = state.shortcutEditEnabled;
    ui.shortcutEditButton.textContent = editing ? t("multi_finish_shortcut_edit") : t("multi_edit_shortcuts");
    ui.shortcutEditButton.classList.toggle("active", editing);
    ui.shortcutEditButton.setAttribute("aria-pressed", editing ? "true" : "false");
    ui.shortcutEditStatus.textContent = state.captureTarget
      ? t("multi_shortcut_capture")
      : (editing ? t("multi_shortcuts_editing") : t("multi_shortcuts_locked"));
    state.slots.forEach(updateSlotView);
    updateBroadcastView();
  }

  function setShortcutEditEnabled(enabled) {
    const next = !!enabled;
    if (!next) {
      state.captureTarget = null;
      if (state.shortcutEditTimer) {
        window.clearTimeout(state.shortcutEditTimer);
        state.shortcutEditTimer = null;
      }
    }
    state.shortcutEditEnabled = next;
    if (next) {
      stopAllPTT();
      resetShortcutEditTimer();
    }
    updateShortcutEditView();
    releaseKeyboardFocus();
  }

  function beginShortcutCapture(target) {
    if (!state.shortcutEditEnabled) {
      return;
    }
    state.captureTarget = target;
    resetShortcutEditTimer();
    if (target.kind === "slot") {
      state.slots[target.index].shortcut.textContent = t("multi_press_key");
    } else {
      ui.broadcastShortcut.textContent = t("multi_press_key");
    }
    updateShortcutEditView();
    releaseKeyboardFocus();
  }

  function applyCapturedShortcut(shortcut) {
    const target = state.captureTarget;
    if (!target) {
      return false;
    }
    state.captureTarget = null;
    if (target.kind === "slot") {
      state.controls.slotShortcuts[target.index] = shortcut;
    } else {
      state.controls.broadcastShortcut = shortcut;
    }
    persistControls();
    resetShortcutEditTimer();
    updateShortcutEditView();
    releaseKeyboardFocus();
    return true;
  }

  function shortcutFromEvent(event) {
    const code = String(event.code || "");
    if (!code || /^(Control|Shift|Alt|Meta)(Left|Right)?$/.test(code)) {
      return "";
    }
    const parts = [];
    if (event.ctrlKey) parts.push("Ctrl");
    if (event.altKey) parts.push("Alt");
    if (event.shiftKey) parts.push("Shift");
    if (event.metaKey) parts.push("Meta");
    parts.push(code);
    return normalizeShortcut(parts.join("+"));
  }

  function isEditableElement(element) {
    if (!element || typeof element.closest !== "function") {
      return false;
    }
    return !!element.closest("input, textarea, select, [contenteditable='true']");
  }

  function releaseKeyboardFocus() {
    const active = document.activeElement;
    if (isEditableElement(active) && typeof active.blur === "function") {
      active.blur();
    }
    if (ui.main && document.activeElement !== ui.main && typeof ui.main.focus === "function") {
      ui.main.focus({ preventScroll: true });
    }
  }

  function installKeyboardFocusRelease() {
    document.addEventListener("change", (event) => {
      if (isEditableElement(event.target)) {
        window.requestAnimationFrame(releaseKeyboardFocus);
      }
    }, true);
    document.addEventListener("keydown", (event) => {
      if ((event.code === "Enter" || event.code === "Escape") && isEditableElement(event.target)) {
        window.requestAnimationFrame(releaseKeyboardFocus);
      }
    }, true);
    document.addEventListener("pointerdown", (event) => {
      if (!state.shortcutEditEnabled || !event.target || typeof event.target.closest !== "function") {
        return;
      }
      if (!event.target.closest("#multiShortcutEdit, .multi-shortcut-button")) {
        setShortcutEditEnabled(false);
      }
    }, true);
  }

  function handleShortcutEvent(payload, originalEvent = null) {
    const phase = payload.phase === "up" ? "up" : "down";
    const shortcut = shortcutFromEvent(payload);
    if (!shortcut) {
      return false;
    }
    if (phase === "down" && payload.code === "Escape" && state.shortcutEditEnabled) {
      if (originalEvent) originalEvent.preventDefault();
      setShortcutEditEnabled(false);
      return true;
    }
    if (phase === "down" && state.captureTarget) {
      if (originalEvent) originalEvent.preventDefault();
      applyCapturedShortcut(shortcut);
      return true;
    }
    if (state.shortcutEditEnabled) {
      if (originalEvent && !payload.editable) originalEvent.preventDefault();
      return false;
    }
    if (payload.editable) {
      return false;
    }
    const slotTargets = state.slots
      .filter((slot) => state.controls.slotShortcuts[slot.index] === shortcut)
      .map((slot) => slot.index);
    const broadcast = state.controls.broadcastShortcut === shortcut
      ? state.slots.filter((slot) => state.controls.selected[slot.index]).map((slot) => slot.index)
      : [];
    const targets = Array.from(new Set([...slotTargets, ...broadcast]));
    if (targets.length === 0) {
      return false;
    }
    if (originalEvent) originalEvent.preventDefault();
    const source = `key:${shortcut}`;
    if (phase === "down") {
      setActiveSource(source, targets);
    } else {
      clearActiveSource(source);
    }
    return true;
  }

  function bindHoldPTT(button, source, targets) {
    let pointerId = null;
    const press = (event) => {
      if (button.disabled || (event.pointerType === "mouse" && event.button !== 0)) {
        return;
      }
      event.preventDefault();
      releaseKeyboardFocus();
      pointerId = event.pointerId;
      try {
        button.setPointerCapture(pointerId);
      } catch (_) {
        // Pointer capture is an optional enhancement.
      }
      setActiveSource(source, targets());
    };
    const release = (event) => {
      if (pointerId !== null && event && event.pointerId !== undefined && event.pointerId !== pointerId) {
        return;
      }
      if (event) event.preventDefault();
      clearActiveSource(source);
      pointerId = null;
    };
    button.addEventListener("pointerdown", press);
    button.addEventListener("pointerup", release);
    button.addEventListener("pointercancel", release);
    button.addEventListener("lostpointercapture", release);
    button.addEventListener("pointerleave", (event) => {
      if (event.pointerType === "mouse") release(event);
    });
    button.addEventListener("contextmenu", (event) => event.preventDefault());
  }

  function setActiveSource(source, targets) {
    const normalized = Array.from(new Set(targets)).filter((index) => Number.isInteger(index) && index >= 0 && index < state.slots.length);
    if (normalized.length === 0) return;
    state.activeSources.set(source, normalized);
    queueReconcile();
  }

  function clearActiveSource(source) {
    if (!state.activeSources.delete(source)) return;
    queueReconcile();
  }

  function stopAllPTT() {
    if (state.activeSources.size === 0 && state.pressedSlots.size === 0) return;
    state.activeSources.clear();
    queueReconcile();
  }

  function desiredPressedSlots() {
    const desired = new Set();
    state.activeSources.forEach((targets) => {
      targets.forEach((index) => {
        const slot = state.slots[index];
        if (slot && slot.connected) desired.add(index);
      });
    });
    return desired;
  }

  function queueReconcile() {
    state.reconcileQueued = true;
    if (state.reconcileRunning) return;
    void reconcileTransmitState();
  }

  async function reconcileTransmitState() {
    if (state.reconcileRunning) return;
    state.reconcileRunning = true;
    try {
      while (state.reconcileQueued) {
        state.reconcileQueued = false;
        const desired = desiredPressedSlots();
        if (desired.size > 0) {
          try {
            if (!state.mic) {
              state.mic = new SharedMicCapture(distributeMicFrame);
            }
            const first = state.slots[desired.values().next().value];
            state.mic.setGainPercent(first ? first.micVolume : 200);
            await state.mic.start();
            state.micError = "";
          } catch (err) {
            const nextMicError = err && err.message ? err.message : String(err);
            if (state.micError !== nextMicError) {
              appendMultiLog(t("multi_log_main"), t("multi_shared_mic_error", { error: nextMicError }), "error");
            }
            state.micError = nextMicError;
            state.activeSources.clear();
            desired.clear();
          }
        }

        const current = new Set(state.pressedSlots);
        current.forEach((index) => {
          if (!desired.has(index)) {
            const slot = state.slots[index];
            postSlotCommand(slot, { command: "ptt", pressed: false });
            state.pressedSlots.delete(index);
          }
        });
        desired.forEach((index) => {
          if (!state.pressedSlots.has(index)) {
            const slot = state.slots[index];
            postSlotCommand(slot, { command: "ptt", pressed: true });
            state.pressedSlots.add(index);
          }
        });
        state.slots.forEach(updateSlotView);
        updateBroadcastView();
        updateMicStatus();
      }
    } finally {
      state.reconcileRunning = false;
    }
  }

  function updateMicStatus() {
    if (state.micError) {
      ui.micStatus.textContent = t("multi_shared_mic_error", { error: state.micError });
      ui.micStatus.className = "multi-mic-status error";
      return;
    }
    if (state.pressedSlots.size > 0) {
      ui.micStatus.textContent = t("multi_shared_mic_active", { count: state.pressedSlots.size });
      ui.micStatus.className = "multi-mic-status ok";
      return;
    }
    ui.micStatus.textContent = state.mic && state.mic.started ? t("multi_shared_mic_ready") : "";
    ui.micStatus.className = "multi-mic-status";
  }

  function distributeMicFrame(frame) {
    if (!(frame instanceof Uint8Array) || frame.byteLength === 0) return;
    state.pressedSlots.forEach((index) => {
      const slot = state.slots[index];
      if (!slot || !slot.connected || !slot.frame || !slot.frame.contentWindow) return;
      const copy = frame.buffer.slice(frame.byteOffset, frame.byteOffset + frame.byteLength);
      slot.frame.contentWindow.postMessage({
        type: `${messageNamespace}audio`,
        slot: index + 1,
        frame: copy,
      }, targetOrigin);
    });
  }

  function handleSlotMessage(event) {
    if (event.origin !== targetOrigin || !event.data || typeof event.data !== "object") return;
    const data = event.data;
    if (data.type === `${messageNamespace}state`) {
      const slot = state.slots.find((item) => item.frame && item.frame.contentWindow === event.source);
      if (!slot || Number(data.slot) !== slot.index + 1) return;
      const snapshot = data.state || {};
      slot.ready = true;
      slot.connected = !!snapshot.connected;
      slot.channelId = Math.max(0, Number(snapshot.channelId) || 0);
      slot.senderId = Math.max(0, Number(snapshot.senderId) || 0);
      slot.selfSenderId = Math.max(0, Number(snapshot.selfSenderId) || 0);
      slot.talkers = Array.isArray(snapshot.activeTalkers)
        ? snapshot.activeTalkers.map((value) => Number(value) || 0).filter((value) => value > 0)
        : [];
      slot.channelLabel = typeof snapshot.channelLabel === "string" ? snapshot.channelLabel : (slot.channelId > 0 ? String(slot.channelId) : "-");
      slot.senderLabel = typeof snapshot.senderLabel === "string" ? snapshot.senderLabel : (slot.senderId > 0 ? String(slot.senderId) : "-");
      slot.talkerLabels = snapshot.talkerLabels && typeof snapshot.talkerLabels === "object"
        ? snapshot.talkerLabels
        : Object.create(null);
      slot.talkAllowed = !!snapshot.talkAllowed;
      slot.micVolume = Math.min(300, Math.max(0, Number(snapshot.micVolume) || 200));
      updateSlotView(slot);
      updateBroadcastView();
      queueReconcile();
      return;
    }
    if (data.type === `${messageNamespace}log`) {
      const slot = state.slots.find((item) => item.frame && item.frame.contentWindow === event.source);
      if (slot && Number(data.slot) === slot.index + 1 && typeof data.text === "string") {
        appendMultiLog(t("multi_log_slot", { slot: slot.index + 1 }), data.text, data.level);
      }
      return;
    }
    if (data.type === `${messageNamespace}interaction`) {
      const slot = state.slots.find((item) => item.frame && item.frame.contentWindow === event.source);
      if (slot && Number(data.slot) === slot.index + 1 && state.shortcutEditEnabled) {
        setShortcutEditEnabled(false);
      }
      return;
    }
    if (data.type === `${messageNamespace}key`) {
      handleShortcutEvent(data, null);
    }
  }

  class SharedMicCapture {
    constructor(onFrame) {
      this.onFrame = onFrame;
      this.ctx = null;
      this.stream = null;
      this.source = null;
      this.inputGain = null;
      this.processor = null;
      this.workletNode = null;
      this.silence = null;
      this.started = false;
      this.gainPercent = 200;
      this.inputBuffer = [];
      this.inputStart = 0;
      this.resampleOffset = 0;
      this.pcmBuffer = [];
      this.pcmStart = 0;
      this.downsampleRatio = 6;
      this.lpState = 0;
    }

    async start() {
      if (this.started) {
        await this.resume();
        return;
      }
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function") {
        throw new Error("microphone API is not supported by this browser");
      }
      this.stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: { ideal: 1 },
          echoCancellation: false,
          noiseSuppression: false,
          autoGainControl: false,
        },
      });
      this.ctx = new (window.AudioContext || window.webkitAudioContext)();
      this.downsampleRatio = this.ctx.sampleRate / 8000;
      this.source = this.ctx.createMediaStreamSource(this.stream);
      this.inputGain = this.ctx.createGain();
      this.inputGain.gain.value = this.gainPercent / 100;
      this.silence = this.ctx.createGain();
      this.silence.gain.value = 0;
      this.source.connect(this.inputGain);
      if (!(await this.tryStartWithWorklet())) {
        this.processor = this.ctx.createScriptProcessor(2048, 1, 1);
        this.inputGain.connect(this.processor);
        this.processor.connect(this.silence);
        this.silence.connect(this.ctx.destination);
        this.processor.onaudioprocess = (event) => this.pushInput(event.inputBuffer.getChannelData(0));
      }
      this.started = true;
      await this.resume();
    }

    async tryStartWithWorklet() {
      if (!this.ctx || !this.inputGain || !this.silence || !this.ctx.audioWorklet || typeof AudioWorkletNode === "undefined") return false;
      try {
        const workletURL = `${basePath}/mic-capture-worklet.js`;
        await this.ctx.audioWorklet.addModule(workletURL);
        this.workletNode = new AudioWorkletNode(this.ctx, "incomudon-mic-capture", {
          numberOfInputs: 1,
          numberOfOutputs: 1,
          outputChannelCount: [1],
        });
        this.workletNode.port.onmessage = (event) => {
          const data = event.data;
          if (data instanceof ArrayBuffer) this.onFrame(new Uint8Array(data));
          else if (ArrayBuffer.isView(data)) this.onFrame(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        };
        this.inputGain.connect(this.workletNode);
        this.workletNode.connect(this.silence);
        this.silence.connect(this.ctx.destination);
        return true;
      } catch (_) {
        if (this.workletNode) {
          try { this.workletNode.disconnect(); } catch (_) {}
          this.workletNode = null;
        }
        return false;
      }
    }

    async resume() {
      if (this.ctx && this.ctx.state === "suspended") await this.ctx.resume();
    }

    setGainPercent(percent) {
      this.gainPercent = Math.min(300, Math.max(0, Number(percent) || 0));
      if (this.inputGain) this.inputGain.gain.value = this.gainPercent / 100;
    }

    pushInput(input) {
      for (let i = 0; i < input.length; i += 1) this.inputBuffer.push(input[i]);
      let available = this.inputBuffer.length - this.inputStart;
      while (this.resampleOffset + this.downsampleRatio <= available - 1) {
        const base = this.inputStart + Math.floor(this.resampleOffset);
        const frac = this.resampleOffset - Math.floor(this.resampleOffset);
        const a = this.inputBuffer[base];
        const b = this.inputBuffer[Math.min(base + 1, this.inputBuffer.length - 1)];
        this.lpState += 0.22 * ((a + (b - a) * frac) - this.lpState);
        this.pcmBuffer.push(floatToInt16(this.lpState));
        this.resampleOffset += this.downsampleRatio;
        available = this.inputBuffer.length - this.inputStart;
      }
      const consumed = Math.floor(this.resampleOffset);
      if (consumed > 0) {
        this.inputStart += consumed;
        this.resampleOffset -= consumed;
      }
      if (this.inputStart > 4096) {
        this.inputBuffer = this.inputBuffer.slice(this.inputStart);
        this.inputStart = 0;
      }
      while (this.pcmBuffer.length - this.pcmStart >= 160) {
        const samples = this.pcmBuffer.slice(this.pcmStart, this.pcmStart + 160);
        this.pcmStart += 160;
        this.onFrame(int16ToPCMBytes(samples));
      }
      if (this.pcmStart > 4096) {
        this.pcmBuffer = this.pcmBuffer.slice(this.pcmStart);
        this.pcmStart = 0;
      }
    }

    stop() {
      if (this.processor) {
        this.processor.onaudioprocess = null;
        this.processor.disconnect();
      }
      if (this.workletNode) {
        this.workletNode.port.onmessage = null;
        this.workletNode.disconnect();
      }
      if (this.source) this.source.disconnect();
      if (this.inputGain) this.inputGain.disconnect();
      if (this.silence) this.silence.disconnect();
      if (this.stream) this.stream.getTracks().forEach((track) => track.stop());
      if (this.ctx) this.ctx.close().catch(() => {});
      this.ctx = null;
      this.stream = null;
      this.source = null;
      this.inputGain = null;
      this.processor = null;
      this.workletNode = null;
      this.silence = null;
      this.started = false;
    }
  }

  function floatToInt16(value) {
    const clamped = Math.max(-1, Math.min(1, value));
    return clamped < 0 ? Math.round(clamped * 32768) : Math.round(clamped * 32767);
  }

  function int16ToPCMBytes(samples) {
    const out = new Uint8Array(samples.length * 2);
    const view = new DataView(out.buffer);
    for (let i = 0; i < samples.length; i += 1) view.setInt16(i * 2, samples[i], true);
    return out;
  }

  async function loadLocale() {
    let locale = "";
    try { locale = localStorage.getItem(localeStorageKey) || ""; } catch (_) {}
    locale = String(locale).toLowerCase().startsWith("ja") ? "ja" : "en";
    try {
      const response = await fetch(`${basePath}/locales/${locale}.json`, { cache: "no-store" });
      if (response.ok) strings = { ...fallbackStrings, ...(await response.json()) };
    } catch (_) {
      // English fallback is intentionally self-contained.
    }
    state.locale = locale;
    document.documentElement.lang = locale;
  }

  function applyStrings() {
    document.title = t("app_title");
    ui.title.textContent = t("header_title");
    ui.languageLabel.textContent = t("language");
    ui.languageSelect.value = state.locale;
    ui.singleChannelLink.textContent = t("multi_single_channel");
    ui.broadcastHeading.textContent = t("multi_broadcast_ptt");
    ui.broadcastShortcutLabel.textContent = t("multi_shortcut");
    ui.stopAll.textContent = t("multi_stop_all");
    ui.receivingHeading.textContent = t("multi_receiving");
    ui.eventsHeading.textContent = t("events");
    ui.clearLog.textContent = t("clear");
    ui.settingsHeading.textContent = t("multi_slot_settings");
    ui.settingsLead.textContent = t("multi_settings_lead");
    applySettingsLockState();
  }

  async function init() {
    await loadLocale();
    applyStrings();
    bindSettingsLockControls();
    bindSettingsLockStorageSync();
    for (let index = 0; index < maxSlots; index += 1) state.slots.push(createSlot(index));
    activateSettingsSlot(state.controls.activeSettingsSlot);
    bindHoldPTT(ui.broadcastPtt, "broadcast", () => state.slots.filter((slot) => state.controls.selected[slot.index]).map((slot) => slot.index));
    updateShortcutEditView();
    ui.broadcastShortcut.addEventListener("click", () => beginShortcutCapture({ kind: "broadcast" }));
    ui.shortcutEditButton.addEventListener("click", () => setShortcutEditEnabled(!state.shortcutEditEnabled));
    ui.stopAll.addEventListener("click", () => {
      stopAllPTT();
      releaseKeyboardFocus();
    });
    ui.clearLog.addEventListener("click", () => {
      ui.logBox.textContent = "";
      releaseKeyboardFocus();
    });
    ui.languageSelect.addEventListener("change", () => {
      const locale = ui.languageSelect.value === "ja" ? "ja" : "en";
      try { localStorage.setItem(localeStorageKey, locale); } catch (_) {}
      if (locale !== state.locale) window.location.reload();
    });
    window.addEventListener("message", handleSlotMessage);
    installKeyboardFocusRelease();
    window.addEventListener("keydown", (event) => {
      if (event.repeat) return;
      handleShortcutEvent({
        phase: "down",
        code: event.code,
        ctrlKey: event.ctrlKey,
        altKey: event.altKey,
        shiftKey: event.shiftKey,
        metaKey: event.metaKey,
        editable: isEditableElement(event.target),
      }, event);
    }, true);
    window.addEventListener("keyup", (event) => {
      handleShortcutEvent({
        phase: "up",
        code: event.code,
        ctrlKey: event.ctrlKey,
        altKey: event.altKey,
        shiftKey: event.shiftKey,
        metaKey: event.metaKey,
        editable: isEditableElement(event.target),
      }, event);
    }, true);
    window.addEventListener("blur", stopAllPTT);
    window.addEventListener("beforeunload", () => {
      stopAllPTT();
      if (state.mic) state.mic.stop();
    });
    updateBroadcastView();
    updateMicStatus();
  }

  void init();
})();