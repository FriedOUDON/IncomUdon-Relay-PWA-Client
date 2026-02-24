(() => {
  const basePath = document.body.dataset.basePath || "";
  const fixedRelayEnabled = document.body.dataset.fixedRelayEnabled === "1";
  const fixedRelayHost = String(document.body.dataset.fixedRelayHost || "").trim();
  const fixedRelayPortRaw = Number.parseInt(document.body.dataset.fixedRelayPort || "", 10);
  const fixedRelayPort = Number.isFinite(fixedRelayPortRaw) && fixedRelayPortRaw > 0 ? fixedRelayPortRaw : 50000;
  const wsTokenRequired = document.body.dataset.wsTokenRequired === "1";
  const authMode = String(document.body.dataset.authMode || "none").trim().toLowerCase();
  const initialCodec2Ready = document.body.dataset.codec2Ready === "1";
  const initialOpusReady = document.body.dataset.opusReady === "1";

  const txCodecPCM = "pcm";
  const txCodecCodec2 = "codec2";
  const txCodecOpus = "opus";
  const codec2BitrateOptions = [450, 700, 1600, 2400, 3200];
  const opusBitrateOptions = [6000, 8000, 12000, 16000, 20000, 64000, 96000, 128000];

  const ui = {
    titleMain: document.getElementById("titleMain"),
    languageSelect: document.getElementById("languageSelect"),
    relayHost: document.getElementById("relayHost"),
    relayPort: document.getElementById("relayPort"),
    channelId: document.getElementById("channelId"),
    senderId: document.getElementById("senderId"),
    password: document.getElementById("password"),
    cryptoMode: document.getElementById("cryptoMode"),
    codecMode: document.getElementById("codecMode"),
    browserCodec: document.getElementById("browserCodec"),
    txCodec: document.getElementById("txCodec"),
    optionTxCodecPcm: document.getElementById("optionTxCodecPcm"),
    optionTxCodecCodec2: document.getElementById("optionTxCodecCodec2"),
    optionTxCodecOpus: document.getElementById("optionTxCodecOpus"),
    codec2Lib: document.getElementById("codec2Lib"),
    opusLib: document.getElementById("opusLib"),
    pcmOnly: document.getElementById("pcmOnly"),
    connectBtn: document.getElementById("connectBtn"),
    disconnectBtn: document.getElementById("disconnectBtn"),
    pttButton: document.getElementById("pttButton"),
    clearLogBtn: document.getElementById("clearLogBtn"),
    connectionStatus: document.getElementById("connectionStatus"),
    talkerStatus: document.getElementById("talkerStatus"),
    logBox: document.getElementById("logBox"),
    cuePttOnEnabled: document.getElementById("cuePttOnEnabled"),
    cuePttOffEnabled: document.getElementById("cuePttOffEnabled"),
    cueCarrierEnabled: document.getElementById("cueCarrierEnabled"),
    cuePttOnUrl: document.getElementById("cuePttOnUrl"),
    cuePttOffUrl: document.getElementById("cuePttOffUrl"),
    cueCarrierUrl: document.getElementById("cueCarrierUrl"),
    cuePttOnFile: document.getElementById("cuePttOnFile"),
    cuePttOffFile: document.getElementById("cuePttOffFile"),
    cueCarrierFile: document.getElementById("cueCarrierFile"),
    cuePttOnTest: document.getElementById("cuePttOnTest"),
    cuePttOffTest: document.getElementById("cuePttOffTest"),
    cueCarrierTest: document.getElementById("cueCarrierTest"),
    cuePttOnReset: document.getElementById("cuePttOnReset"),
    cuePttOffReset: document.getElementById("cuePttOffReset"),
    cueCarrierReset: document.getElementById("cueCarrierReset"),
    audioTxSlotCount: document.getElementById("audioTxSlotCount"),
    audioTxSlots: document.getElementById("audioTxSlots"),
    logoutBtn: document.getElementById("logoutBtn"),
  };

  const settingsStorageKey = "incomudon.pwa.settings.v1";
  const wsTokenStorageKey = "incomudon.pwa.ws_token.v1";
  const localeStorageKey = "incomudon.pwa.locale.v1";
  const fallbackLocale = "en";
  const supportedUiLocales = ["en", "ja"];
  const wsToken = initializeWSToken();
  const englishFallbackStrings = {
    app_title: "IncomUdon Relay PWA Client",
    header_title: "Relay PWA Client",
    language: "Language",
    relay_host: "Relay Host",
    relay_port: "Relay Port",
    channel_id: "Channel ID",
    sender_id: "Sender ID (random if empty)",
    password: "Password",
    crypto_mode: "Crypto Mode",
    codec_mode: "Transmit Bitrate",
    browser_codec: "Browser Codec",
    tx_codec: "TX Codec",
    tx_codec_pcm: "pcm",
    tx_codec_codec2: "codec2",
    tx_codec_opus: "opus",
    uplink_opus_optional: "opus (optional)",
    pcm_only: "PCM only (no Web-side encode)",
    connect: "Connect",
    disconnect: "Disconnect",
    logout: "Logout",
    connection: "Connection",
    talker: "Talker",
    hold_to_talk: "Hold to Talk (Space)",
    cue_sounds: "Cue Sounds",
    cue_ptt_on: "PTT ON Cue",
    cue_ptt_off: "PTT OFF Cue",
    cue_carrier: "Carrier Sense Cue",
    cue_audio_url: "Audio URL",
    cue_local_file: "Local File (session only)",
    audio_tx_files: "Audio File TX",
    audio_tx_slot_count: "Preset Slots",
    audio_tx_slot: "Slot {index}",
    audio_tx_slot_empty: "No file selected",
    audio_tx_send: "Send",
    audio_tx_stop: "Stop",
    audio_tx_select_file: "Select File",
    audio_tx_delete: "Delete",
    test: "Test",
    default: "Default",
    events: "Events",
    clear: "Clear",
    status_connecting: "Connecting",
    status_offline: "Offline",
    status_error: "Error",
    status_connected: "Connected ({host}:{port})",
    talker_none: "None",
    talker_you: "You",
    log_connect_failed: "connect failed: {error}",
    log_ws_opened: "websocket opened",
    log_ws_closed: "websocket closed",
    log_ws_error: "websocket error",
    log_ws_auth_required: "websocket token is required; open with ?ws_token=...",
    log_auth_session_required: "authentication session is missing or expired; please sign in again",
    log_basic_auth_required: "basic authentication is required; reload the page and authenticate",
    log_browser_codec_opus: "browser codec: opus (uplink/downlink)",
    log_opus_fallback_pcm: "opus unavailable, fallback to pcm: {error}",
    log_downlink_opus_fallback_pcm: "opus decoder unavailable, fallback to pcm: {error}",
    log_downlink_opus_decode_failed: "opus downlink decode failed: {error}",
    log_audio_output_suspended: "audio output is suspended (tap PTT to resume)",
    log_microphone_start_failed: "microphone start failed: {error}",
    log_microphone_permission_denied: "microphone permission denied; PTT is disabled",
    log_connected_summary: "connected channel={channel} sender={sender} mode={mode} codec={codec}",
    log_disconnected: "disconnected",
    log_peer_codec: "peer codec sender={sender} mode={mode} pcmOnly={pcmOnly}",
    log_ready: "ready",
    log_cue_source_empty: "cue source is empty ({label})",
    log_cue_play_failed: "cue play failed ({label}): {error}",
    log_cue_local_selected: "cue local file selected ({label}): {name}",
    log_cue_reset_default: "cue reset to default ({label})",
    log_audio_tx_not_connected: "audio file TX requires an active connection",
    log_audio_tx_busy: "audio file TX is already running",
    log_audio_tx_missing_file: "audio file is not selected (slot {index})",
    log_audio_tx_slot_selected: "audio file selected (slot {index}): {name}",
    log_audio_tx_slot_cleared: "audio file cleared (slot {index})",
    log_audio_tx_start: "audio file TX started (slot {index}): {name}",
    log_audio_tx_completed: "audio file TX completed (slot {index}): {name}",
    log_audio_tx_aborted: "audio file TX aborted",
    log_audio_tx_failed: "audio file TX failed (slot {index}): {error}",
    log_audio_tx_ptt_active: "audio file TX is blocked while PTT is active",
    mic_insecure_context: "microphone API is unavailable on insecure context (use HTTPS or localhost)",
    mic_not_supported: "microphone API is not supported by this browser",
    opus_decoder_not_supported: "WebCodecs AudioDecoder is not supported for Opus downlink",
    opus_decoder_config_not_supported: "Opus AudioDecoder configuration is not supported",
  };

  const i18n = {
    locale: fallbackLocale,
    strings: { ...englishFallbackStrings },
  };
  const cueDefaults = {
    pttOnEnabled: false,
    pttOffEnabled: true,
    carrierEnabled: true,
    pttOnUrl: "sfx/ptt_on.wav",
    pttOffUrl: "sfx/ptt_off.wav",
    carrierUrl: "sfx/carrier_sense.wav",
  };

  function isAndroidBrowser() {
    const ua = (navigator && navigator.userAgent) ? navigator.userAgent : "";
    return /Android/i.test(ua);
  }

  const state = {
    ws: null,
    connected: false,
    pttPressed: false,
    player: null,
    mic: null,
    browserCodec: "pcm",
    txCodec: txCodecPCM,
    uplinkCodec: "pcm",
    downlinkCodec: "pcm",
    codecAvailability: {
      codec2: initialCodec2Ready,
      opus: initialOpusReady,
    },
    opusEncoder: null,
    opusDecoder: null,
    downlinkOpusWarned: false,
    micPermissionDenied: false,
    txQueue: [],
    txTimer: null,
    txTickMs: 20,
    txMaxQueue: 48,
    txRampFrames: 1,
    txFrameIndex: 0,
    cuePlayer: null,
    cueFiles: {
      pttOn: null,
      pttOff: null,
      carrier: null,
    },
    audioTxSlots: [],
    audioTxTask: null,
    lastCarrierCueMs: 0,
    selfSenderId: 0,
    talkerId: 0,
    talkAllowed: false,
    connectionView: {
      kind: "offline",
      host: "",
      port: 0,
    },
  };
  const senderIDMin = 1;
  const senderIDMax = 0x7fffffff;

  applyInitialFormSettings();
  bindFormPersistence();
  bindCueControls();
  bindAudioTxControls();
  configureAuthUI();
  initI18n();

  function sendPcmFrame(frame) {
    enqueueUplinkPacket(0x01, frame);
  }

  function sendOpusFrame(frame) {
    enqueueUplinkPacket(0x02, frame);
  }

  function normalizeSenderID(raw, randomIfInvalid = true) {
    const text = String(raw || "").trim();
    if (!text) {
      return randomIfInvalid ? randomSenderID() : senderIDMin;
    }

    const value = Number(text);
    if (!Number.isFinite(value)) {
      return randomIfInvalid ? randomSenderID() : senderIDMin;
    }

    if (!Number.isSafeInteger(value)) {
      return randomIfInvalid ? randomSenderID() : senderIDMin;
    }

    const id = Math.trunc(value);
    if (id < senderIDMin) {
      return randomIfInvalid ? randomSenderID() : senderIDMin;
    }
    if (id > senderIDMax) {
      return randomIfInvalid ? randomSenderID() : senderIDMin;
    }
    return id;
  }

  function canonicalizeSenderIDField() {
    if (!ui.senderId) {
      return senderIDMin;
    }
    const normalized = normalizeSenderID(ui.senderId.value, true);
    ui.senderId.value = String(normalized);
    return normalized;
  }

  function transmitUplinkFrame(frame) {
    if (!frame || frame.length < 2) {
      return;
    }
    const shaped = shapeTxFrame(frame);
    if (state.uplinkCodec === "opus" && state.opusEncoder) {
      state.opusEncoder.encodeFrame(shaped);
      return;
    }
    sendPcmFrame(shaped);
  }

  function enqueueUplinkPacket(type, frame) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    if (!frame || frame.length === 0) {
      return;
    }
    const packet = new Uint8Array(1 + frame.length);
    packet[0] = type;
    packet.set(frame, 1);
    if (state.txQueue.length >= state.txMaxQueue) {
      const overflow = state.txQueue.length - state.txMaxQueue + 1;
      state.txQueue.splice(0, overflow);
    }
    state.txQueue.push(packet);
    ensureTxLoop();
  }

  function ensureTxLoop() {
    if (state.txTimer) {
      return;
    }
    state.txTimer = window.setInterval(flushUplinkQueue, state.txTickMs);
  }

  function stopTxLoop() {
    if (state.txTimer) {
      window.clearInterval(state.txTimer);
      state.txTimer = null;
    }
  }

  function flushUplinkQueue() {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN || !state.connected || !state.pttPressed) {
      state.txQueue = [];
      stopTxLoop();
      return;
    }
    const packet = state.txQueue.shift();
    if (!packet) {
      return;
    }
    state.ws.send(packet);
  }

  function shapeTxFrame(frame) {
    if (!frame || frame.length < 2) {
      return frame;
    }

    const out = new Uint8Array(frame.length);
    out.set(frame);

    const rampFrames = Math.max(0, Number(state.txRampFrames) || 0);
    const frameIndex = Math.max(0, Number(state.txFrameIndex) || 0);
    state.txFrameIndex = frameIndex + 1;
    const sampleCount = Math.floor(out.length / 2);
    if (sampleCount <= 0) {
      return out;
    }
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

    if (rampFrames > 0 && frameIndex < rampFrames) {
      const g0 = frameIndex / rampFrames;
      const g1 = Math.min(1, (frameIndex + 1) / rampFrames);
      const denom = sampleCount > 1 ? (sampleCount - 1) : 1;

      for (let i = 0; i < sampleCount; i += 1) {
        const gain = g0 + ((g1 - g0) * (i / denom));
        const sample = view.getInt16(i * 2, true);
        const scaled = Math.round(sample * gain);
        const clamped = Math.max(-32768, Math.min(32767, scaled));
        view.setInt16(i * 2, clamped, true);
      }
    }

    return out;
  }

  ui.connectBtn.addEventListener("click", () => {
    persistFormSettings();
    connectRelay().catch((err) => {
      appendLog(t("log_connect_failed", { error: err.message || err }), "error");
      applyDisconnectedState();
    });
  });

  ui.disconnectBtn.addEventListener("click", () => {
    disconnectRelay();
  });

  ui.clearLogBtn.addEventListener("click", () => {
    ui.logBox.textContent = "";
  });

  bindPTT(ui.pttButton);

  window.addEventListener("keydown", (event) => {
    if (event.code !== "Space" || event.repeat) {
      return;
    }
    const tagName = document.activeElement ? document.activeElement.tagName : "";
    if (tagName === "INPUT" || tagName === "TEXTAREA" || tagName === "SELECT") {
      return;
    }
    event.preventDefault();
    setPTT(true);
  });

  window.addEventListener("keyup", (event) => {
    if (event.code !== "Space") {
      return;
    }
    event.preventDefault();
    setPTT(false);
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.player) {
      state.player.resumeIfNeeded();
    }
  });

  window.addEventListener("pageshow", () => {
    if (state.player) {
      state.player.resumeIfNeeded();
    }
  });

  function wsURL() {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const path = basePath ? `${basePath}/ws` : "/ws";
    const url = new URL(`${proto}://${window.location.host}${path}`);
    if (wsToken) {
      url.searchParams.set("token", wsToken);
    }
    return url.toString();
  }

  function supportsAuthLogout() {
    return authMode === "basic" || authMode === "oidc";
  }

  function authCheckURL() {
    return basePath ? `${basePath}/auth/check` : "/auth/check";
  }

  function oidcLoginURL() {
    const loginPath = basePath ? `${basePath}/auth/login` : "/auth/login";
    const next = `${window.location.pathname}${window.location.search || ""}`;
    const params = new URLSearchParams();
    params.set("next", next);
    return `${loginPath}?${params.toString()}`;
  }

  async function ensureAuthSessionBeforeConnect() {
    if (!supportsAuthLogout()) {
      return true;
    }
    try {
      const response = await fetch(authCheckURL(), {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
      });
      if (response.status === 204 || response.status === 200) {
        return true;
      }
      if (response.status === 401) {
        if (authMode === "oidc") {
          appendLog(t("log_auth_session_required"), "warn");
          window.location.href = oidcLoginURL();
          return false;
        }
        if (authMode === "basic") {
          appendLog(t("log_basic_auth_required"), "error");
          return false;
        }
      }
      return true;
    } catch (_) {
      // Network failures are handled by websocket connection path.
      return true;
    }
  }

  function authLogoutURL() {
    return basePath ? `${basePath}/auth/logout` : "/auth/logout";
  }

  function configureAuthUI() {
    if (!ui.logoutBtn) {
      return;
    }
    if (!supportsAuthLogout()) {
      ui.logoutBtn.hidden = true;
      return;
    }
    ui.logoutBtn.hidden = false;
    if (!ui.logoutBtn.dataset.bound) {
      ui.logoutBtn.dataset.bound = "1";
      ui.logoutBtn.addEventListener("click", () => {
        window.location.href = authLogoutURL();
      });
    }
  }

  async function connectRelay() {
    if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }
    if (!(await ensureAuthSessionBeforeConnect())) {
      return;
    }
    if (wsTokenRequired && !wsToken) {
      appendLog(t("log_ws_auth_required"), "error");
      setConnectionView({ kind: "error", level: "error" });
      return;
    }

    const ws = new WebSocket(wsURL());
    ws.binaryType = "arraybuffer";
    state.ws = ws;

    setConnectionView({ kind: "connecting", level: "warn" });

    ws.onopen = async () => {
      appendLog(t("log_ws_opened"), "info");
      state.micPermissionDenied = false;

      state.browserCodec = normalizeBrowserCodec(ui.browserCodec.value);
      state.uplinkCodec = state.browserCodec;
      state.downlinkCodec = state.browserCodec;
      state.downlinkOpusWarned = false;

      if (state.browserCodec === "opus") {
        let opusReady = true;
        let fallbackReason = "";

        try {
          state.opusEncoder = new OpusUplinkEncoder(sendOpusFrame);
          await state.opusEncoder.start();
        } catch (err) {
          opusReady = false;
          fallbackReason = err && err.message ? err.message : String(err);
          state.opusEncoder = null;
        }

        if (opusReady) {
          try {
            state.opusDecoder = new OpusDownlinkDecoder((frame) => {
              if (state.player) {
                state.player.playPCM(frame.bytes, frame.sampleRate);
              }
            });
            await state.opusDecoder.start();
          } catch (err) {
            opusReady = false;
            fallbackReason = err && err.message ? err.message : String(err);
            if (state.opusDecoder) {
              state.opusDecoder.close();
              state.opusDecoder = null;
            }
          }
        }

        if (opusReady) {
          appendLog(t("log_browser_codec_opus"), "info");
        } else {
          if (state.opusEncoder) {
            state.opusEncoder.close();
            state.opusEncoder = null;
          }
          if (state.opusDecoder) {
            state.opusDecoder.close();
            state.opusDecoder = null;
          }
          state.browserCodec = "pcm";
          state.uplinkCodec = "pcm";
          state.downlinkCodec = "pcm";
          ui.browserCodec.value = "pcm";
          appendLog(t("log_opus_fallback_pcm", { error: fallbackReason || "initialization failed" }), "warn");
          persistFormSettings();
        }
      } else {
        if (state.opusEncoder) {
          state.opusEncoder.close();
          state.opusEncoder = null;
        }
        if (state.opusDecoder) {
          state.opusDecoder.close();
          state.opusDecoder = null;
        }
      }

      const safeSenderID = canonicalizeSenderIDField();
      const selectedTxCodec = sanitizeSelectedTxCodec();
      persistFormSettings();

      sendCommand({
        type: "connect",
        relayHost: fixedRelayEnabled ? effectiveFixedRelayHost() : ui.relayHost.value.trim(),
        relayPort: fixedRelayEnabled ? effectiveFixedRelayPort() : Number(ui.relayPort.value),
        channelId: Number(ui.channelId.value),
        senderId: safeSenderID,
        password: ui.password.value,
        cryptoMode: ui.cryptoMode.value,
        codecMode: Number(ui.codecMode.value),
        txCodec: selectedTxCodec,
        codec2Lib: ui.codec2Lib.value.trim(),
        opusLib: ui.opusLib.value.trim(),
        uplinkCodec: state.browserCodec,
        downlinkCodec: state.browserCodec,
        pcmOnly: selectedTxCodec === txCodecPCM,
      });

      try {
        if (state.player) {
          await state.player.resume();
          state.player.resetTimeline();
        }
      } catch (_) {
        appendLog(t("log_audio_output_suspended"), "warn");
      }

      try {
        if (state.mic) {
          await state.mic.start();
        }
      } catch (err) {
        if (isMicPermissionDenied(err)) {
          state.micPermissionDenied = true;
          if (state.pttPressed) {
            setPTT(false, false);
          }
          refreshPTTAvailability();
          appendLog(t("log_microphone_permission_denied"), "warn");
        } else {
          appendLog(t("log_microphone_start_failed", { error: err.message || err }), "warn");
        }
      }
    };

    ws.onmessage = (event) => {
      handleServerMessage(event.data);
    };

    ws.onclose = (event) => {
      if (wsTokenRequired && !wsToken) {
        appendLog(t("log_ws_auth_required"), "error");
      }
      if (event && Number(event.code) === 1006 && supportsAuthLogout()) {
        if (authMode === "oidc") {
          appendLog(t("log_auth_session_required"), "warn");
        } else if (authMode === "basic") {
          appendLog(t("log_basic_auth_required"), "warn");
        }
      }
      if (event && Number(event.code) && Number(event.code) !== 1000) {
        appendLog(`${t("log_ws_closed")} (code=${event.code})`, "warn");
      } else {
        appendLog(t("log_ws_closed"), "warn");
      }
      applyDisconnectedState();
    };

    ws.onerror = () => {
      appendLog(t("log_ws_error"), "error");
    };
  }

  function disconnectRelay() {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      sendCommand({ type: "disconnect" });
      state.ws.close();
    }
    applyDisconnectedState();
  }

  function sendCommand(command) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    state.ws.send(JSON.stringify(command));
  }

  function handleServerMessage(data) {
    if (typeof data === "string") {
      let event;
      try {
        event = JSON.parse(data);
      } catch (_) {
        return;
      }
      handleServerEvent(event);
      return;
    }

    const bytes = new Uint8Array(data);
    if (bytes.length < 2) {
      return;
    }

    const msgType = bytes[0];
    if (msgType === 0x11 && state.player) {
      state.player.playPCM(bytes.subarray(1), 8000);
      return;
    }

    if (msgType === 0x12) {
      if (!state.opusDecoder) {
        if (!state.downlinkOpusWarned) {
          state.downlinkOpusWarned = true;
          appendLog(t("log_downlink_opus_fallback_pcm", {
            error: t("opus_decoder_not_supported"),
          }), "warn");
        }
        return;
      }
      state.opusDecoder.decodePacket(bytes.subarray(1));
    }
  }

  function handleServerEvent(event) {
    if (!event || typeof event !== "object") {
      return;
    }

    if (event.type === "connected") {
      state.connected = true;
      state.selfSenderId = Number(event.senderId || 0);
      state.connectionView.host = event.relayHost || "";
      state.connectionView.port = Number(event.relayPort || 0);
      ui.connectBtn.disabled = true;
      ui.disconnectBtn.disabled = false;
      const hasCodec2Ready = typeof event.codec2Ready === "boolean";
      const hasOpusReady = typeof event.opusReady === "boolean";
      if (hasCodec2Ready || hasOpusReady) {
        applyTxCodecAvailability({
          codec2: hasCodec2Ready ? event.codec2Ready : state.codecAvailability.codec2,
          opus: hasOpusReady ? event.opusReady : state.codecAvailability.opus,
        });
      }
      const connectedTxCodec = normalizeTxCodec(
        event.txCodec || deriveTxCodecFromLegacy(event.pcmOnly, event.uplinkCodec),
      );
      state.txCodec = connectedTxCodec;
      if (ui.txCodec) {
        ui.txCodec.value = connectedTxCodec;
      }
      ui.pcmOnly.checked = connectedTxCodec === txCodecPCM;
      sanitizeSelectedTxCodec(event.codecMode);
      if (event.uplinkCodec === "opus" || event.uplinkCodec === "pcm") {
        state.uplinkCodec = event.uplinkCodec;
      }
      if (event.downlinkCodec === "opus" || event.downlinkCodec === "pcm") {
        state.downlinkCodec = event.downlinkCodec;
      }

      const effectiveBrowserCodec = deriveBrowserCodec(state.uplinkCodec, state.downlinkCodec);
      state.browserCodec = effectiveBrowserCodec;
      ui.browserCodec.value = effectiveBrowserCodec;

      if (effectiveBrowserCodec !== "opus") {
        if (state.opusEncoder) {
          state.opusEncoder.close();
          state.opusEncoder = null;
        }
        if (state.opusDecoder) {
          state.opusDecoder.close();
          state.opusDecoder = null;
        }
      }
      persistFormSettings();
      refreshPTTAvailability();
      refreshAudioTxSlotsUI();
      setConnectionView({ kind: "connected", level: "ok", host: event.relayHost, port: event.relayPort });
      appendLog(t("log_connected_summary", {
        channel: event.channelId,
        sender: event.senderId,
        mode: event.cryptoMode,
        codec: effectiveBrowserCodec,
      }), "info");
      return;
    }

    if (event.type === "disconnected") {
      appendLog(event.message || t("log_disconnected"), "warn");
      applyDisconnectedState();
      return;
    }

    if (event.type === "talker") {
      const prevTalkerId = Number(state.talkerId || 0);
      const nextTalkerId = Number(event.talkerId || 0);
      const remoteTalkEnded =
        prevTalkerId !== 0 &&
        prevTalkerId !== state.selfSenderId &&
        nextTalkerId === 0;

      updateTalkerStatus(nextTalkerId, event.talkAllowed);

      if (remoteTalkEnded) {
        playCue("pttOff");
      }

      if (state.pttPressed && !event.talkAllowed && nextTalkerId !== 0 &&
          nextTalkerId !== state.selfSenderId) {
        playCue("carrier");
      }
      return;
    }

    if (event.type === "peer_codec") {
      appendLog(t("log_peer_codec", {
        sender: event.senderId,
        mode: event.codecMode,
        pcmOnly: event.pcmOnly ? 1 : 0,
      }), "info");
      return;
    }

    if (event.type === "status") {
      const level = normalizeLevel(event.level);
      appendLog(event.message || "", level);
      if (level === "error") {
        setConnectionView({ kind: "error", level: "error" });
      }
      return;
    }

    if (event.type === "ready") {
      appendLog(event.message || t("log_ready"), "info");
    }
  }

  function normalizeLevel(level) {
    if (level === "warn" || level === "error" || level === "info") {
      return level;
    }
    return "info";
  }

  function applyDisconnectedState() {
    state.connected = false;
    cancelAudioTxTask(false);
    setPTT(false, false);
    state.txQueue = [];
    stopTxLoop();
    state.txFrameIndex = 0;
    state.selfSenderId = 0;
    if (state.player) {
      state.player.resetTimeline();
    }
    if (state.mic) {
      state.mic.stop();
    }
    if (state.opusEncoder) {
      state.opusEncoder.close();
      state.opusEncoder = null;
    }
    if (state.opusDecoder) {
      state.opusDecoder.close();
      state.opusDecoder = null;
    }
    state.uplinkCodec = "pcm";
    state.downlinkCodec = "pcm";
    state.browserCodec = "pcm";
    state.downlinkOpusWarned = false;
    state.micPermissionDenied = false;
    if (state.ws) {
      state.ws.onclose = null;
      state.ws.onmessage = null;
      state.ws.onerror = null;
      state.ws = null;
    }
    ui.connectBtn.disabled = false;
    ui.disconnectBtn.disabled = true;
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    updateTalkerStatus(0, false);
    setConnectionView({ kind: "offline", level: "warn" });
  }

  function applyInitialFormSettings() {
    const defaults = {
      relayHost: defaultRelayHost(),
      relayPort: "50000",
      channelId: "1",
      senderId: String(randomSenderID()),
      password: "",
      cryptoMode: "aes-gcm",
      codecMode: "1600",
      browserCodec: "opus",
      txCodec: txCodecPCM,
      codec2Lib: "",
      opusLib: "",
      pcmOnly: true,
      cuePttOnEnabled: cueDefaults.pttOnEnabled,
      cuePttOffEnabled: cueDefaults.pttOffEnabled,
      cueCarrierEnabled: cueDefaults.carrierEnabled,
      cuePttOnUrl: cueDefaults.pttOnUrl,
      cuePttOffUrl: cueDefaults.pttOffUrl,
      cueCarrierUrl: cueDefaults.carrierUrl,
      audioTxSlotCount: "3",
    };
    if (fixedRelayEnabled) {
      defaults.relayHost = effectiveFixedRelayHost();
      defaults.relayPort = String(effectiveFixedRelayPort());
    }

    const stored = readStoredSettings();
    const merged = {
      ...defaults,
      ...stored,
    };

    if (!merged.relayHost || !String(merged.relayHost).trim()) {
      merged.relayHost = defaults.relayHost;
    }
    merged.senderId = String(normalizeSenderID(merged.senderId, true));
    if (!merged.codecMode) {
      merged.codecMode = defaults.codecMode;
    }
    if (!merged.browserCodec) {
      merged.browserCodec = deriveBrowserCodec(merged.uplinkCodec, merged.downlinkCodec);
    }
    if (!merged.txCodec) {
      merged.txCodec = deriveTxCodecFromLegacy(merged.pcmOnly, merged.uplinkCodec);
    }
    if (!merged.cuePttOnUrl || !String(merged.cuePttOnUrl).trim()) {
      merged.cuePttOnUrl = cueDefaults.pttOnUrl;
    }
    if (!merged.cuePttOffUrl || !String(merged.cuePttOffUrl).trim()) {
      merged.cuePttOffUrl = cueDefaults.pttOffUrl;
    }
    if (!merged.cueCarrierUrl || !String(merged.cueCarrierUrl).trim()) {
      merged.cueCarrierUrl = cueDefaults.carrierUrl;
    }
    if (!merged.audioTxSlotCount) {
      merged.audioTxSlotCount = defaults.audioTxSlotCount;
    }
    if (fixedRelayEnabled) {
      merged.relayHost = defaults.relayHost;
      merged.relayPort = defaults.relayPort;
    }

    ui.relayHost.value = String(merged.relayHost);
    ui.relayPort.value = String(merged.relayPort);
    ui.channelId.value = String(merged.channelId);
    ui.senderId.value = String(merged.senderId);
    ui.password.value = String(merged.password);
    ui.cryptoMode.value = String(merged.cryptoMode);
    ui.browserCodec.value = normalizeBrowserCodec(merged.browserCodec);
    if (ui.txCodec) {
      ui.txCodec.value = normalizeTxCodec(merged.txCodec);
    }
    ui.codec2Lib.value = String(merged.codec2Lib || "");
    ui.opusLib.value = String(merged.opusLib || "");
    sanitizeSelectedTxCodec(merged.codecMode);
    ui.cuePttOnEnabled.checked = !!merged.cuePttOnEnabled;
    ui.cuePttOffEnabled.checked = !!merged.cuePttOffEnabled;
    ui.cueCarrierEnabled.checked = !!merged.cueCarrierEnabled;
    ui.cuePttOnUrl.value = String(merged.cuePttOnUrl);
    ui.cuePttOffUrl.value = String(merged.cuePttOffUrl);
    ui.cueCarrierUrl.value = String(merged.cueCarrierUrl);
    ui.audioTxSlotCount.value = String(normalizeAudioTxSlotCount(merged.audioTxSlotCount));
    setAudioTxSlotCount(merged.audioTxSlotCount, false);
    applyFixedRelayUIState();

    persistFormSettings();
  }

  function bindFormPersistence() {
    const persistTargets = [
      ui.relayHost,
      ui.relayPort,
      ui.channelId,
      ui.senderId,
      ui.password,
      ui.cryptoMode,
      ui.codecMode,
      ui.browserCodec,
      ui.txCodec,
      ui.codec2Lib,
      ui.opusLib,
      ui.cuePttOnEnabled,
      ui.cuePttOffEnabled,
      ui.cueCarrierEnabled,
      ui.cuePttOnUrl,
      ui.cuePttOffUrl,
      ui.cueCarrierUrl,
      ui.audioTxSlotCount,
    ];

    persistTargets.forEach((element) => {
      if (!element) {
        return;
      }
      element.addEventListener("input", persistFormSettings);
      element.addEventListener("change", persistFormSettings);
    });

    if (ui.senderId && !ui.senderId.dataset.normalizeBound) {
      ui.senderId.dataset.normalizeBound = "1";
      ui.senderId.addEventListener("blur", () => {
        canonicalizeSenderIDField();
        persistFormSettings();
      });
    }
  }

  function readStoredSettings() {
    try {
      const raw = localStorage.getItem(settingsStorageKey);
      if (!raw) {
        return {};
      }
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") {
        return {};
      }
      return parsed;
    } catch (_) {
      return {};
    }
  }

  function persistFormSettings() {
    const selectedTxCodec = sanitizeSelectedTxCodec();
    const settings = {
      relayHost: fixedRelayEnabled ? effectiveFixedRelayHost() : ui.relayHost.value.trim(),
      relayPort: fixedRelayEnabled ? String(effectiveFixedRelayPort()) : ui.relayPort.value,
      channelId: ui.channelId.value,
      senderId: ui.senderId.value,
      password: ui.password.value,
      cryptoMode: ui.cryptoMode.value,
      codecMode: ui.codecMode.value,
      browserCodec: ui.browserCodec.value,
      txCodec: selectedTxCodec,
      codec2Lib: ui.codec2Lib.value.trim(),
      opusLib: ui.opusLib.value.trim(),
      pcmOnly: selectedTxCodec === txCodecPCM,
      cuePttOnEnabled: !!ui.cuePttOnEnabled.checked,
      cuePttOffEnabled: !!ui.cuePttOffEnabled.checked,
      cueCarrierEnabled: !!ui.cueCarrierEnabled.checked,
      cuePttOnUrl: ui.cuePttOnUrl.value.trim(),
      cuePttOffUrl: ui.cuePttOffUrl.value.trim(),
      cueCarrierUrl: ui.cueCarrierUrl.value.trim(),
      audioTxSlotCount: String(normalizeAudioTxSlotCount(ui.audioTxSlotCount ? ui.audioTxSlotCount.value : 3)),
    };
    try {
      localStorage.setItem(settingsStorageKey, JSON.stringify(settings));
    } catch (_) {
      // Ignore persistence errors (private mode or storage denied).
    }
  }

  function bindCueControls() {
    ui.cuePttOnFile.addEventListener("change", () => {
      selectCueFile("pttOn", ui.cuePttOnFile.files && ui.cuePttOnFile.files[0]);
    });
    ui.cuePttOffFile.addEventListener("change", () => {
      selectCueFile("pttOff", ui.cuePttOffFile.files && ui.cuePttOffFile.files[0]);
    });
    ui.cueCarrierFile.addEventListener("change", () => {
      selectCueFile("carrier", ui.cueCarrierFile.files && ui.cueCarrierFile.files[0]);
    });

    ui.cuePttOnTest.addEventListener("click", () => playCue("pttOn", true));
    ui.cuePttOffTest.addEventListener("click", () => playCue("pttOff", true));
    ui.cueCarrierTest.addEventListener("click", () => playCue("carrier", true));

    ui.cuePttOnReset.addEventListener("click", () => resetCueToDefault("pttOn"));
    ui.cuePttOffReset.addEventListener("click", () => resetCueToDefault("pttOff"));
    ui.cueCarrierReset.addEventListener("click", () => resetCueToDefault("carrier"));

    window.addEventListener("beforeunload", cleanupCueFiles);
  }

  function bindAudioTxControls() {
    if (!ui.audioTxSlotCount) {
      return;
    }
    const applySlotCount = () => {
      setAudioTxSlotCount(ui.audioTxSlotCount.value, true);
      persistFormSettings();
    };
    ui.audioTxSlotCount.addEventListener("change", applySlotCount);
    ui.audioTxSlotCount.addEventListener("blur", applySlotCount);
  }

  function cueControls(kind) {
    if (kind === "pttOn") {
      return {
        enabled: ui.cuePttOnEnabled,
        url: ui.cuePttOnUrl,
        file: ui.cuePttOnFile,
        defaultUrl: cueDefaults.pttOnUrl,
        label: t("cue_ptt_on"),
      };
    }
    if (kind === "pttOff") {
      return {
        enabled: ui.cuePttOffEnabled,
        url: ui.cuePttOffUrl,
        file: ui.cuePttOffFile,
        defaultUrl: cueDefaults.pttOffUrl,
        label: t("cue_ptt_off"),
      };
    }
    return {
      enabled: ui.cueCarrierEnabled,
      url: ui.cueCarrierUrl,
      file: ui.cueCarrierFile,
      defaultUrl: cueDefaults.carrierUrl,
      label: t("cue_carrier"),
    };
  }

  function playCue(kind, force = false) {
    if (!state.cuePlayer) {
      return;
    }
    if (state.player) {
      state.player.resumeIfNeeded();
    }

    const controls = cueControls(kind);
    if (!force && controls.enabled && !controls.enabled.checked) {
      return;
    }

    if (kind === "carrier") {
      const now = Date.now();
      if (!force && now - state.lastCarrierCueMs < 150) {
        return;
      }
      state.lastCarrierCueMs = now;
    }

    const source = resolveCueSource(kind);
    if (!source) {
      appendLog(t("log_cue_source_empty", { label: controls.label }), "warn");
      return;
    }

    state.cuePlayer.play(source, (err) => {
      appendLog(t("log_cue_play_failed", { label: controls.label, error: err }), "warn");
    });
  }

  function resolveCueSource(kind) {
    const fileEntry = state.cueFiles[kind];
    if (fileEntry && fileEntry.objectUrl) {
      return fileEntry.objectUrl;
    }

    const controls = cueControls(kind);
    const urlText = controls.url ? controls.url.value.trim() : "";
    if (urlText) {
      return urlText;
    }
    return controls.defaultUrl;
  }

  function selectCueFile(kind, file) {
    clearCueFile(kind);
    if (!file) {
      return;
    }
    const objectUrl = URL.createObjectURL(file);
    state.cueFiles[kind] = {
      objectUrl,
      name: file.name,
    };
    const controls = cueControls(kind);
    appendLog(t("log_cue_local_selected", { label: controls.label, name: file.name }), "info");
  }

  function clearCueFile(kind) {
    const prev = state.cueFiles[kind];
    if (!prev || !prev.objectUrl) {
      state.cueFiles[kind] = null;
      return;
    }
    try {
      URL.revokeObjectURL(prev.objectUrl);
    } catch (_) {
      // Ignore revoke errors.
    }
    state.cueFiles[kind] = null;
  }

  function resetCueToDefault(kind) {
    clearCueFile(kind);
    const controls = cueControls(kind);
    if (controls.url) {
      controls.url.value = controls.defaultUrl;
    }
    if (controls.file) {
      controls.file.value = "";
    }
    persistFormSettings();
    appendLog(t("log_cue_reset_default", { label: controls.label }), "info");
  }

  function cleanupCueFiles() {
    clearCueFile("pttOn");
    clearCueFile("pttOff");
    clearCueFile("carrier");
  }

  function normalizeAudioTxSlotCount(value) {
    const parsed = Number.parseInt(String(value || "").trim(), 10);
    if (!Number.isFinite(parsed)) {
      return 3;
    }
    return Math.max(1, Math.min(12, parsed));
  }

  function createAudioTxSlotState() {
    return { file: null };
  }

  function setAudioTxSlotCount(value, preserveExisting) {
    const count = normalizeAudioTxSlotCount(value);
    const keepExisting = preserveExisting !== false;
    const next = [];
    for (let i = 0; i < count; i += 1) {
      if (keepExisting && state.audioTxSlots[i]) {
        next.push(state.audioTxSlots[i]);
      } else {
        next.push(createAudioTxSlotState());
      }
    }
    state.audioTxSlots = next;
    if (ui.audioTxSlotCount) {
      ui.audioTxSlotCount.value = String(count);
    }
    refreshAudioTxSlotsUI();
  }

  function refreshAudioTxSlotsUI() {
    if (!ui.audioTxSlots) {
      return;
    }
    renderAudioTxSlots();
  }

  function renderAudioTxSlots() {
    if (!ui.audioTxSlots) {
      return;
    }
    ui.audioTxSlots.textContent = "";

    const activeTask = state.audioTxTask;
    const hasActiveTask = !!activeTask;
    const pttBusy = state.pttPressed && !hasActiveTask;

    for (let i = 0; i < state.audioTxSlots.length; i += 1) {
      const slot = state.audioTxSlots[i] || createAudioTxSlotState();
      const row = document.createElement("div");
      row.className = "audio-tx-slot";
      if (activeTask && activeTask.slotIndex === i) {
        row.classList.add("active");
      }

      const head = document.createElement("div");
      head.className = "audio-tx-slot-head";

      const title = document.createElement("p");
      title.className = "audio-tx-slot-title";
      title.textContent = t("audio_tx_slot", { index: i + 1 });
      head.appendChild(title);

      const name = document.createElement("p");
      name.className = "audio-tx-slot-file";
      name.textContent = slot.file ? slot.file.name : t("audio_tx_slot_empty");
      head.appendChild(name);
      row.appendChild(head);

      const hiddenInput = document.createElement("input");
      hiddenInput.type = "file";
      hiddenInput.accept = "audio/*,.wav";
      hiddenInput.className = "audio-tx-file-input";
      hiddenInput.disabled = hasActiveTask;
      hiddenInput.addEventListener("change", () => {
        setAudioTxSlotFile(i, hiddenInput.files && hiddenInput.files[0]);
        hiddenInput.value = "";
      });
      row.appendChild(hiddenInput);

      const actions = document.createElement("div");
      actions.className = "audio-tx-slot-actions";

      const sendBtn = document.createElement("button");
      const isActiveSlot = !!(activeTask && activeTask.slotIndex === i);
      sendBtn.type = "button";
      sendBtn.className = "btn";
      sendBtn.textContent = isActiveSlot ? t("audio_tx_stop") : t("audio_tx_send");
      sendBtn.disabled = isActiveSlot ? false : (!state.connected || !slot.file || hasActiveTask || pttBusy);
      sendBtn.addEventListener("click", () => {
        if (isActiveSlot) {
          cancelAudioTxTask(true);
          return;
        }
        startAudioTxFromSlot(i).catch((err) => {
          appendLog(t("log_audio_tx_failed", { index: i + 1, error: err && err.message ? err.message : String(err) }), "error");
          cancelAudioTxTask(false);
        });
      });
      actions.appendChild(sendBtn);

      const selectBtn = document.createElement("button");
      selectBtn.type = "button";
      selectBtn.className = "ghost";
      selectBtn.textContent = t("audio_tx_select_file");
      selectBtn.disabled = hasActiveTask;
      selectBtn.addEventListener("click", () => {
        if (!hiddenInput.disabled) {
          hiddenInput.click();
        }
      });
      actions.appendChild(selectBtn);

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "ghost";
      deleteBtn.textContent = t("audio_tx_delete");
      deleteBtn.disabled = hasActiveTask || !slot.file;
      deleteBtn.addEventListener("click", () => {
        clearAudioTxSlotFile(i, true);
      });
      actions.appendChild(deleteBtn);

      row.appendChild(actions);
      ui.audioTxSlots.appendChild(row);
    }
  }

  function setAudioTxSlotFile(index, file) {
    if (index < 0 || index >= state.audioTxSlots.length) {
      return;
    }
    const slot = state.audioTxSlots[index] || createAudioTxSlotState();
    slot.file = file || null;
    state.audioTxSlots[index] = slot;
    persistFormSettings();
    if (file) {
      appendLog(t("log_audio_tx_slot_selected", { index: index + 1, name: file.name }), "info");
    }
    refreshAudioTxSlotsUI();
  }

  function clearAudioTxSlotFile(index, emitLog) {
    if (index < 0 || index >= state.audioTxSlots.length) {
      return;
    }
    const slot = state.audioTxSlots[index];
    if (!slot) {
      return;
    }
    const hadFile = !!slot.file;
    slot.file = null;
    state.audioTxSlots[index] = slot;
    persistFormSettings();
    if (emitLog && hadFile) {
      appendLog(t("log_audio_tx_slot_cleared", { index: index + 1 }), "info");
    }
    refreshAudioTxSlotsUI();
  }

  async function startAudioTxFromSlot(index) {
    if (state.audioTxTask) {
      appendLog(t("log_audio_tx_busy"), "warn");
      return;
    }
    if (!state.connected || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      appendLog(t("log_audio_tx_not_connected"), "warn");
      return;
    }
    if (state.pttPressed) {
      appendLog(t("log_audio_tx_ptt_active"), "warn");
      return;
    }
    const slot = state.audioTxSlots[index];
    if (!slot || !slot.file) {
      appendLog(t("log_audio_tx_missing_file", { index: index + 1 }), "warn");
      return;
    }

    const frames = await decodeAudioFileToFrames(slot.file);
    if (!frames || frames.length === 0) {
      throw new Error("decoded audio is empty");
    }
    startAudioTxTask(index, slot.file.name, frames);
  }

  async function decodeAudioFileToFrames(file) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass || typeof OfflineAudioContext === "undefined") {
      throw new Error(t("mic_not_supported"));
    }
    const sourceBytes = await file.arrayBuffer();
    const decodeContext = new AudioContextClass();
    try {
      const decoded = await decodeContext.decodeAudioData(sourceBytes.slice(0));
      const targetSamples = Math.max(1, Math.ceil(decoded.duration * 8000));
      const offline = new OfflineAudioContext(1, targetSamples, 8000);
      const src = offline.createBufferSource();
      src.buffer = decoded;
      src.connect(offline.destination);
      src.start(0);
      const rendered = await offline.startRendering();
      const mono = rendered.getChannelData(0);
      if (!mono || mono.length === 0) {
        return [];
      }

      const frameCount = Math.ceil(mono.length / 160);
      const frames = new Array(frameCount);
      let offset = 0;
      for (let i = 0; i < frameCount; i += 1) {
        const pcm = new Int16Array(160);
        const remain = Math.min(160, mono.length - offset);
        for (let j = 0; j < remain; j += 1) {
          pcm[j] = floatToInt16(mono[offset + j]);
        }
        offset += remain;
        frames[i] = int16ToPCMBytes(pcm);
      }
      return frames;
    } finally {
      decodeContext.close().catch(() => {});
    }
  }

  function startAudioTxTask(slotIndex, name, frames) {
    cancelAudioTxTask(false);
    state.txFrameIndex = 0;
    state.audioTxTask = {
      slotIndex,
      name,
      frames,
      next: 0,
      timer: null,
      finishing: false,
    };
    state.pttPressed = true;
    ui.pttButton.classList.add("active");
    sendCommand({ type: "ptt", pressed: true });
    playCue("pttOn");
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    appendLog(t("log_audio_tx_start", { index: slotIndex + 1, name }), "info");

    tickAudioTxTask();
    const task = state.audioTxTask;
    if (task) {
      task.timer = window.setInterval(tickAudioTxTask, 20);
    }
  }

  function tickAudioTxTask() {
    const task = state.audioTxTask;
    if (!task || task.finishing) {
      return;
    }
    if (!state.connected || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      task.finishing = true;
      cancelAudioTxTask(false);
      return;
    }
    if (task.next >= task.frames.length) {
      task.finishing = true;
      finishAudioTxTask("log_audio_tx_completed", { index: task.slotIndex + 1, name: task.name }, "info");
      return;
    }

    const frame = task.frames[task.next];
    task.next += 1;
    transmitUplinkFrame(frame);
  }

  async function finishAudioTxTask(logKey, params, level) {
    const task = state.audioTxTask;
    if (!task) {
      return;
    }
    if (task.timer) {
      window.clearInterval(task.timer);
      task.timer = null;
    }
    await flushAudioTxPipeline();

    if (state.pttPressed) {
      sendCommand({ type: "ptt", pressed: false });
      playCue("pttOff");
    }
    state.pttPressed = false;
    ui.pttButton.classList.remove("active");
    state.txQueue = [];
    stopTxLoop();
    state.txFrameIndex = 0;
    state.audioTxTask = null;
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();

    if (logKey) {
      appendLog(t(logKey, params || {}), level || "info");
    }
  }

  async function flushAudioTxPipeline() {
    if (state.uplinkCodec === "opus" && state.opusEncoder) {
      try {
        await state.opusEncoder.flush();
      } catch (_) {
        // Ignore encoder flush errors.
      }
    }

    const deadline = Date.now() + 1600;
    while (state.txQueue.length > 0 && Date.now() < deadline) {
      await new Promise((resolve) => window.setTimeout(resolve, 20));
    }
  }

  function cancelAudioTxTask(emitLog) {
    const task = state.audioTxTask;
    if (!task) {
      return;
    }
    if (task.timer) {
      window.clearInterval(task.timer);
      task.timer = null;
    }
    if (state.pttPressed) {
      sendCommand({ type: "ptt", pressed: false });
      playCue("pttOff");
    }
    state.audioTxTask = null;
    state.pttPressed = false;
    ui.pttButton.classList.remove("active");
    state.txQueue = [];
    stopTxLoop();
    state.txFrameIndex = 0;
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    if (emitLog) {
      appendLog(t("log_audio_tx_aborted"), "warn");
    }
  }

  function t(key, params) {
    const source = i18n.strings[key] || englishFallbackStrings[key] || key;
    return source.replace(/\{(\w+)\}/g, (_, name) => {
      if (!params || params[name] === undefined || params[name] === null) {
        return "";
      }
      return String(params[name]);
    });
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (!el) {
      return;
    }
    el.textContent = value;
  }

  function updateTalkerStatus(talkerId, talkAllowed) {
    state.talkerId = Number(talkerId || 0);
    state.talkAllowed = !!talkAllowed;
    if (!ui.talkerStatus) {
      return;
    }
    if (state.talkerId === 0) {
      ui.talkerStatus.textContent = t("talker_none");
      return;
    }
    const talkerText = String(state.talkerId);
    ui.talkerStatus.textContent = state.talkAllowed ? `${talkerText} (${t("talker_you")})` : talkerText;
  }

  function setConnectionView(next) {
    state.connectionView = {
      ...state.connectionView,
      ...next,
    };
    applyConnectionView();
  }

  function applyConnectionView() {
    const view = state.connectionView || { kind: "offline", host: "", port: 0, level: "warn" };
    switch (view.kind) {
      case "connecting":
        setConnectionStatus(t("status_connecting"), view.level || "warn");
        return;
      case "connected":
        setConnectionStatus(t("status_connected", { host: view.host, port: view.port }), view.level || "ok");
        return;
      case "error":
        setConnectionStatus(t("status_error"), view.level || "error");
        return;
      default:
        setConnectionStatus(t("status_offline"), view.level || "warn");
        return;
    }
  }

  function applyI18nToUI() {
    document.title = t("app_title");
    document.documentElement.lang = i18n.locale;

    setText("titleMain", t("header_title"));
    setText("labelLanguage", t("language"));
    setText("labelRelayHost", t("relay_host"));
    setText("labelRelayPort", t("relay_port"));
    setText("labelChannelId", t("channel_id"));
    setText("labelSenderId", t("sender_id"));
    setText("labelPassword", t("password"));
    setText("labelCryptoMode", t("crypto_mode"));
    setText("labelCodecMode", t("codec_mode"));
    setText("labelBrowserCodec", t("browser_codec"));
    setText("labelTxCodec", t("tx_codec"));
    setText("optionTxCodecPcm", t("tx_codec_pcm"));
    setText("optionTxCodecCodec2", t("tx_codec_codec2"));
    setText("optionTxCodecOpus", t("tx_codec_opus"));
    setText("optionBrowserCodecOpus", t("uplink_opus_optional"));
    setText("labelPcmOnly", t("pcm_only"));
    setText("connectBtn", t("connect"));
    setText("disconnectBtn", t("disconnect"));
    setText("logoutBtn", t("logout"));
    setText("labelConnection", t("connection"));
    setText("labelTalker", t("talker"));
    setText("labelPttButton", t("hold_to_talk"));
    setText("headingCueSounds", t("cue_sounds"));
    setText("labelCuePttOn", t("cue_ptt_on"));
    setText("labelCuePttOff", t("cue_ptt_off"));
    setText("labelCueCarrier", t("cue_carrier"));
    setText("labelCuePttOnUrl", t("cue_audio_url"));
    setText("labelCuePttOffUrl", t("cue_audio_url"));
    setText("labelCueCarrierUrl", t("cue_audio_url"));
    setText("labelCuePttOnFile", t("cue_local_file"));
    setText("labelCuePttOffFile", t("cue_local_file"));
    setText("labelCueCarrierFile", t("cue_local_file"));
    setText("cuePttOnTest", t("test"));
    setText("cuePttOffTest", t("test"));
    setText("cueCarrierTest", t("test"));
    setText("cuePttOnReset", t("default"));
    setText("cuePttOffReset", t("default"));
    setText("cueCarrierReset", t("default"));
    setText("headingAudioTx", t("audio_tx_files"));
    setText("labelAudioTxSlotCount", t("audio_tx_slot_count"));
    setText("headingEvents", t("events"));
    setText("clearLogBtn", t("clear"));

    updateTalkerStatus(state.talkerId, state.talkAllowed);
    applyConnectionView();
    refreshAudioTxSlotsUI();
  }

  function normalizeLocale(raw) {
    return String(raw || "")
      .trim()
      .replace(/_/g, "-")
      .toLowerCase();
  }

  function localeCandidates(raw) {
    const normalized = normalizeLocale(raw);
    if (!normalized) {
      return [];
    }
    const parts = normalized.split("-");
    const out = [normalized];
    if (parts.length > 1) {
      out.push(parts[0]);
    }
    return out;
  }

  async function tryFetchLocale(locale) {
    const path = basePath ? `${basePath}/locales/${locale}.json` : `locales/${locale}.json`;
    try {
      const res = await fetch(path, { cache: "no-store" });
      if (!res.ok) {
        return null;
      }
      const parsed = await res.json();
      if (!parsed || typeof parsed !== "object") {
        return null;
      }
      return parsed;
    } catch (_) {
      return null;
    }
  }

  async function loadBestLocale(requested) {
    const candidates = [];
    const add = (value) => {
      if (!value) {
        return;
      }
      if (!candidates.includes(value)) {
        candidates.push(value);
      }
    };

    localeCandidates(requested).forEach(add);

    if (!requested) {
      const browserLocales = Array.isArray(navigator.languages) && navigator.languages.length > 0
        ? navigator.languages
        : [navigator.language];
      browserLocales.forEach((item) => {
        localeCandidates(item).forEach(add);
      });
    }

    add(fallbackLocale);

    for (const candidate of candidates) {
      const bundle = await tryFetchLocale(candidate);
      if (bundle) {
        return { locale: candidate, bundle };
      }
    }

    return { locale: fallbackLocale, bundle: { ...englishFallbackStrings } };
  }

  async function setLocale(requested, persistChoice) {
    const loaded = await loadBestLocale(requested);
    i18n.locale = loaded.locale;
    i18n.strings = {
      ...englishFallbackStrings,
      ...loaded.bundle,
    };

    const selectValue = supportedUiLocales.includes(i18n.locale) ? i18n.locale : fallbackLocale;
    if (ui.languageSelect && ui.languageSelect.value !== selectValue) {
      ui.languageSelect.value = selectValue;
    }

    if (persistChoice) {
      try {
        localStorage.setItem(localeStorageKey, requested || selectValue);
      } catch (_) {
        // ignore storage failures
      }
    }

    applyI18nToUI();
  }

  async function initI18n() {
    if (ui.languageSelect && !ui.languageSelect.dataset.bound) {
      ui.languageSelect.dataset.bound = "1";
      ui.languageSelect.addEventListener("change", () => {
        setLocale(ui.languageSelect.value, true).catch(() => {});
      });
    }

    let preferred = "";
    try {
      preferred = localStorage.getItem(localeStorageKey) || "";
    } catch (_) {
      preferred = "";
    }

    if (ui.languageSelect && preferred && supportedUiLocales.includes(normalizeLocale(preferred))) {
      ui.languageSelect.value = normalizeLocale(preferred);
    }

    await setLocale(preferred || "", false);
  }

  function isMicPermissionDenied(err) {
    if (!err) {
      return false;
    }
    const name = String(err.name || "").toLowerCase();
    if (name === "notallowederror" || name === "permissiondeniederror") {
      return true;
    }
    const message = String(err.message || err).toLowerCase();
    return message.includes("permission denied") || message.includes("denied permission");
  }

  function refreshPTTAvailability() {
    ui.pttButton.disabled = !state.connected || state.micPermissionDenied || !!state.audioTxTask;
  }

  function normalizeBrowserCodec(value) {
    return String(value || "").trim().toLowerCase() === "opus" ? "opus" : "pcm";
  }

  function normalizeTxCodec(value) {
    const text = String(value || "").trim().toLowerCase();
    if (text === txCodecCodec2) {
      return txCodecCodec2;
    }
    if (text === txCodecOpus) {
      return txCodecOpus;
    }
    return txCodecPCM;
  }

  function nearestBitrateOption(options, value) {
    if (!Array.isArray(options) || options.length === 0) {
      return 0;
    }
    let best = options[0];
    let bestDiff = Math.abs(value - best);
    for (let i = 1; i < options.length; i += 1) {
      const candidate = options[i];
      const diff = Math.abs(value - candidate);
      if (diff < bestDiff) {
        best = candidate;
        bestDiff = diff;
      }
    }
    return best;
  }

  function legacyCodec2ModeToOpusBitrate(mode) {
    if (mode <= 450) {
      return 6000;
    }
    if (mode <= 700) {
      return 8000;
    }
    if (mode <= 1600) {
      return 12000;
    }
    if (mode <= 2400) {
      return 16000;
    }
    return 20000;
  }

  function opusBitrateToLegacyCodec2Mode(bitrate) {
    if (bitrate <= 6000) {
      return 450;
    }
    if (bitrate <= 8000) {
      return 700;
    }
    if (bitrate <= 12000) {
      return 1600;
    }
    if (bitrate <= 16000) {
      return 2400;
    }
    return 3200;
  }

  function bitrateOptionsForTxCodec(txCodec) {
    return normalizeTxCodec(txCodec) === txCodecOpus
      ? opusBitrateOptions
      : codec2BitrateOptions;
  }

  function normalizeBitrateForTxCodec(rawValue, txCodec) {
    const normalizedTxCodec = normalizeTxCodec(txCodec);
    const rawText = rawValue === undefined || rawValue === null ? "" : rawValue;
    const parsed = Number.parseInt(String(rawText), 10);
    let value = Number.isFinite(parsed) ? parsed : 0;

    if (normalizedTxCodec === txCodecOpus) {
      if (value < opusBitrateOptions[0]) {
        value = legacyCodec2ModeToOpusBitrate(value);
      }
      return nearestBitrateOption(opusBitrateOptions, value);
    }

    if (value >= opusBitrateOptions[0]) {
      value = opusBitrateToLegacyCodec2Mode(value);
    }
    return nearestBitrateOption(codec2BitrateOptions, value);
  }

  function syncCodecModeOptions(preferredValue) {
    if (!ui.codecMode) {
      return;
    }

    const selectedTxCodec = normalizeTxCodec(ui.txCodec ? ui.txCodec.value : state.txCodec);
    const options = bitrateOptionsForTxCodec(selectedTxCodec);
    const currentValue = preferredValue !== undefined ? preferredValue : ui.codecMode.value;
    const normalizedValue = normalizeBitrateForTxCodec(currentValue, selectedTxCodec);

    const currentOptionValues = Array.from(ui.codecMode.options).map((option) => Number.parseInt(option.value, 10));
    const optionsUnchanged =
      currentOptionValues.length === options.length &&
      currentOptionValues.every((value, index) => value === options[index]);

    if (!optionsUnchanged) {
      ui.codecMode.innerHTML = "";
      options.forEach((value) => {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = String(value);
        ui.codecMode.appendChild(option);
      });
    }

    ui.codecMode.value = String(normalizedValue);
  }

  function deriveTxCodecFromLegacy(pcmOnly, uplinkCodec) {
    if (pcmOnly) {
      return txCodecPCM;
    }
    return normalizeBrowserCodec(uplinkCodec) === "opus" ? txCodecOpus : txCodecCodec2;
  }

  function setOptionVisibility(optionElement, visible) {
    if (!optionElement) {
      return;
    }
    optionElement.hidden = !visible;
    optionElement.disabled = !visible;
  }

  function applyTxCodecAvailability(next) {
    if (!next || typeof next !== "object") {
      return;
    }
    state.codecAvailability.codec2 = !!next.codec2;
    state.codecAvailability.opus = !!next.opus;
    sanitizeSelectedTxCodec();
  }

  function sanitizeSelectedTxCodec(preferredCodecMode) {
    const codec2Ready = !!(state.codecAvailability && state.codecAvailability.codec2);
    const opusReady = !!(state.codecAvailability && state.codecAvailability.opus);

    setOptionVisibility(ui.optionTxCodecPcm, true);
    setOptionVisibility(ui.optionTxCodecCodec2, codec2Ready);
    setOptionVisibility(ui.optionTxCodecOpus, opusReady);

    let selected = normalizeTxCodec(ui.txCodec ? ui.txCodec.value : state.txCodec);
    if (selected === txCodecCodec2 && !codec2Ready) {
      selected = txCodecPCM;
    }
    if (selected === txCodecOpus && !opusReady) {
      selected = txCodecPCM;
    }

    state.txCodec = selected;
    if (ui.txCodec) {
      ui.txCodec.value = selected;
    }
    syncCodecModeOptions(preferredCodecMode);
    if (ui.pcmOnly) {
      ui.pcmOnly.checked = selected === txCodecPCM;
    }
    return selected;
  }

  function deriveBrowserCodec(uplink, downlink) {
    const up = normalizeBrowserCodec(uplink);
    const down = normalizeBrowserCodec(downlink);
    if (up === "opus" && down === "opus") {
      return "opus";
    }
    return "pcm";
  }

  function resolveWorkletURL(fileName) {
    if (!fileName) {
      return "";
    }
    return basePath ? `${basePath}/worklets/${fileName}` : `worklets/${fileName}`;
  }

  function defaultRelayHost() {
    const host = String(window.location.hostname || "").trim();
    if (host) {
      return host;
    }
    return "127.0.0.1";
  }

  function effectiveFixedRelayHost() {
    return fixedRelayHost || defaultRelayHost();
  }

  function effectiveFixedRelayPort() {
    return fixedRelayPort;
  }

  function applyFixedRelayUIState() {
    if (!fixedRelayEnabled) {
      return;
    }
    ui.relayHost.value = effectiveFixedRelayHost();
    ui.relayPort.value = String(effectiveFixedRelayPort());
    ui.relayHost.readOnly = true;
    ui.relayPort.readOnly = true;
    ui.relayHost.disabled = true;
    ui.relayPort.disabled = true;
  }

  function initializeWSToken() {
    const params = new URLSearchParams(window.location.search || "");
    const fromQuery = String(params.get("ws_token") || params.get("token") || "").trim();
    if (fromQuery) {
      try {
        localStorage.setItem(wsTokenStorageKey, fromQuery);
      } catch (_) {
        // Ignore storage errors.
      }
      try {
        sessionStorage.setItem(wsTokenStorageKey, fromQuery);
      } catch (_) {
        // Ignore storage errors.
      }
      return fromQuery;
    }
    try {
      const stored = String(localStorage.getItem(wsTokenStorageKey) || "").trim();
      if (stored) {
        return stored;
      }
    } catch (_) {
      // Ignore storage errors.
    }
    try {
      const stored = String(sessionStorage.getItem(wsTokenStorageKey) || "").trim();
      if (stored) {
        return stored;
      }
    } catch (_) {
      // Ignore storage errors.
    }
    return "";
  }

  function randomSenderID() {
    try {
      if (window.crypto && typeof window.crypto.getRandomValues === "function") {
        const bytes = new Uint32Array(1);
        window.crypto.getRandomValues(bytes);
        let id = Number(bytes[0] & 0x7fffffff);
        if (id <= 0) {
          id = 1;
        }
        return id;
      }
    } catch (_) {
      // Fall back to Math.random when Web Crypto is unavailable.
    }
    const fallback = Math.floor(Math.random() * 0x7fffffff);
    return fallback > 0 ? fallback : 1;
  }

  async function requestMicrophoneStream(constraints) {
    const mediaDevices = navigator.mediaDevices;
    if (mediaDevices && typeof mediaDevices.getUserMedia === "function") {
      return mediaDevices.getUserMedia(constraints);
    }

    const legacyGetUserMedia = navigator.getUserMedia ||
      navigator.webkitGetUserMedia ||
      navigator.mozGetUserMedia ||
      navigator.msGetUserMedia;
    if (typeof legacyGetUserMedia === "function") {
      return new Promise((resolve, reject) => {
        legacyGetUserMedia.call(navigator, constraints, resolve, reject);
      });
    }

    if (!window.isSecureContext) {
      throw new Error(t("mic_insecure_context"));
    }
    throw new Error(t("mic_not_supported"));
  }

  function setConnectionStatus(text, level) {
    ui.connectionStatus.textContent = text;
    ui.connectionStatus.style.color = levelColor(level);
  }

  function levelColor(level) {
    if (level === "ok") {
      return "var(--ok)";
    }
    if (level === "error") {
      return "var(--err)";
    }
    if (level === "warn") {
      return "var(--warn)";
    }
    return "var(--ink)";
  }

  function appendLog(text, level) {
    if (!text) {
      return;
    }
    const ts = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = normalizeLevel(level);
    line.textContent = `[${ts}] ${text}`;
    ui.logBox.appendChild(line);
    ui.logBox.scrollTop = ui.logBox.scrollHeight;
  }

  function bindPTT(button) {
    let activePointerId = null;

    const press = (event) => {
      if (button.disabled) {
        return;
      }
      if (event.pointerType === "mouse" && event.button !== 0) {
        return;
      }
      event.preventDefault();
      if (event.pointerId !== undefined && typeof button.setPointerCapture === "function") {
        try {
          button.setPointerCapture(event.pointerId);
          activePointerId = event.pointerId;
        } catch (_) {
          activePointerId = event.pointerId;
        }
      }
      setPTT(true);
    };
    const release = (event) => {
      if (event) {
        if (activePointerId !== null && event.pointerId !== undefined && event.pointerId !== activePointerId) {
          return;
        }
        event.preventDefault();
      }
      setPTT(false);
      if (event && event.pointerId !== undefined && typeof button.releasePointerCapture === "function") {
        try {
          if (button.hasPointerCapture && button.hasPointerCapture(event.pointerId)) {
            button.releasePointerCapture(event.pointerId);
          }
        } catch (_) {
          // Ignore capture release errors.
        }
      }
      activePointerId = null;
    };

    button.addEventListener("pointerdown", press);
    button.addEventListener("pointerup", release);
    button.addEventListener("pointercancel", release);
    button.addEventListener("lostpointercapture", release);
    button.addEventListener("pointerleave", (event) => {
      if (event.pointerType === "mouse") {
        release(event);
      }
    });
    button.addEventListener("contextmenu", (event) => {
      event.preventDefault();
    });
    button.addEventListener("selectstart", (event) => {
      event.preventDefault();
    });
  }

  async function setPTT(pressed, emitCue = true) {
    if (state.audioTxTask) {
      return;
    }
    if (pressed && state.micPermissionDenied) {
      return;
    }
    if (state.pttPressed === pressed) {
      return;
    }
    state.pttPressed = pressed;
    ui.pttButton.classList.toggle("active", pressed);

    if (!state.connected) {
      state.pttPressed = false;
      ui.pttButton.classList.remove("active");
      return;
    }

    if (pressed) {
      state.txFrameIndex = 0;
      try {
        if (state.player) {
          await state.player.resume();
        }
      } catch (_) {
        // Keep going without hard fail.
      }
      try {
        if (state.mic) {
          await state.mic.resume();
        }
      } catch (_) {
        // Keep going without hard fail.
      }
      if (emitCue) {
        playCue("pttOn");
      }
    } else {
      if (emitCue) {
        playCue("pttOff");
      }
      state.txQueue = [];
      stopTxLoop();
      state.txFrameIndex = 0;
    }

    sendCommand({ type: "ptt", pressed });
  }

  class MicCapture {
    constructor(onFrame) {
      this.onFrame = onFrame;
      this.ctx = null;
      this.stream = null;
      this.source = null;
      this.processor = null;
      this.workletNode = null;
      this.silence = null;
      this.started = false;

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
        return;
      }

      this.stream = await requestMicrophoneStream({
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
      this.silence = this.ctx.createGain();
      this.silence.gain.value = 0;

      const workletReady = await this.tryStartWithWorklet();
      if (workletReady) {
        this.started = true;
        return;
      }

      this.processor = this.ctx.createScriptProcessor(2048, 1, 1);

      this.source.connect(this.processor);
      this.processor.connect(this.silence);
      this.silence.connect(this.ctx.destination);

      this.processor.onaudioprocess = (event) => {
        const input = event.inputBuffer.getChannelData(0);
        this.pushInput(input);
      };

      this.started = true;
    }

    async tryStartWithWorklet() {
      if (!this.ctx || !this.source || !this.silence) {
        return false;
      }
      if (!this.ctx.audioWorklet || typeof AudioWorkletNode === "undefined") {
        return false;
      }

      try {
        await this.ctx.audioWorklet.addModule(resolveWorkletURL("mic-capture-worklet.js"));
        this.workletNode = new AudioWorkletNode(this.ctx, "incomudon-mic-capture", {
          numberOfInputs: 1,
          numberOfOutputs: 1,
          outputChannelCount: [1],
        });
        this.workletNode.port.onmessage = (event) => {
          this.handleWorkletFrame(event.data);
        };

        this.source.connect(this.workletNode);
        this.workletNode.connect(this.silence);
        this.silence.connect(this.ctx.destination);
        return true;
      } catch (_) {
        if (this.workletNode) {
          try {
            this.workletNode.disconnect();
          } catch (_) {
            // Ignore disconnect errors.
          }
          this.workletNode = null;
        }
        return false;
      }
    }

    handleWorkletFrame(payload) {
      if (!payload) {
        return;
      }

      let samples;
      if (payload instanceof ArrayBuffer) {
        samples = new Int16Array(payload);
      } else if (ArrayBuffer.isView(payload)) {
        samples = new Int16Array(payload.buffer, payload.byteOffset, Math.floor(payload.byteLength / 2));
      } else {
        return;
      }

      if (samples.length < 160) {
        return;
      }
      this.onFrame(int16ToPCMBytes(samples.subarray(0, 160)));
    }

    async resume() {
      if (!this.ctx) {
        return;
      }
      if (this.ctx.state === "suspended") {
        await this.ctx.resume();
      }
    }

    stop() {
      if (this.processor) {
        this.processor.disconnect();
        this.processor.onaudioprocess = null;
        this.processor = null;
      }
      if (this.workletNode) {
        this.workletNode.port.onmessage = null;
        this.workletNode.disconnect();
        this.workletNode = null;
      }
      if (this.source) {
        this.source.disconnect();
        this.source = null;
      }
      if (this.silence) {
        this.silence.disconnect();
        this.silence = null;
      }
      if (this.stream) {
        this.stream.getTracks().forEach((track) => track.stop());
        this.stream = null;
      }
      if (this.ctx) {
        this.ctx.close().catch(() => {});
        this.ctx = null;
      }

      this.started = false;
      this.inputBuffer = [];
      this.inputStart = 0;
      this.resampleOffset = 0;
      this.pcmBuffer = [];
      this.pcmStart = 0;
      this.lpState = 0;
    }

    pushInput(chunk) {
      for (let i = 0; i < chunk.length; i += 1) {
        this.inputBuffer.push(chunk[i]);
      }

      let availableInput = this.inputBuffer.length - this.inputStart;
      while (this.resampleOffset + this.downsampleRatio <= availableInput - 1) {
        const baseOffset = Math.floor(this.resampleOffset);
        const base = this.inputStart + baseOffset;
        const frac = this.resampleOffset - baseOffset;
        const a = this.inputBuffer[base];
        const b = this.inputBuffer[Math.min(base + 1, this.inputBuffer.length - 1)];
        const interpolated = a + (b - a) * frac;

        // Mild smoothing to reduce high-frequency click artifacts after downsampling.
        this.lpState += 0.22 * (interpolated - this.lpState);
        this.pcmBuffer.push(floatToInt16(this.lpState));
        this.resampleOffset += this.downsampleRatio;
        availableInput = this.inputBuffer.length - this.inputStart;
      }

      const consumed = Math.floor(this.resampleOffset);
      if (consumed > 0) {
        this.inputStart += consumed;
        this.resampleOffset -= consumed;
      }
      if (this.inputStart > 4096 && this.inputStart * 2 >= this.inputBuffer.length) {
        this.inputBuffer = this.inputBuffer.slice(this.inputStart);
        this.inputStart = 0;
      }

      while (this.pcmBuffer.length - this.pcmStart >= 160) {
        const frameBytes = new Uint8Array(320);
        const view = new DataView(frameBytes.buffer);
        for (let i = 0; i < 160; i += 1) {
          view.setInt16(i * 2, this.pcmBuffer[this.pcmStart + i], true);
        }
        this.pcmStart += 160;
        this.onFrame(frameBytes);
      }
      if (this.pcmStart > 2048 && this.pcmStart * 2 >= this.pcmBuffer.length) {
        this.pcmBuffer = this.pcmBuffer.slice(this.pcmStart);
        this.pcmStart = 0;
      }
    }
  }

  class OpusUplinkEncoder {
    constructor(onPacket) {
      this.onPacket = onPacket;
      this.encoder = null;
      this.started = false;
      this.timestampUs = 0;
      this.sampleRate = 8000;
      this.channels = 1;
    }

    static isSupported() {
      return typeof window.AudioEncoder !== "undefined" &&
        typeof window.AudioData !== "undefined";
    }

    async start() {
      if (this.started) {
        return;
      }
      if (!OpusUplinkEncoder.isSupported()) {
        throw new Error("WebCodecs AudioEncoder is not supported");
      }

      const config = {
        codec: "opus",
        sampleRate: this.sampleRate,
        numberOfChannels: this.channels,
        bitrate: 20000,
      };

      const support = await AudioEncoder.isConfigSupported(config);
      if (!support || !support.supported) {
        throw new Error("Opus AudioEncoder configuration is not supported");
      }

      this.encoder = new AudioEncoder({
        output: (chunk) => {
          const bytes = new Uint8Array(chunk.byteLength);
          chunk.copyTo(bytes);
          this.onPacket(bytes);
        },
        error: (err) => {
          appendLog(`opus encoder error: ${err.message || err}`, "warn");
        },
      });
      this.encoder.configure(config);
      this.timestampUs = 0;
      this.started = true;
    }

    encodeFrame(pcmFrame) {
      if (!this.started || !this.encoder) {
        return;
      }
      if (!pcmFrame || pcmFrame.length < 2) {
        return;
      }

      const frameBytes = new Uint8Array(pcmFrame.length);
      frameBytes.set(pcmFrame);
      const frameSamples = Math.floor(frameBytes.length / 2);
      if (frameSamples <= 0) {
        return;
      }

      const audioData = new AudioData({
        format: "s16",
        sampleRate: this.sampleRate,
        numberOfFrames: frameSamples,
        numberOfChannels: this.channels,
        timestamp: this.timestampUs,
        data: frameBytes,
      });

      this.encoder.encode(audioData);
      audioData.close();
      this.timestampUs += Math.round((frameSamples * 1000000) / this.sampleRate);
    }

    async flush() {
      if (!this.encoder) {
        return;
      }
      await this.encoder.flush();
    }

    close() {
      if (!this.encoder) {
        this.started = false;
        return;
      }
      try {
        this.encoder.flush().catch(() => {});
      } catch (_) {
        // Keep closing even if flush is unavailable.
      }
      this.encoder.close();
      this.encoder = null;
      this.started = false;
      this.timestampUs = 0;
    }
  }

  class OpusDownlinkDecoder {
    constructor(onPCMFrame) {
      this.onPCMFrame = onPCMFrame;
      this.decoder = null;
      this.started = false;
      this.timestampUs = 0;
      this.sampleRate = 8000;
      this.channels = 1;
      this.frameSamples = 160;
    }

    static isSupported() {
      return typeof window.AudioDecoder !== "undefined" &&
        typeof window.EncodedAudioChunk !== "undefined" &&
        typeof window.AudioData !== "undefined";
    }

    async start() {
      if (this.started) {
        return;
      }
      if (!OpusDownlinkDecoder.isSupported()) {
        throw new Error(t("opus_decoder_not_supported"));
      }

      const config = {
        codec: "opus",
        sampleRate: this.sampleRate,
        numberOfChannels: this.channels,
      };

      const support = await AudioDecoder.isConfigSupported(config);
      if (!support || !support.supported) {
        throw new Error(t("opus_decoder_config_not_supported"));
      }

      this.decoder = new AudioDecoder({
        output: (audioData) => {
          this.handleOutput(audioData);
        },
        error: (err) => {
          appendLog(t("log_downlink_opus_decode_failed", { error: err.message || err }), "warn");
        },
      });
      this.decoder.configure(config);
      this.timestampUs = 0;
      this.started = true;
    }

    decodePacket(packet) {
      if (!this.started || !this.decoder) {
        return;
      }
      if (!packet || packet.length === 0) {
        return;
      }

      const bytes = new Uint8Array(packet.length);
      bytes.set(packet);
      const durationUs = Math.round((this.frameSamples * 1000000) / this.sampleRate);

      try {
        const chunk = new EncodedAudioChunk({
          type: "key",
          timestamp: this.timestampUs,
          duration: durationUs,
          data: bytes,
        });
        this.decoder.decode(chunk);
        this.timestampUs += durationUs;
      } catch (err) {
        appendLog(t("log_downlink_opus_decode_failed", { error: err.message || err }), "warn");
      }
    }

    handleOutput(audioData) {
      try {
        const frameCount = Number(audioData.numberOfFrames || 0);
        if (frameCount <= 0) {
          return;
        }
        const sampleRate = Number(audioData.sampleRate || this.sampleRate) || this.sampleRate;
        const channels = Math.max(1, Number(audioData.numberOfChannels || 1));
        const samples = frameCount * channels;
        const pcmInterleaved = new Int16Array(samples);

        try {
          audioData.copyTo(pcmInterleaved, { planeIndex: 0, format: "s16" });
        } catch (_) {
          audioData.copyTo(pcmInterleaved, { planeIndex: 0 });
        }

        if (channels === 1) {
          this.onPCMFrame({
            bytes: int16ToPCMBytes(pcmInterleaved),
            sampleRate,
          });
          return;
        }

        const mono = new Int16Array(frameCount);
        for (let i = 0; i < frameCount; i += 1) {
          mono[i] = pcmInterleaved[i * channels];
        }
        this.onPCMFrame({
          bytes: int16ToPCMBytes(mono),
          sampleRate,
        });
      } catch (err) {
        appendLog(t("log_downlink_opus_decode_failed", { error: err.message || err }), "warn");
      } finally {
        audioData.close();
      }
    }

    close() {
      if (!this.decoder) {
        this.started = false;
        return;
      }
      try {
        this.decoder.flush().catch(() => {});
      } catch (_) {
        // Keep closing even if flush is unavailable.
      }
      this.decoder.close();
      this.decoder = null;
      this.started = false;
      this.timestampUs = 0;
    }
  }

  class PCMPlayer {
    constructor() {
      this.ctx = null;
      this.nextPlayTime = 0;
      this.isAndroid = isAndroidBrowser();
      this.streamMode = this.isAndroid;
      this.streamModeKind = "none";
      this.startupLeadSec = this.isAndroid ? 0.26 : 0.05;
      this.catchupLeadSec = this.isAndroid ? 0.12 : 0.03;
      this.softLagSec = this.isAndroid ? -0.01 : -0.02;
      this.hardLagSec = this.isAndroid ? -0.25 : -0.12;
      this.maxLeadSec = this.isAndroid ? 1.2 : 0.8;
      this.declickSamples = 0;
      this.prevTailSample = 0;
      this.hasPrevTailSample = false;
      this.resampleFromRate = 0;
      this.resamplePos = 0;
      this.prevInputSample = 0;
      this.hasPrevInputSample = false;
      this.streamNode = null;
      this.workletNode = null;
      this.workletInitAttempted = false;
      this.streamChunks = [];
      this.streamOffset = 0;
      this.streamBufferedSamples = 0;
      this.streamPrimeSamples = this.isAndroid ? 8192 : 2048;
      this.streamMaxSamples = this.isAndroid ? 96000 : 24000;
      this.streamPrimed = false;
      this.streamHoldSample = 0;
      this.streamUnderrunBlocks = 0;
      this.keepAliveSource = null;
      this.keepAliveGain = null;
      this.lastResumeAttemptMs = 0;
    }

    async resume() {
      if (!this.ctx) {
        this.ctx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (this.ctx.state !== "running") {
        await this.ctx.resume();
      }
      this.ensureKeepAliveSource();
      await this.ensureStreamOutput();
    }

    ensureKeepAliveSource() {
      if (!this.ctx || this.keepAliveSource) {
        return;
      }
      try {
        const gain = this.ctx.createGain();
        gain.gain.value = 0;
        gain.connect(this.ctx.destination);

        if (typeof this.ctx.createConstantSource === "function") {
          const src = this.ctx.createConstantSource();
          src.offset.value = 0;
          src.connect(gain);
          src.start();
          this.keepAliveSource = src;
        } else {
          const osc = this.ctx.createOscillator();
          osc.type = "sine";
          osc.frequency.value = 18;
          osc.connect(gain);
          osc.start();
          this.keepAliveSource = osc;
        }
        this.keepAliveGain = gain;
      } catch (_) {
        // Keep running even if keep-alive source is unavailable.
      }
    }

    resumeIfNeeded() {
      if (!this.ctx) {
        return;
      }
      const stateName = String(this.ctx.state || "");
      if (stateName === "running") {
        return;
      }
      const now = Date.now();
      if (now - this.lastResumeAttemptMs < 1500) {
        return;
      }
      this.lastResumeAttemptMs = now;
      this.ctx.resume()
        .then(() => {
          this.ensureKeepAliveSource();
        })
        .catch(() => {});
    }

    async ensureStreamOutput() {
      if (!this.streamMode || !this.ctx || this.streamModeKind !== "none") {
        return;
      }

      if (!this.workletInitAttempted &&
          this.ctx.audioWorklet &&
          typeof AudioWorkletNode !== "undefined") {
        this.workletInitAttempted = true;
        try {
          await this.ctx.audioWorklet.addModule(resolveWorkletURL("pcm-playback-worklet.js"));
          this.workletNode = new AudioWorkletNode(this.ctx, "incomudon-pcm-playback", {
            numberOfInputs: 0,
            numberOfOutputs: 1,
            outputChannelCount: [1],
          });
          this.workletNode.port.postMessage({
            type: "config",
            primeSamples: this.streamPrimeSamples,
            maxSamples: this.streamMaxSamples,
          });
          if (this.streamBufferedSamples > 0 && this.streamChunks.length > 0) {
            if (this.streamOffset > 0) {
              const head = this.streamChunks[0];
              this.streamChunks[0] = head.subarray(this.streamOffset);
              this.streamOffset = 0;
            }
            for (let i = 0; i < this.streamChunks.length; i += 1) {
              const chunk = this.streamChunks[i];
              if (!chunk || chunk.length === 0) {
                continue;
              }
              const payload = new Float32Array(chunk.length);
              payload.set(chunk);
              this.workletNode.port.postMessage({ type: "pcm", samples: payload }, [payload.buffer]);
            }
            this.streamChunks = [];
            this.streamOffset = 0;
            this.streamBufferedSamples = 0;
            this.streamPrimed = false;
            this.streamHoldSample = 0;
            this.streamUnderrunBlocks = 0;
          }
          this.workletNode.connect(this.ctx.destination);
          this.streamModeKind = "worklet";
          return;
        } catch (_) {
          if (this.workletNode) {
            try {
              this.workletNode.disconnect();
            } catch (_) {
              // Ignore disconnect errors.
            }
            this.workletNode = null;
          }
        }
      }

      if (typeof this.ctx.createScriptProcessor === "function") {
        const node = this.ctx.createScriptProcessor(2048, 1, 1);
        node.onaudioprocess = (event) => {
          const out = event.outputBuffer.getChannelData(0);
          this.fillStreamOutput(out);
        };
        node.connect(this.ctx.destination);
        this.streamNode = node;
        this.streamModeKind = "script";
        return;
      }

      this.streamMode = false;
    }

    resetTimeline() {
      this.nextPlayTime = 0;
      this.prevTailSample = 0;
      this.hasPrevTailSample = false;
      this.resampleFromRate = 0;
      this.resamplePos = 0;
      this.prevInputSample = 0;
      this.hasPrevInputSample = false;
      this.streamChunks = [];
      this.streamOffset = 0;
      this.streamBufferedSamples = 0;
      this.streamPrimed = false;
      this.streamHoldSample = 0;
      this.streamUnderrunBlocks = 0;
      if (this.streamModeKind === "worklet" && this.workletNode) {
        try {
          this.workletNode.port.postMessage({ type: "reset" });
        } catch (_) {
          // Ignore postMessage errors.
        }
      }
    }

    resampleContinuous(input, fromRate, toRate) {
      if (!input || input.length <= 0) {
        return new Float32Array(0);
      }
      if (fromRate === toRate || !Number.isFinite(fromRate) || !Number.isFinite(toRate) || fromRate <= 0 || toRate <= 0) {
        this.resampleFromRate = 0;
        this.resamplePos = 0;
        this.hasPrevInputSample = false;
        return input;
      }

      const sampleAt = (idx, prev, src) => {
        if (idx <= 0) {
          return prev;
        }
        const srcIndex = idx - 1;
        if (srcIndex < 0) {
          return prev;
        }
        if (srcIndex >= src.length) {
          return src[src.length - 1];
        }
        return src[srcIndex];
      };

      if (!this.hasPrevInputSample || this.resampleFromRate !== fromRate) {
        this.resampleFromRate = fromRate;
        this.resamplePos = 0;
        this.prevInputSample = input[0];
        this.hasPrevInputSample = true;
      }

      const prev = this.prevInputSample;
      const step = fromRate / toRate;
      const extLength = input.length + 1;
      let pos = this.resamplePos;
      if (!Number.isFinite(pos) || pos < 0 || pos >= extLength - 1) {
        pos = 0;
      }
      const maxOut = Math.max(1, Math.ceil((extLength - 1 - pos) / step) + 1);
      const output = new Float32Array(maxOut);
      let outLen = 0;
      while (pos + 1 < extLength && outLen < output.length) {
        const i0 = Math.floor(pos);
        const frac = pos - i0;
        const a = sampleAt(i0, prev, input);
        const b = sampleAt(i0 + 1, prev, input);
        output[outLen] = a + ((b - a) * frac);
        outLen += 1;
        pos += step;
      }

      this.resamplePos = pos - input.length;
      if (!Number.isFinite(this.resamplePos) || this.resamplePos < 0 || this.resamplePos > 1) {
        this.resamplePos = 0;
      }
      this.prevInputSample = input[input.length - 1];
      this.hasPrevInputSample = true;

      if (outLen === output.length) {
        return output;
      }
      const trimmed = new Float32Array(outLen);
      if (outLen > 0) {
        trimmed.set(output.subarray(0, outLen));
      }
      return trimmed;
    }

    enqueueStreamSamples(samples) {
      if (!samples || samples.length <= 0) {
        return;
      }

      if (this.streamModeKind === "worklet" && this.workletNode) {
        try {
          this.workletNode.port.postMessage({ type: "pcm", samples }, [samples.buffer]);
        } catch (_) {
          // Ignore worklet transfer errors and keep going.
        }
        return;
      }

      if (this.streamBufferedSamples > this.streamMaxSamples) {
        this.streamChunks = [];
        this.streamOffset = 0;
        this.streamBufferedSamples = 0;
        this.streamPrimed = false;
      }

      let overflow = (this.streamBufferedSamples + samples.length) - this.streamMaxSamples;
      while (overflow > 0 && this.streamChunks.length > 0) {
        const head = this.streamChunks[0];
        const available = head.length - this.streamOffset;
        if (available <= overflow) {
          this.streamChunks.shift();
          this.streamOffset = 0;
          this.streamBufferedSamples -= available;
          overflow -= available;
        } else {
          this.streamOffset += overflow;
          this.streamBufferedSamples -= overflow;
          overflow = 0;
        }
      }

      this.streamChunks.push(samples);
      this.streamBufferedSamples += samples.length;
      this.streamUnderrunBlocks = 0;
    }

    fillStreamOutput(out) {
      out.fill(0);
      if (this.streamBufferedSamples <= 0) {
        if (this.streamPrimed) {
          let hold = this.streamHoldSample;
          for (let i = 0; i < out.length; i += 1) {
            out[i] = hold;
            hold *= 0.999;
          }
          this.streamHoldSample = hold;
          this.streamUnderrunBlocks += 1;
          if (this.streamUnderrunBlocks >= 8) {
            this.streamPrimed = false;
          }
        }
        return;
      }
      if (!this.streamPrimed) {
        if (this.streamBufferedSamples < this.streamPrimeSamples) {
          return;
        }
        this.streamPrimed = true;
      }

      let write = 0;
      while (write < out.length && this.streamChunks.length > 0) {
        const head = this.streamChunks[0];
        const available = head.length - this.streamOffset;
        if (available <= 0) {
          this.streamChunks.shift();
          this.streamOffset = 0;
          continue;
        }
        const n = Math.min(available, out.length - write);
        out.set(head.subarray(this.streamOffset, this.streamOffset + n), write);
        write += n;
        this.streamOffset += n;
        this.streamBufferedSamples -= n;
        if (this.streamOffset >= head.length) {
          this.streamChunks.shift();
          this.streamOffset = 0;
        }
      }
      if (write > 0) {
        this.streamHoldSample = out[write - 1];
      }
      if (write < out.length) {
        let hold = this.streamHoldSample;
        for (let i = write; i < out.length; i += 1) {
          out[i] = hold;
          hold *= 0.999;
        }
        this.streamHoldSample = hold;
        this.streamUnderrunBlocks += 1;
      } else {
        this.streamUnderrunBlocks = 0;
      }
    }

    playPCM(bytes, sampleRate = 8000) {
      if (!bytes || bytes.length < 2) {
        return;
      }
      if (!this.ctx) {
        return;
      }
      this.resumeIfNeeded();

      const sampleCount = Math.floor(bytes.length / 2);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const input = new Float32Array(sampleCount);
      for (let i = 0; i < sampleCount; i += 1) {
        input[i] = view.getInt16(i * 2, true) / 32768;
      }

      const fromRate = Number(sampleRate) > 0 ? Number(sampleRate) : 8000;
      const output = this.resampleContinuous(input, fromRate, this.ctx.sampleRate);
      if (output.length <= 0) {
        return;
      }

      if (this.declickSamples > 0 && this.hasPrevTailSample) {
        const blendCount = Math.min(this.declickSamples, output.length);
        const prev = this.prevTailSample;
        for (let i = 0; i < blendCount; i += 1) {
          const t = (i + 1) / (blendCount + 1);
          output[i] = prev + ((output[i] - prev) * t);
        }
      }
      this.prevTailSample = output[output.length - 1];
      this.hasPrevTailSample = true;

      if (this.streamMode) {
        this.ensureStreamOutput().catch(() => {});
        this.enqueueStreamSamples(output);
        return;
      }

      const now = this.ctx.currentTime;
      const lead = this.nextPlayTime - now;
      if (!Number.isFinite(this.nextPlayTime) ||
          lead < this.hardLagSec ||
          lead > this.maxLeadSec) {
        this.nextPlayTime = now + this.startupLeadSec;
        this.hasPrevTailSample = false;
      } else if (lead < this.softLagSec) {
        // Minor drift: catch up gently without resetting cross-frame continuity.
        this.nextPlayTime = now + this.catchupLeadSec;
      }

      const buffer = this.ctx.createBuffer(1, output.length, this.ctx.sampleRate);
      buffer.copyToChannel(output, 0);

      const source = this.ctx.createBufferSource();
      source.buffer = buffer;
      source.connect(this.ctx.destination);

      source.start(this.nextPlayTime);
      this.nextPlayTime += buffer.duration;
    }
  }

  class CuePlayer {
    constructor(player) {
      this.player = player || null;
      this.bufferCache = new Map();
      this.pendingLoads = new Map();
    }

    play(source, onError) {
      if (!source) {
        return;
      }
      this.playInternal(source, onError).catch((err) => {
        if (onError) {
          onError(err && err.message ? err.message : String(err));
        }
      });
    }

    async playInternal(source, onError) {
      if (await this.tryPlayWebAudio(source)) {
        return;
      }
      this.playHTMLAudio(source, onError);
    }

    async tryPlayWebAudio(source) {
      if (!this.player) {
        return false;
      }
      try {
        await this.player.resume();
      } catch (_) {
        this.player.resumeIfNeeded();
      }

      const ctx = this.player.ctx;
      if (!ctx || String(ctx.state || "") !== "running") {
        return false;
      }

      let buffer = this.bufferCache.get(source);
      if (!buffer) {
        buffer = await this.loadBuffer(source, ctx);
        if (!buffer) {
          return false;
        }
        this.bufferCache.set(source, buffer);
      }

      const node = ctx.createBufferSource();
      node.buffer = buffer;
      node.connect(ctx.destination);
      node.start();
      return true;
    }

    async loadBuffer(source, ctx) {
      let pending = this.pendingLoads.get(source);
      if (!pending) {
        pending = fetch(source)
          .then((res) => {
            if (!res || !res.ok) {
              throw new Error(`failed to fetch cue source: ${res ? res.status : "unknown"}`);
            }
            return res.arrayBuffer();
          })
          .then((bytes) => new Promise((resolve, reject) => {
            ctx.decodeAudioData(bytes.slice(0), resolve, reject);
          }));
        this.pendingLoads.set(source, pending);
      }

      try {
        return await pending;
      } finally {
        this.pendingLoads.delete(source);
      }
    }

    playHTMLAudio(source, onError) {
      try {
        const audio = new Audio(source);
        audio.preload = "auto";
        audio.volume = 1.0;
        const playPromise = audio.play();
        if (playPromise && typeof playPromise.catch === "function") {
          playPromise.catch((err) => {
            if (onError) {
              onError(err && err.message ? err.message : String(err));
            }
          });
        }
      } catch (err) {
        if (onError) {
          onError(err && err.message ? err.message : String(err));
        }
      }
    }
  }

  function floatToInt16(value) {
    const clamped = Math.max(-1, Math.min(1, value));
    return clamped < 0 ? Math.round(clamped * 32768) : Math.round(clamped * 32767);
  }

  function int16ToPCMBytes(samples) {
    const out = new Uint8Array(samples.length * 2);
    const view = new DataView(out.buffer);
    for (let i = 0; i < samples.length; i += 1) {
      view.setInt16(i * 2, samples[i], true);
    }
    return out;
  }

  state.player = new PCMPlayer();
  state.cuePlayer = new CuePlayer(state.player);
  state.mic = new MicCapture((frame) => {
    if (!state.connected || !state.pttPressed || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    if (state.audioTxTask) {
      return;
    }
    transmitUplinkFrame(frame);
  });
})();

