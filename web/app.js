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
  const settingsLockStorageKey = "incomudon.pwa.settings_lock.v1";
  const settingsUnlockSessionKey = "incomudon.pwa.settings_lock.unlocked.v1";
  const settingsLockPBKDF2Iterations = 310000;

  const txCodecPCM = "pcm";
  const txCodecCodec2 = "codec2";
  const txCodecOpus = "opus";
  const defaultOpusBitrate = 12000;
  const micVolumeMinPercent = 0;
  const micVolumeMaxPercent = 300;
  const micVolumeDefaultPercent = 200;
  const micVolumeSnapPercent = 200;
  const micVolumeSnapThreshold = 4;
  const passwordHashPrefix = "sha256:";
  const sha256HexPattern = /^[0-9a-f]{64}$/i;
  const codec2BitrateOptions = [450, 700, 1600, 2400, 3200];
  const opusBitrateOptions = [6000, 8000, 12000, 16000, 20000, 64000, 96000, 128000];
  const settingsReconnectDebounceMs = 350;
  // The media path must prefer current audio over queued, stale frames.
  const txWebSocketHighWaterBytes = 1024;
  const txOpusMaxQueuedFrames = 4;
  const audioFrameDurationSec = 160 / 8000;
  const audioTxPacerModulePromises = new WeakMap();
  const audioDebugStorageKey = "incomudon.pwa.audio_debug.v1";
  const embeddedQuery = new URLSearchParams(window.location.search || "");
  const packetDebugQuery = embeddedQuery.get("packet_debug") === "1";
  const embeddedSlotIndexRaw = Number.parseInt(embeddedQuery.get("slot") || "", 10);
  const isEmbeddedSlot = embeddedQuery.get("embed") === "1" &&
    Number.isInteger(embeddedSlotIndexRaw) && embeddedSlotIndexRaw > 0;
  const embeddedSlotIndex = isEmbeddedSlot ? embeddedSlotIndexRaw : 0;
  const embeddedStoragePrefix = isEmbeddedSlot ? `multi:${embeddedSlotIndex}:` : "";
  if (isEmbeddedSlot) {
    document.body.classList.add("embedded-slot");
  }
  const mediaStorageDBName = "incomudon.pwa.media.v1";
  const mediaStorageStoreName = "files";
  const mediaStorageVersion = 1;
  const mediaStorageCuePrefix = `${embeddedStoragePrefix}cue:`;
  const mediaStorageAudioTxPrefix = `${embeddedStoragePrefix}audioTx:`;
  const maxCueFilesBytes = 20 * 1024 * 1024;
  const maxAudioTxFilesBytes = 100 * 1024 * 1024;
  const maxPersistedMediaBytes = maxCueFilesBytes + maxAudioTxFilesBytes;

  const ui = {
    main: document.getElementById("appMain"),
    titleMain: document.getElementById("titleMain"),
    languageSelect: document.getElementById("languageSelect"),
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
    settingsExportButton: document.getElementById("settingsExportButton"),
    settingsImportButton: document.getElementById("settingsImportButton"),
    settingsImportFile: document.getElementById("settingsImportFile"),
    advancedSettingsDetails: document.getElementById("advancedSettingsDetails"),
    cueSettingsCard: document.getElementById("cueSettingsCard"),
    audioTxSettingsCard: document.getElementById("audioTxSettingsCard"),
    relayHost: document.getElementById("relayHost"),
    relayPort: document.getElementById("relayPort"),
    channelId: document.getElementById("channelId"),
    senderId: document.getElementById("senderId"),
    password: document.getElementById("password"),
    cryptoMode: document.getElementById("cryptoMode"),
    codecMode: document.getElementById("codecMode"),
    browserCodec: document.getElementById("browserCodec"),
    wsToken: document.getElementById("wsToken"),
    txCodec: document.getElementById("txCodec"),
    micVolume: document.getElementById("micVolume"),
    micVolumeValue: document.getElementById("micVolumeValue"),
    receiveOnly: document.getElementById("receiveOnly"),
    selfSenderMute: document.getElementById("selfSenderMute"),
    qosEnabled: document.getElementById("qosEnabled"),
    fecEnabled: document.getElementById("fecEnabled"),
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
    packetDebugCard: document.getElementById("packetDebugCard"),
    packetDebugOutput: document.getElementById("packetDebugOutput"),
    packetDebugReset: document.getElementById("packetDebugReset"),
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
    cuePttOnFileStatus: document.getElementById("cuePttOnFileStatus"),
    cuePttOffFileStatus: document.getElementById("cuePttOffFileStatus"),
    cueCarrierFileStatus: document.getElementById("cueCarrierFileStatus"),
    cuePttOnTest: document.getElementById("cuePttOnTest"),
    cuePttOffTest: document.getElementById("cuePttOffTest"),
    cueCarrierTest: document.getElementById("cueCarrierTest"),
    cuePttOnReset: document.getElementById("cuePttOnReset"),
    cuePttOffReset: document.getElementById("cuePttOffReset"),
    cueCarrierReset: document.getElementById("cueCarrierReset"),
    audioTxSlotCount: document.getElementById("audioTxSlotCount"),
    audioTxLoopEnabled: document.getElementById("audioTxLoopEnabled"),
    audioTxSlots: document.getElementById("audioTxSlots"),
    clearSavedMediaBtn: document.getElementById("clearSavedMediaBtn"),
    logoutBtn: document.getElementById("logoutBtn"),
  };

  const settingsStorageKey = isEmbeddedSlot
    ? `incomudon.pwa.multi.slot.${embeddedSlotIndex}.settings.v1`
    : "incomudon.pwa.settings.v1";
  const wsTokenStorageKey = "incomudon.pwa.ws_token.v1";
  const localeStorageKey = "incomudon.pwa.locale.v1";
  const fallbackLocale = "en";
  const supportedUiLocales = ["en", "ja"];
  const authRemainingHeader = "X-Incomudon-Auth-Remaining-Sec";
  const startupQueryOverrides = readStartupQueryOverrides();
  const initialWSToken = initializeWSToken(startupQueryOverrides);
  const englishFallbackStrings = {
    app_title: "IncomUdon Relay PWA Client",
    header_title: "Relay PWA Client",
    language: "Language",
    advanced_settings: "Advanced Settings",
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
    settings_export: "Export Settings",
    settings_import: "Import Settings",
    settings_import_invalid: "The selected file is not a valid IncomUdon settings export.",
    settings_import_failed: "Settings import failed: {error}",
    settings_imported: "Settings imported. Reload the page to apply the updated settings.",
    settings_export_file: "incomudon-pwa-settings.json",
    settings_value_hidden: "Hidden while settings are locked",
    relay_host: "Relay Host",
    relay_port: "Relay Port",
    channel_id: "Channel ID",
    sender_id: "Sender ID (random if empty)",
    password: "Password",
    password_unchanged: "(Unchanged)",
    crypto_mode: "Crypto Mode",
    codec_mode: "Transmit Bitrate",
    browser_codec: "Browser Codec",
    ws_token: "WS Token",
    tx_codec: "TX Codec",
    mic_volume: "Mic Volume",
    receive_only: "Receive-only mode",
    receive_only_mode: "Receive-only mode",
    self_sender_mute: "Mute own sender ID",
    tx_codec_pcm: "pcm",
    tx_codec_codec2: "codec2",
    tx_codec_opus: "opus",
    qos_enabled: "Network QoS (DSCP EF)",
    fec_enabled: "TX FEC (RS 2-loss)",
    uplink_opus_optional: "opus (optional)",
    pcm_only: "PCM only (no Web-side encode)",
    connect: "Connect",
    disconnect: "Disconnect",
    logout: "Logout",
    connection: "Connection",
    talker: "Talker",
    hold_to_talk: "Hold to Talk (Space)",
    hold_to_talk_remaining: "Hold to Talk ({seconds}s left)",
    cue_sounds: "Cue Sounds",
    cue_ptt_on: "PTT ON Cue",
    cue_ptt_off: "PTT OFF Cue",
    cue_carrier: "Carrier Sense Cue",
    cue_audio_url: "Audio URL",
    cue_local_file: "Local File (stored in browser)",
    media_file_none: "No local file selected",
    media_file_saved: "Saved: {name} ({size})",
    media_file_session: "Session only: {name} ({size})",
    media_clear_saved: "Clear Saved Files",
    media_clear_saved_confirm: "Remove all locally saved cue and audio TX files?",
    audio_tx_files: "Audio File TX",
    audio_tx_slot_count: "Preset Slots",
    audio_tx_slot: "Slot {index}",
    audio_tx_slot_empty: "No file selected",
    audio_tx_send: "Send",
    audio_tx_stop: "Stop",
    audio_tx_select_file: "Select File",
    audio_tx_delete: "Delete",
    audio_tx_loading: "Loading...",
    audio_tx_loop: "Loop playback",
    test: "Test",
    default: "Default",
    events: "Events",
    clear: "Clear",
    packet_debug: "Packet Debug",
    packet_debug_reset: "Reset counters",
    packet_debug_ws: "WebSocket",
    packet_debug_page: "Page",
    packet_debug_context: "Audio contexts",
    packet_debug_tx_generated: "TX generated",
    packet_debug_tx_sent: "TX sent",
    packet_debug_tx_dropped: "TX dropped",
    packet_debug_rx_received: "RX received",
    packet_debug_rx_dropped: "RX dropped",
    packet_debug_playback: "Playback",
    packet_debug_server_ws: "Server WebSocket",
    packet_debug_relay_rx: "Relay RX",
    packet_debug_relay_tx: "Relay TX",
    packet_debug_mix: "Mix / decode",
    packet_debug_talkers: "RX talkers",
    status_connecting: "Connecting",
    status_offline: "Offline",
    status_error: "Error",
    status_reconnecting: "Disconnected (reconnecting...)",
    status_connected: "Connected ({host}:{port})",
    talker_none: "None",
    talker_you: "You",
    log_connect_failed: "connect failed: {error}",
    log_ws_opened: "websocket opened",
    log_ws_closed: "websocket closed",
    log_ws_error: "websocket error",
    log_ws_reconnect_attempt: "websocket disconnected; reconnecting ({attempt}/{max})",
    log_ws_auth_required: "websocket token is required; open with ?ws_token=...",
    log_auth_session_required: "authentication session is missing or expired; please sign in again",
    log_auth_session_remaining_connect: "authentication session remaining at connect: {remaining}",
    log_auth_session_remaining_ptt: "authentication session remaining at PTT: {remaining}",
    log_basic_auth_required: "basic authentication is required; reload the page and authenticate",
    log_browser_codec_opus: "browser codec: opus (uplink/downlink)",
    log_browser_opus_uplink_bitrate: "browser uplink opus bitrate: {bitrateKbps} kbps",
    log_browser_opus_uplink_bitrate_fallback: "browser uplink opus bitrate fallback: requested {requestedKbps} kbps, using {effectiveKbps} kbps",
    log_opus_fallback_pcm: "opus unavailable, fallback to pcm: {error}",
    log_downlink_opus_fallback_pcm: "opus decoder unavailable, fallback to pcm: {error}",
    log_downlink_opus_decode_failed: "opus downlink decode failed: {error}",
    log_audio_output_suspended: "audio output is suspended (tap PTT to resume)",
    log_microphone_start_failed: "microphone start failed: {error}",
    log_microphone_permission_denied: "microphone permission denied; PTT is disabled",
    log_connected_summary: "connected channel={channel} sender={sender} mode={mode} codec={codec}",
    log_talker_started: "talk started: channel={channel} talker={talker}",
    log_talker_ended: "talk ended: channel={channel} talker={talker}",
    log_disconnected: "disconnected",
    log_peer_codec: "peer codec sender={sender} mode={mode} pcmOnly={pcmOnly}",
    log_ready: "ready",
    log_cue_source_empty: "cue source is empty ({label})",
    log_cue_play_failed: "cue play failed ({label}): {error}",
    log_cue_local_selected: "cue local file selected ({label}): {name}",
    log_cue_reset_default: "cue reset to default ({label})",
    log_media_restore_failed: "saved audio files could not be restored: {error}",
    log_media_file_session_only: "could not save {name}; it will be kept for this session only: {error}",
    log_media_storage_cleared: "locally saved audio files cleared",
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
    log_audio_tx_receive_only: "audio file TX is unavailable in receive-only mode",
    log_tx_timeout_forced_off: "TX timed out; forcing PTT off",
    log_password_hash_failed: "password hash failed: {error}",
    log_reconnecting_settings: "settings changed; reconnecting to apply updates",
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
    pttOnEnabled: true,
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
    passwordHash: "",
    pttPressed: false,
    player: null,
    mic: null,
    browserCodec: "pcm",
      txCodec: initialOpusReady ? txCodecOpus : txCodecPCM,
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
    micVolumePercent: micVolumeDefaultPercent,
    receiveOnly: false,
    receiveMuted: false,
    selfSenderMute: true,
    packetDebugEnabled: packetDebugQuery,
    packetDebugTimer: null,
    packetDebugLastSnapshot: null,
    serverPacketStats: null,
    audioDebugEnabled: readAudioDebugEnabled(),
    audioStats: {
      activity: Object.create(null),
      txSent: 0,
      txDropped: 0,
      txDropReasons: Object.create(null),
      rxReceived: 0,
      rxDropped: Object.create(null),
      audioTxTicks: 0,
      audioTxSkipped: 0,
    },
    txRampFrames: 1,
    txFrameIndex: 0,
    txSessionId: 0,
    cuePlayer: null,
    cueFiles: {
      pttOn: null,
      pttOff: null,
      carrier: null,
    },
    audioTxSlots: [],
    audioTxTask: null,
    audioTxLoadingSlot: -1,
    audioTxLoadSequence: 0,
    mediaFilesReady: false,
    mediaFilesReadyPromise: null,
    mediaStoragePersistenceRequested: false,
    lastCarrierCueMs: 0,
    selfSenderId: 0,
    talkerId: 0,
    activeTalkers: [],
    directoryChannels: Object.create(null),
    directorySpeakers: Object.create(null),
    directoryExpiryTimer: null,
    talkAllowed: false,
    serverTalkTimeoutSec: 0,
    serverMultiTalkEnabled: false,
    serverMaxActiveTalkers: 1,
    // A file-TX-to-mic handoff sends PTT_OFF and PTT_ON back-to-back. Ignore
    // the expected release for the old grant so it is not mistaken for a timeout.
    expectedLocalTalkReleaseUntilMs: 0,
    txTimeoutRemainingSec: 0,
    txTimeoutDeadlineMs: 0,
    txTimeoutTicker: null,
    connectionView: {
      kind: "offline",
      host: "",
      port: 0,
    },
    settingsReconnectTimer: null,
    reconnectTimer: null,
    reconnectAttempt: 0,
    reconnectMaxAttempts: 3,
    disconnectRequested: false,
    hiddenRelaySettings: {
      relayHost: "",
      relayPort: "",
      wsToken: "",
    },
    settingsLockConfig: loadSettingsLockConfig(),
    settingsUnlocked: false,
    settingsLockBusy: false,
    startupAutoConnectAttempted: false,
    startupLegacyPlainPassword: "",
    lastAuthSessionNoticeMs: 0,
  };
  function readAudioDebugEnabled() {
    if (embeddedQuery.get("audio_debug") === "1") {
      return true;
    }
    try {
      return window.localStorage.getItem(audioDebugStorageKey) === "1";
    } catch (_) {
      return false;
    }
  }

  function audioDebug(event, details = {}) {
    if (!state.audioDebugEnabled) {
      return;
    }
    const ws = state.ws;
    console.debug("[IncomUdon audio]", event, {
      atMs: Math.round(performance.now()),
      visibility: document.visibilityState,
      hidden: !!document.hidden,
      focused: document.hasFocus(),
      wsReadyState: ws ? ws.readyState : WebSocket.CLOSED,
      bufferedAmount: ws ? Number(ws.bufferedAmount || 0) : 0,
      ...details,
    });
  }

  function recordAudioActivity(kind, details = {}) {
    const now = performance.now();
    const activity = state.audioStats.activity[kind] || {
      count: 0,
      bytes: 0,
      lastAtMs: 0,
      lastLogMs: 0,
      lastGapMs: 0,
      intervalSamples: 0,
      intervalTotalMs: 0,
      intervalMaxMs: 0,
    };
    const gapMs = activity.lastAtMs > 0 ? now - activity.lastAtMs : 0;
    activity.count += 1;
    const bytes = Number(details.bytes);
    if (Number.isFinite(bytes) && bytes > 0) {
      activity.bytes += Math.floor(bytes);
    }
    if (gapMs > 0) {
      activity.lastGapMs = gapMs;
      activity.intervalSamples += 1;
      activity.intervalTotalMs += gapMs;
      activity.intervalMaxMs = Math.max(activity.intervalMaxMs, gapMs);
    }
    activity.lastAtMs = now;
    state.audioStats.activity[kind] = activity;
    if (state.audioDebugEnabled && (gapMs >= 80 || now - activity.lastLogMs >= 1000)) {
      activity.lastLogMs = now;
      audioDebug("frame", {
        kind,
        count: activity.count,
        gapMs: Math.round(gapMs),
        ...details,
      });
    }
  }

  function noteDroppedTxFrame(reason, details = {}) {
    state.audioStats.txDropped += 1;
    const key = String(reason || "unknown");
    state.audioStats.txDropReasons[key] = Number(state.audioStats.txDropReasons[key] || 0) + 1;
    audioDebug("tx-drop", {
      reason: key,
      dropped: state.audioStats.txDropped,
      ...details,
    });
  }

  function noteDroppedRxFrame(reason, details = {}) {
    const key = String(reason || "unknown");
    const current = Number(state.audioStats.rxDropped[key] || 0);
    state.audioStats.rxDropped[key] = current + 1;
    audioDebug("rx-drop", {
      reason: key,
      dropped: state.audioStats.rxDropped[key],
      ...details,
    });
  }

  function audioDebugSnapshot() {
    const ws = state.ws;
    const player = state.player;
    const mic = state.mic;
    return {
      nowMs: performance.now(),
      visibilityState: document.visibilityState,
      hidden: !!document.hidden,
      hasFocus: document.hasFocus(),
      websocket: {
        readyState: ws ? ws.readyState : WebSocket.CLOSED,
        bufferedAmount: ws ? Number(ws.bufferedAmount || 0) : 0,
      },
      playback: player && typeof player.debugState === "function" ? player.debugState() : null,
      microphone: mic && mic.ctx ? {
        state: mic.ctx.state,
        currentTime: mic.ctx.currentTime,
      } : null,
      stats: {
        ...state.audioStats,
        activity: cloneAudioActivities(state.audioStats.activity),
        txDropReasons: { ...state.audioStats.txDropReasons },
        rxDropped: { ...state.audioStats.rxDropped },
      },
      serverPacketStats: state.serverPacketStats ? { ...state.serverPacketStats } : null,
    };
  }

  function cloneAudioActivities(activity) {
    const out = Object.create(null);
    Object.entries(activity || {}).forEach(([kind, value]) => {
      out[kind] = { ...value };
    });
    return out;
  }

  function installAudioDebugHook() {
    window.__incomudonAudioDebug = {
      snapshot: audioDebugSnapshot,
      setEnabled(enabled) {
        state.audioDebugEnabled = !!enabled;
        try {
          window.localStorage.setItem(audioDebugStorageKey, state.audioDebugEnabled ? "1" : "0");
        } catch (_) {
          // Debug mode still works for this page even if storage is unavailable.
        }
        audioDebug("debug-enabled", { enabled: state.audioDebugEnabled });
      },
    };
  }

  installAudioDebugHook();

  function createAudioStats() {
    return {
      activity: Object.create(null),
      txSent: 0,
      txDropped: 0,
      txDropReasons: Object.create(null),
      rxReceived: 0,
      rxDropped: Object.create(null),
      audioTxTicks: 0,
      audioTxSkipped: 0,
    };
  }

  function packetDebugReadyStateName(value) {
    switch (Number(value)) {
      case WebSocket.CONNECTING: return "CONNECTING";
      case WebSocket.OPEN: return "OPEN";
      case WebSocket.CLOSING: return "CLOSING";
      default: return "CLOSED";
    }
  }

  function packetDebugSnapshot() {
    const ws = state.ws;
    const player = state.player;
    const mic = state.mic;
    return {
      atMs: performance.now(),
      startedAtMs: Number(state.packetDebugStartedAtMs || performance.now()),
      visibilityState: document.visibilityState,
      hasFocus: document.hasFocus(),
      websocket: {
        readyState: ws ? ws.readyState : WebSocket.CLOSED,
        bufferedAmount: ws ? Number(ws.bufferedAmount || 0) : 0,
        reconnectAttempt: Number(state.reconnectAttempt || 0),
      },
      playback: player && typeof player.debugState === "function" ? player.debugState() : null,
      microphone: mic && mic.ctx ? {
        state: String(mic.ctx.state || "none"),
        sampleRate: Number(mic.ctx.sampleRate || 0),
        currentTime: Number(mic.ctx.currentTime || 0),
      } : null,
      audio: {
        txSent: Number(state.audioStats.txSent || 0),
        txDropped: Number(state.audioStats.txDropped || 0),
        txDropReasons: { ...state.audioStats.txDropReasons },
        rxReceived: Number(state.audioStats.rxReceived || 0),
        rxDropped: { ...state.audioStats.rxDropped },
        audioTxTicks: Number(state.audioStats.audioTxTicks || 0),
        audioTxSkipped: Number(state.audioStats.audioTxSkipped || 0),
        activity: cloneAudioActivities(state.audioStats.activity),
      },
      server: state.serverPacketStats && typeof state.serverPacketStats === "object"
        ? { ...state.serverPacketStats }
        : null,
    };
  }

  function packetDebugNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number : 0;
  }

  function packetDebugRate(current, previous, key, elapsedSec) {
    if (!previous || elapsedSec <= 0) return 0;
    return Math.max(0, (packetDebugNumber(current && current[key]) - packetDebugNumber(previous && previous[key])) / elapsedSec);
  }

  function packetDebugActivity(snapshot, previous, names) {
    const currentActivity = snapshot && snapshot.audio && snapshot.audio.activity ? snapshot.audio.activity : {};
    const previousActivity = previous && previous.audio && previous.audio.activity ? previous.audio.activity : {};
    const elapsedSec = previous ? Math.max(0.001, (snapshot.atMs - previous.atMs) / 1000) : 0;
    const nameList = Array.isArray(names) ? names : [names];
    let count = 0;
    let bytes = 0;
    let previousCount = 0;
    let previousBytes = 0;
    let lastGapMs = 0;
    let intervalSamples = 0;
    let intervalTotalMs = 0;
    let intervalMaxMs = 0;
    nameList.forEach((name) => {
      const item = currentActivity[name] || {};
      const previousItem = previousActivity[name] || {};
      count += packetDebugNumber(item.count);
      bytes += packetDebugNumber(item.bytes);
      previousCount += packetDebugNumber(previousItem.count);
      previousBytes += packetDebugNumber(previousItem.bytes);
      lastGapMs = Math.max(lastGapMs, packetDebugNumber(item.lastGapMs));
      intervalSamples += packetDebugNumber(item.intervalSamples);
      intervalTotalMs += packetDebugNumber(item.intervalTotalMs);
      intervalMaxMs = Math.max(intervalMaxMs, packetDebugNumber(item.intervalMaxMs));
    });
    return {
      count,
      bytes,
      rate: elapsedSec > 0 ? Math.max(0, (count - previousCount) / elapsedSec) : 0,
      bytesPerSec: elapsedSec > 0 ? Math.max(0, (bytes - previousBytes) / elapsedSec) : 0,
      lastGapMs,
      averageGapMs: intervalSamples > 0 ? intervalTotalMs / intervalSamples : 0,
      maxGapMs: intervalMaxMs,
    };
  }

  function formatPacketDebugRate(value, suffix = "fps") {
    return `${packetDebugNumber(value).toFixed(1)} ${suffix}`;
  }

  function formatPacketDebugBytes(value) {
    const bytes = packetDebugNumber(value);
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${Math.round(bytes)} B`;
  }

  function formatPacketDebugInterval(activity) {
    if (!activity || activity.count <= 1) return "-";
    return `last ${activity.lastGapMs.toFixed(1)} / avg ${activity.averageGapMs.toFixed(1)} / max ${activity.maxGapMs.toFixed(1)} ms`;
  }

  function formatPacketDebugBreakdown(values) {
    const entries = Object.entries(values || {})
      .map(([key, value]) => [String(key), packetDebugNumber(value)])
      .filter(([, value]) => value > 0)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return entries.length ? entries.map(([key, value]) => `${key}=${value}`).join(", ") : "-";
  }

  function formatPacketDebugTalkers(values) {
    const entries = Object.entries(values || {})
      .map(([sender, count]) => [Number(sender), packetDebugNumber(count)])
      .filter(([sender, count]) => Number.isFinite(sender) && sender > 0 && count > 0)
      .sort((a, b) => a[0] - b[0]);
    return entries.length ? entries.map(([sender, count]) => `${sender}:${count}`).join("  ") : "-";
  }

  function formatPacketDebugReport(snapshot, previous) {
    const elapsedSec = previous ? Math.max(0.001, (snapshot.atMs - previous.atMs) / 1000) : 0;
    const server = snapshot.server || {};
    const previousServer = previous && previous.server ? previous.server : null;
    const generatedMic = packetDebugActivity(snapshot, previous, "mic-generated");
    const generatedSharedMic = packetDebugActivity(snapshot, previous, "shared-mic-frame");
    const generatedFile = packetDebugActivity(snapshot, previous, "audio-file-tick");
    const sent = packetDebugActivity(snapshot, previous, "tx-send");
    const received = packetDebugActivity(snapshot, previous, ["rx-pcm", "rx-opus"]);
    const playback = snapshot.playback || {};
    const worklet = playback.worklet || {};
    const playerRate = packetDebugNumber(worklet.sourceSampleRate || playback.sourceSampleRate || 8000);
    const bufferedMs = playerRate > 0 ? (packetDebugNumber(worklet.bufferedSamples) * 1000) / playerRate : 0;
    const targetMs = packetDebugNumber(playback.jitterTargetMs);
    const maxMs = packetDebugNumber(playback.jitterMaxMs);
    const serverRxRate = packetDebugRate(server, previousServer, "relayRxDatagrams", elapsedSec);
    const serverTxRate = packetDebugRate(server, previousServer, "relayTxAudioPackets", elapsedSec);
    const serverOutRate = packetDebugRate(server, previousServer, "webSocketWrittenFrames", elapsedSec);
    const serverMixRate = packetDebugRate(server, previousServer, "downlinkMixedFrames", elapsedSec);
    const uptimeSec = Math.max(0, (snapshot.atMs - snapshot.startedAtMs) / 1000);
    const ws = snapshot.websocket || {};
    const mic = snapshot.microphone || {};

    return [
      `${t("packet_debug_ws")}: ${packetDebugReadyStateName(ws.readyState)} | uptime ${uptimeSec.toFixed(1)} s | buffered ${formatPacketDebugBytes(ws.bufferedAmount)} | reconnect ${packetDebugNumber(ws.reconnectAttempt)}`,
      `${t("packet_debug_page")}: ${snapshot.visibilityState} | focus ${snapshot.hasFocus ? "yes" : "no"}`,
      `${t("packet_debug_context")}: output=${playback.contextState || "none"}@${packetDebugNumber(playback.sampleRate || 0)}Hz/${playback.streamMode || "none"} | mic=${mic.state || "none"}@${packetDebugNumber(mic.sampleRate)}Hz`,
      `${t("packet_debug_tx_generated")}: mic ${formatPacketDebugRate(generatedMic.rate)} (${formatPacketDebugInterval(generatedMic)}) | shared ${formatPacketDebugRate(generatedSharedMic.rate)} | file ${formatPacketDebugRate(generatedFile.rate)} (${formatPacketDebugInterval(generatedFile)})`,
      `${t("packet_debug_tx_sent")}: ${formatPacketDebugRate(sent.rate)} | ${formatPacketDebugBytes(sent.bytesPerSec)}/s | interval ${formatPacketDebugInterval(sent)} | total ${snapshot.audio.txSent}`,
      `${t("packet_debug_tx_dropped")}: ${snapshot.audio.txDropped} | file skipped ${snapshot.audio.audioTxSkipped} | ${formatPacketDebugBreakdown(snapshot.audio.txDropReasons)}`,
      `${t("packet_debug_rx_received")}: ${formatPacketDebugRate(received.rate)} | ${formatPacketDebugBytes(received.bytesPerSec)}/s | interval ${formatPacketDebugInterval(received)} | total ${snapshot.audio.rxReceived}`,
      `${t("packet_debug_rx_dropped")}: ${formatPacketDebugBreakdown(snapshot.audio.rxDropped)}`,
      `${t("packet_debug_playback")}: buffer ${bufferedMs.toFixed(1)} / target ${targetMs.toFixed(1)} / max ${maxMs.toFixed(1)} ms | underrun ${packetDebugNumber(worklet.underrunEvents)} | discard ${packetDebugNumber(playback.droppedSamples)} samples`,
      `${t("packet_debug_server_ws")}: queue ${packetDebugNumber(server.webSocketQueueDepth)}/48 | written ${formatPacketDebugRate(serverOutRate)} | queued pcm=${packetDebugNumber(server.webSocketQueuedPcmFrames)} opus=${packetDebugNumber(server.webSocketQueuedOpusFrames)} | drop ${packetDebugNumber(server.webSocketDroppedFrames)} | errors ${packetDebugNumber(server.webSocketWriteErrors)}`,
      `${t("packet_debug_relay_rx")}: ${formatPacketDebugRate(serverRxRate, "pkt/s")} | audio ${packetDebugNumber(server.relayRxAudioPackets)} | fec ${packetDebugNumber(server.relayRxFecPackets)} | ${formatPacketDebugBytes(packetDebugRate(server, previousServer, "relayRxBytes", elapsedSec))}/s | invalid ${packetDebugNumber(server.relayRxInvalidPackets)} rejected ${packetDebugNumber(server.relayRxRejectedPackets)}`,
      `${t("packet_debug_relay_tx")}: audio ${formatPacketDebugRate(serverTxRate, "pkt/s")} | total ${packetDebugNumber(server.relayTxAudioPackets)} | fec ${packetDebugNumber(server.relayTxFecPackets)} | control ${packetDebugNumber(server.relayTxControlPackets)} | errors ${packetDebugNumber(server.relayTxErrors)}`,
      `${t("packet_debug_mix")}: ${formatPacketDebugRate(serverMixRate)} | decoded ${packetDebugNumber(server.downlinkDecodedFrames)} | inputs ${packetDebugNumber(server.downlinkMixedInputs)} | queue ${packetDebugNumber(server.downlinkQueuedFrames)} frames/${packetDebugNumber(server.downlinkQueuedSenders)} senders | queue drop ${packetDebugNumber(server.downlinkQueueDrops)} | self mute ${packetDebugNumber(server.downlinkSelfMutedFrames)} | unsupported ${packetDebugNumber(server.unsupportedFrames)}`,
      `${t("packet_debug_talkers")}: ${formatPacketDebugTalkers(server.relayRxAudioBySender)}`,
    ].join("\n");
  }

  function refreshPacketDebugView() {
    if (!state.packetDebugEnabled) {
      return;
    }
    const snapshot = packetDebugSnapshot();
    const output = formatPacketDebugReport(snapshot, state.packetDebugLastSnapshot);
    state.packetDebugLastSnapshot = snapshot;
    if (ui.packetDebugOutput) {
      ui.packetDebugOutput.textContent = output;
    }
    return snapshot;
  }

  function notifyEmbeddedPacketDebug(snapshot = null) {
    if (!isEmbeddedSlot || !state.packetDebugEnabled || !window.parent || window.parent === window) {
      return;
    }
    try {
      window.parent.postMessage({
        type: "incomudon-slot-packet-debug",
        slot: embeddedSlotIndex,
        snapshot: snapshot || packetDebugSnapshot(),
        text: ui.packetDebugOutput ? ui.packetDebugOutput.textContent : "",
      }, window.location.origin);
    } catch (_) {
      // Monitoring is optional and must not affect the audio path.
    }
  }

  function publishEmbeddedPacketDebug() {
    if (!state.packetDebugEnabled) {
      return;
    }
    const snapshot = refreshPacketDebugView();
    notifyEmbeddedPacketDebug(snapshot);
  }

  function resetPacketDebugCounters() {
    state.audioStats = createAudioStats();
    state.serverPacketStats = null;
    state.packetDebugLastSnapshot = null;
    state.packetDebugStartedAtMs = performance.now();
    if (state.player && typeof state.player.resetDebugStats === "function") {
      state.player.resetDebugStats();
    }
    if (state.connected) {
      sendCommand({ type: "reset_packet_debug" });
    }
    publishEmbeddedPacketDebug();
  }

  function startPacketDebugMonitor() {
    if (ui.packetDebugCard) {
      ui.packetDebugCard.hidden = !state.packetDebugEnabled;
    }
    if (!state.packetDebugEnabled) {
      return;
    }
    resetPacketDebugCounters();
    if (state.packetDebugTimer) {
      window.clearInterval(state.packetDebugTimer);
    }
    state.packetDebugTimer = window.setInterval(publishEmbeddedPacketDebug, 1000);
  }

  const senderIDMin = 1;
  const senderIDMax = 0x7fffffff;
  const portableSettingsKeys = [
    "relayHost", "relayPort", "channelId", "senderId", "passwordHash",
    "cryptoMode", "codecMode", "browserCodec", "wsToken", "txCodec",
    "micVolumePercent", "qosEnabled", "fecEnabled", "codec2Lib", "opusLib",
    "pcmOnly", "cuePttOnEnabled", "cuePttOffEnabled", "cueCarrierEnabled",
    "cuePttOnUrl", "cuePttOffUrl", "cueCarrierUrl", "audioTxSlotCount",
    "receiveOnly", "selfSenderMute", "audioTxLoopEnabled",
  ];
  state.settingsUnlocked = isSettingsUnlockSessionValid(state.settingsLockConfig);

  applyInitialFormSettings();
  applySettingsLockState();
  bindSettingsLockControls();
  bindSettingsLockStorageSync();
  bindFormPersistence();
  bindCueControls();
  bindAudioTxControls();
  refreshCueFileStatuses();
  refreshAudioTxSlotsUI();
  state.mediaFilesReadyPromise = restorePersistedMediaFiles();
  configureAuthUI();
  initI18n()
    .catch(() => {})
    .finally(() => {
      startPacketDebugMonitor();
      maybeAutoConnectOnStartup().catch(() => {});
    });

  function sendPcmFrame(frame) {
    enqueueUplinkPacket(0x01, frame);
  }

  function sendOpusFrame(frame, txSessionId) {
    enqueueUplinkPacket(0x02, frame, txSessionId);
  }

  function normalizePasswordHashToken(value) {
    const text = String(value || "").trim();
    if (!text) {
      return "";
    }
    if (text.startsWith(passwordHashPrefix)) {
      const hex = text.slice(passwordHashPrefix.length).trim().toLowerCase();
      if (sha256HexPattern.test(hex)) {
        return `${passwordHashPrefix}${hex}`;
      }
      return "";
    }
    if (sha256HexPattern.test(text)) {
      return `${passwordHashPrefix}${text.toLowerCase()}`;
    }
    return "";
  }

  function hasPasswordHashToken() {
    return !!normalizePasswordHashToken(state.passwordHash);
  }

  function applyPasswordInputPresentation() {
    if (!ui.password) {
      return;
    }
    if (ui.password.value) {
      ui.password.placeholder = "";
      return;
    }
    ui.password.placeholder = t("password_unchanged");
  }

  async function sha256Hex(text) {
    if (!window.crypto || !window.crypto.subtle || typeof window.crypto.subtle.digest !== "function") {
      throw new Error("Web Crypto API is unavailable");
    }
    const enc = new TextEncoder();
    const bytes = enc.encode(String(text));
    const digest = await window.crypto.subtle.digest("SHA-256", bytes);
    const hashBytes = new Uint8Array(digest);
    let hex = "";
    for (let i = 0; i < hashBytes.length; i += 1) {
      hex += hashBytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  async function resolvePasswordTokenForConnect() {
    if (!ui.password) {
      return normalizePasswordHashToken(state.passwordHash);
    }
    const raw = ui.password.value || "";
    if (!raw) {
      state.passwordHash = normalizePasswordHashToken(state.passwordHash);
      if (!state.passwordHash) {
        const legacyPlain = String(state.startupLegacyPlainPassword || "");
        if (legacyPlain) {
          const hashHex = await sha256Hex(legacyPlain);
          state.passwordHash = `${passwordHashPrefix}${hashHex}`;
          state.startupLegacyPlainPassword = "";
          applyPasswordInputPresentation();
          persistFormSettings();
        }
      }
      applyPasswordInputPresentation();
      return state.passwordHash;
    }

    const normalized = normalizePasswordHashToken(raw);
    let token = normalized;
    if (!token) {
      const hashHex = await sha256Hex(raw);
      token = `${passwordHashPrefix}${hashHex}`;
    }
    state.passwordHash = token;
    ui.password.value = "";
    applyPasswordInputPresentation();
    persistFormSettings();
    return token;
  }

  function normalizeMicVolumePercent(rawValue) {
    const parsed = Number.parseInt(String(rawValue ?? ""), 10);
    if (!Number.isFinite(parsed)) {
      return micVolumeDefaultPercent;
    }
    return Math.max(micVolumeMinPercent, Math.min(micVolumeMaxPercent, parsed));
  }

  function snapMicVolumePercent(value) {
    const normalized = normalizeMicVolumePercent(value);
    if (Math.abs(normalized - micVolumeSnapPercent) <= micVolumeSnapThreshold) {
      return micVolumeSnapPercent;
    }
    return normalized;
  }

  function updateMicVolumeDisplay() {
    if (!ui.micVolumeValue) {
      return;
    }
    ui.micVolumeValue.textContent = `${state.micVolumePercent}%`;
  }

  function applyMicVolumeFromUI(rawValue, persist = true) {
    const snapped = snapMicVolumePercent(rawValue);
    state.micVolumePercent = snapped;
    if (ui.micVolume) {
      ui.micVolume.value = String(snapped);
    }
    if (state.mic && typeof state.mic.setGainPercent === "function") {
      state.mic.setGainPercent(snapped);
    }
    updateMicVolumeDisplay();
    if (persist) {
      persistFormSettings();
    }
    notifyEmbeddedSlotState();
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

  function transmitUplinkFrame(frame, source = "unknown") {
    if (!frame || frame.length < 2 || !state.connected || !state.pttPressed) {
      return;
    }
    const shaped = shapeTxFrame(frame);
    if (state.uplinkCodec === "opus" && state.opusEncoder) {
      if (state.opusEncoder.isBackpressured()) {
        noteDroppedTxFrame("opus-encoder-backpressure", {
          source,
          queueSize: state.opusEncoder.queueSize(),
        });
        return;
      }
      if (!state.opusEncoder.encodeFrame(shaped, state.txSessionId)) {
        noteDroppedTxFrame("opus-encode-failed", { source });
      }
      return;
    }
    sendPcmFrame(shaped);
  }

  function enqueueUplinkPacket(type, frame, txSessionId = null) {
    if (type === 0x02 && txSessionId !== null && txSessionId !== state.txSessionId) {
      noteDroppedTxFrame("stale-opus-output", { txSessionId, activeSessionId: state.txSessionId });
      return;
    }
    const ws = state.ws;
    if (!state.connected || !state.pttPressed || !ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }
    if (!frame || frame.length === 0) {
      return;
    }
    const bufferedAmount = Number(ws.bufferedAmount || 0);
    if (bufferedAmount >= txWebSocketHighWaterBytes) {
      // Do not keep speech that cannot be delivered in real time. The next
      // AudioWorklet frame represents newer audio and is more useful.
      noteDroppedTxFrame("websocket-backpressure", { bufferedAmount });
      return;
    }

    const packet = new Uint8Array(1 + frame.length);
    packet[0] = type;
    packet.set(frame, 1);
    try {
      ws.send(packet);
      state.audioStats.txSent += 1;
      recordAudioActivity("tx-send", {
        type,
        bytes: packet.byteLength,
        bufferedAmount: Number(ws.bufferedAmount || 0),
      });
    } catch (err) {
      noteDroppedTxFrame("websocket-send-failed", {
        error: err && err.message ? err.message : String(err),
      });
    }
  }

  function beginTxSession() {
    state.txSessionId += 1;
    if (state.txSessionId > Number.MAX_SAFE_INTEGER - 1) {
      state.txSessionId = 1;
    }
    return state.txSessionId;
  }

  function invalidateTxSession() {
    return beginTxSession();
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
    releaseKeyboardFocus();
    clearPendingSettingsReconnect();
    persistFormSettings();
    connectRelay().catch((err) => {
      appendLog(t("log_connect_failed", { error: err.message || err }), "error");
      applyDisconnectedState();
    });
  });

  ui.disconnectBtn.addEventListener("click", () => {
    releaseKeyboardFocus();
    clearPendingSettingsReconnect();
    disconnectRelay();
  });

  ui.clearLogBtn.addEventListener("click", () => {
    releaseKeyboardFocus();
    ui.logBox.textContent = "";
  });
  ui.packetDebugReset?.addEventListener("click", () => {
    releaseKeyboardFocus();
    resetPacketDebugCounters();
  });

  bindPTT(ui.pttButton);
  installKeyboardFocusRelease();

  function isKeyboardEditableTarget(element) {
    return !!(element && typeof element.closest === "function" &&
      element.closest("input, textarea, select, [contenteditable='true']"));
  }

  function releaseKeyboardFocus() {
    const active = document.activeElement;
    if (isKeyboardEditableTarget(active) && typeof active.blur === "function") {
      active.blur();
    }
    if (ui.main && document.activeElement !== ui.main && typeof ui.main.focus === "function") {
      ui.main.focus({ preventScroll: true });
    }
  }

  function installKeyboardFocusRelease() {
    document.addEventListener("change", (event) => {
      if (isKeyboardEditableTarget(event.target)) {
        window.requestAnimationFrame(releaseKeyboardFocus);
      }
    }, true);
    document.addEventListener("keydown", (event) => {
      if ((event.code === "Enter" || event.code === "Escape") && isKeyboardEditableTarget(event.target)) {
        window.requestAnimationFrame(releaseKeyboardFocus);
      }
    }, true);
    document.addEventListener("pointerdown", (event) => {
      if (!isKeyboardEditableTarget(document.activeElement) || !event.target || typeof event.target.closest !== "function") {
        return;
      }
      if (event.target.closest("input, textarea, select, label, button, a, [contenteditable='true']")) {
        return;
      }
      window.requestAnimationFrame(releaseKeyboardFocus);
    }, true);
  }

  window.addEventListener("keydown", (event) => {
    if (isEmbeddedSlot) {
      if (!event.repeat) {
        forwardEmbeddedKeyboardEvent("down", event);
      }
      return;
    }
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
    if (isEmbeddedSlot) {
      forwardEmbeddedKeyboardEvent("up", event);
      return;
    }
    if (event.code !== "Space") {
      return;
    }
    event.preventDefault();
    setPTT(false);
  });

  function logAudioLifecycle(event) {
    audioDebug("lifecycle", {
      event,
      audioContextState: state.player && state.player.ctx ? state.player.ctx.state : "none",
      audioContextTime: state.player && state.player.ctx ? state.player.ctx.currentTime : 0,
    });
  }

  document.addEventListener("visibilitychange", () => {
    logAudioLifecycle("visibilitychange");
    // This is only a best-effort recovery for a browser-suspended context. Do
    // not stop an active transmission or blindly resume while hidden.
    if (!document.hidden && state.player) {
      state.player.resumeIfNeeded();
    }
    if (!document.hidden) {
      resumeUnexpectedConnectionOnForeground();
    }
  });
  window.addEventListener("blur", () => logAudioLifecycle("window-blur"));
  window.addEventListener("focus", () => {
    logAudioLifecycle("window-focus");
    if (state.player) {
      state.player.resumeIfNeeded();
    }
  });
  window.addEventListener("pagehide", () => logAudioLifecycle("pagehide"));
  window.addEventListener("pageshow", () => {
    logAudioLifecycle("pageshow");
    if (state.player) {
      state.player.resumeIfNeeded();
    }
  });

  function embeddedSlotSnapshot() {
    return {
      connected: !!state.connected,
      channelId: Number(ui.channelId ? ui.channelId.value : 0) || 0,
      senderId: Number(ui.senderId ? ui.senderId.value : 0) || 0,
      selfSenderId: Number(state.selfSenderId || 0),
      activeTalkers: Array.isArray(state.activeTalkers) ? state.activeTalkers.slice() : [],
      channelName: directoryChannelName(Number(ui.channelId ? ui.channelId.value : 0) || 0),
      channelLabel: formatDirectoryChannelLabel(Number(ui.channelId ? ui.channelId.value : 0) || 0),
      senderLabel: formatDirectorySpeakerLabel(
        Number(ui.channelId ? ui.channelId.value : 0) || 0,
        Number(ui.senderId ? ui.senderId.value : 0) || 0,
      ),
      talkerLabels: (Array.isArray(state.activeTalkers) ? state.activeTalkers : []).reduce((labels, talkerId) => {
        labels[String(talkerId)] = formatDirectorySpeakerLabel(
          Number(ui.channelId ? ui.channelId.value : 0) || 0,
          Number(talkerId) || 0,
        );
        return labels;
      }, Object.create(null)),
      talkAllowed: !!state.talkAllowed,
      pttPressed: !!state.pttPressed,
      receiveOnly: !!state.receiveOnly,
      receiveMuted: !!state.receiveMuted,
      selfSenderMute: !!state.selfSenderMute,
      micVolume: Number(state.micVolumePercent || micVolumeDefaultPercent),
      connectionKind: String((state.connectionView && state.connectionView.kind) || "offline"),
      reconnectAttempt: Number(state.reconnectAttempt || 0),
    };
  }

  function notifyEmbeddedSlotState() {
    if (!isEmbeddedSlot || !window.parent || window.parent === window) {
      return;
    }
    try {
      window.parent.postMessage({
        type: "incomudon-slot-state",
        slot: embeddedSlotIndex,
        state: embeddedSlotSnapshot(),
      }, window.location.origin);
    } catch (_) {
      // The multi-channel page is optional; keep standalone operation unaffected.
    }
  }

  function notifyEmbeddedSlotInteraction() {
    if (!isEmbeddedSlot || !window.parent || window.parent === window) {
      return;
    }
    try {
      window.parent.postMessage({
        type: "incomudon-slot-interaction",
        slot: embeddedSlotIndex,
      }, window.location.origin);
    } catch (_) {
      // The multi-channel page is optional; keep standalone operation unaffected.
    }
  }

  function notifyEmbeddedLog(text, level) {
    if (!isEmbeddedSlot || !text || !window.parent || window.parent === window) {
      return;
    }
    try {
      window.parent.postMessage({
        type: "incomudon-slot-log",
        slot: embeddedSlotIndex,
        text: String(text),
        level: normalizeLevel(level),
      }, window.location.origin);
    } catch (_) {
      // The multi-channel page is optional; keep standalone operation unaffected.
    }
  }

  function embeddedKeyboardEditableTarget() {
    const active = document.activeElement;
    if (!active) {
      return false;
    }
    const tag = String(active.tagName || "").toUpperCase();
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || active.isContentEditable;
  }

  function forwardEmbeddedKeyboardEvent(phase, event) {
    if (!isEmbeddedSlot || !window.parent || window.parent === window) {
      return;
    }
    const editable = embeddedKeyboardEditableTarget();
    if (!editable && event.code !== "Tab") {
      event.preventDefault();
    }
    try {
      window.parent.postMessage({
        type: "incomudon-slot-key",
        slot: embeddedSlotIndex,
        phase,
        code: event.code,
        ctrlKey: !!event.ctrlKey,
        altKey: !!event.altKey,
        shiftKey: !!event.shiftKey,
        metaKey: !!event.metaKey,
        editable,
      }, window.location.origin);
    } catch (_) {
      // Ignore parent messaging errors.
    }
  }

  function externalFrameFromMessage(frame) {
    if (frame instanceof ArrayBuffer) {
      return new Uint8Array(frame);
    }
    if (ArrayBuffer.isView(frame)) {
      return new Uint8Array(frame.buffer, frame.byteOffset, frame.byteLength);
    }
    return null;
  }

  function handleEmbeddedSlotMessage(event) {
    if (!isEmbeddedSlot || event.origin !== window.location.origin || !event.data || typeof event.data !== "object") {
      return;
    }
    const data = event.data;
    if (Number(data.slot) !== embeddedSlotIndex) {
      return;
    }
    if (data.type === "incomudon-slot-packet-debug-request") {
      // The parent sends this after the iframe load event. It closes the race
      // where this slot published its first snapshot before the parent had
      // registered its message listener, without affecting audio processing.
      publishEmbeddedPacketDebug();
      return;
    }
    if (data.type === "incomudon-slot-settings-lock") {
      state.settingsLockConfig = loadSettingsLockConfig();
      if (isSettingsLockEnabled()) {
        state.settingsUnlocked = data.unlocked === true;
        if (state.settingsUnlocked) {
          persistSettingsUnlockSession();
        } else {
          clearSettingsUnlockSession();
        }
      } else {
        state.settingsUnlocked = false;
      }
      applySettingsLockState();
      return;
    }
    if (data.type === "incomudon-slot-command") {
      switch (data.command) {
        case "request-state":
          notifyEmbeddedSlotState();
          break;
        case "set_receive_muted":
          state.receiveMuted = !!data.muted;
          if (state.player) {
            state.player.setMuted(state.receiveMuted);
          }
          notifyEmbeddedSlotState();
          break;
        case "connect":
          connectRelay().catch((err) => {
            appendLog(t("log_connect_failed", { error: err && err.message ? err.message : String(err) }), "error");
            applyDisconnectedState();
          });
          break;
        case "disconnect":
          disconnectRelay();
          break;
        case "ptt":
          setPTT(!!data.pressed, true, true);
          break;
        default:
          break;
      }
      return;
    }
    if (data.type === "incomudon-slot-audio") {
      const frame = externalFrameFromMessage(data.frame);
      if (!frame || !state.connected || !state.pttPressed || !state.ws || state.ws.readyState !== WebSocket.OPEN || state.audioTxTask) {
        return;
      }
      recordAudioActivity("shared-mic-frame", { bytes: frame.byteLength });
      transmitUplinkFrame(frame, "shared-mic");
    }
  }

  function wsURL() {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const path = basePath ? `${basePath}/ws` : "/ws";
    const url = new URL(`${proto}://${window.location.host}${path}`);
    const wsToken = currentWSToken();
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

  async function fetchAuthSessionStatus() {
    if (!supportsAuthLogout()) {
      return { status: 204, remainingSec: null };
    }
    try {
      const response = await fetch(authCheckURL(), {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
      });
      const remainingRaw = response.headers.get(authRemainingHeader);
      let remainingSec = null;
      if (remainingRaw !== null && remainingRaw !== "") {
        const parsed = Number.parseInt(remainingRaw, 10);
        if (Number.isFinite(parsed) && parsed >= 0) {
          remainingSec = parsed;
        }
      }
      return {
        status: Number(response.status || 0),
        remainingSec,
      };
    } catch (_) {
      return { status: 0, remainingSec: null };
    }
  }

  function currentAuthSessionMessage() {
    if (authMode === "basic") {
      return t("log_basic_auth_required");
    }
    return t("log_auth_session_required");
  }

  function notifyAuthSessionExpired() {
    const message = currentAuthSessionMessage();
    const now = Date.now();
    if (now - Number(state.lastAuthSessionNoticeMs || 0) < 1500) {
      return message;
    }
    state.lastAuthSessionNoticeMs = now;
    appendLog(message, "warn");
    try {
      console.warn(`[IncomUdon] ${message}`);
    } catch (_) {
      // Ignore console access errors.
    }
    return message;
  }

  function closeSessionForAuthExpiry() {
    const ws = state.ws;
    if (ws) {
      ws.onclose = null;
      ws.onmessage = null;
      ws.onerror = null;
      try {
        ws.close();
      } catch (_) {
        // Ignore websocket close failures.
      }
    }
    applyDisconnectedState();
  }

  function formatRemainingAuthDuration(totalSec) {
    const safe = Math.max(0, Number.parseInt(String(totalSec || 0), 10) || 0);
    const days = Math.floor(safe / 86400);
    const hours = Math.floor((safe % 86400) / 3600);
    const minutes = Math.floor((safe % 3600) / 60);
    const seconds = safe % 60;
    const parts = [];
    if (days > 0) {
      parts.push(`${days}d`);
    }
    if (days > 0 || hours > 0) {
      parts.push(`${hours}h`);
    }
    if (days > 0 || hours > 0 || minutes > 0) {
      parts.push(`${minutes}m`);
    }
    parts.push(`${seconds}s`);
    return parts.join(" ");
  }

  function logAuthSessionRemaining(remainingSec, phase) {
    if (!Number.isFinite(remainingSec) || remainingSec < 0 || authMode !== "oidc") {
      return;
    }
    if (phase !== "connect" && phase !== "ptt") {
      return;
    }
    const remaining = formatRemainingAuthDuration(remainingSec);
    const key = phase === "ptt"
      ? "log_auth_session_remaining_ptt"
      : "log_auth_session_remaining_connect";
    appendLog(t(key, { remaining }), "info");
  }

  async function ensureAuthSessionBeforeConnect() {
    if (!supportsAuthLogout()) {
      return true;
    }
    const authStatus = await fetchAuthSessionStatus();
    if (authStatus.status === 204 || authStatus.status === 200 || authStatus.status === 0) {
      logAuthSessionRemaining(authStatus.remainingSec, "connect");
      return true;
    }
    if (authStatus.status === 401) {
      notifyAuthSessionExpired();
      if (authMode === "oidc") {
        window.location.href = oidcLoginURL();
      }
      return false;
    }
    return true;
  }

  async function ensureAuthSessionBeforeTransmit(phase) {
    if (!supportsAuthLogout()) {
      return true;
    }
    const authStatus = await fetchAuthSessionStatus();
    if (authStatus.status === 204 || authStatus.status === 200 || authStatus.status === 0) {
      logAuthSessionRemaining(authStatus.remainingSec, phase);
      return true;
    }
    if (authStatus.status === 401) {
      notifyAuthSessionExpired();
      closeSessionForAuthExpiry();
      return false;
    }
    return true;
  }

  async function checkAuthSessionAfterUnexpectedClose() {
    if (!supportsAuthLogout()) {
      return;
    }
    const authStatus = await fetchAuthSessionStatus();
    if (authStatus.status === 401) {
      notifyAuthSessionExpired();
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

  async function connectRelay(options = {}) {
    const reconnecting = options && options.reconnect === true;
    if (!reconnecting) {
      clearReconnectTimer();
      state.reconnectAttempt = 0;
      state.disconnectRequested = false;
    }
    if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }
    if (!(await ensureAuthSessionBeforeConnect())) {
      return;
    }
    if (wsTokenRequired && !currentWSToken()) {
      appendLog(t("log_ws_auth_required"), "error");
      setConnectionView({ kind: "error", level: "error" });
      return;
    }

    const ws = new WebSocket(wsURL());
    ws.binaryType = "arraybuffer";
    state.ws = ws;

    setConnectionView({ kind: reconnecting ? "reconnecting" : "connecting", level: "warn" });

    ws.onopen = async () => {
      audioDebug("websocket-open");
      clearReconnectTimer();
      state.reconnectAttempt = 0;
      state.disconnectRequested = false;
      appendLog(t("log_ws_opened"), "info");
      state.micPermissionDenied = false;
      const safeSenderID = canonicalizeSenderIDField();
      const selectedTxCodec = sanitizeSelectedTxCodec();
      const selectedCodecMode = normalizeBitrateForTxCodec(ui.codecMode ? ui.codecMode.value : 0, selectedTxCodec);
      if (ui.codecMode) {
        ui.codecMode.value = String(selectedCodecMode);
      }
      const browserOpusUplinkBitrate = resolveBrowserUplinkOpusBitrate(selectedTxCodec, selectedCodecMode);
      let passwordToken = "";
      try {
        passwordToken = await resolvePasswordTokenForConnect();
      } catch (err) {
        appendLog(t("log_password_hash_failed", { error: err && err.message ? err.message : String(err) }), "error");
        ws.close();
        return;
      }

      state.browserCodec = normalizeBrowserCodec(ui.browserCodec.value);
      state.uplinkCodec = state.browserCodec;
      state.downlinkCodec = state.browserCodec;
      state.downlinkOpusWarned = false;

      if (state.browserCodec === "opus") {
        let opusReady = true;
        let fallbackReason = "";

        try {
          state.opusEncoder = new OpusUplinkEncoder(sendOpusFrame, browserOpusUplinkBitrate);
          await state.opusEncoder.start();
        } catch (err) {
          opusReady = false;
          fallbackReason = err && err.message ? err.message : String(err);
          state.opusEncoder = null;
        }

        if (opusReady) {
          try {
            state.opusDecoder = new OpusDownlinkDecoder((frame) => {
              if (state.receiveMuted) {
                noteDroppedRxFrame("local-receive-mute", { bytes: frame && frame.bytes ? frame.bytes.byteLength : 0 });
              } else if (state.player) {
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
          const effectiveUplinkBitrate = state.opusEncoder
            ? state.opusEncoder.getConfiguredBitrate()
            : browserOpusUplinkBitrate;
          if (state.uplinkCodec === "opus" && selectedTxCodec === txCodecOpus) {
            if (effectiveUplinkBitrate !== browserOpusUplinkBitrate) {
              appendLog(t("log_browser_opus_uplink_bitrate_fallback", {
                requestedKbps: formatBitrateKbps(browserOpusUplinkBitrate),
                effectiveKbps: formatBitrateKbps(effectiveUplinkBitrate),
              }), "warn");
            } else {
              appendLog(t("log_browser_opus_uplink_bitrate", {
                bitrateKbps: formatBitrateKbps(effectiveUplinkBitrate),
              }), "info");
            }
          }
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

      persistFormSettings();

      sendCommand({
        type: "connect",
        relayHost: fixedRelayEnabled ? effectiveFixedRelayHost() : currentRelayHost(),
        relayPort: fixedRelayEnabled ? effectiveFixedRelayPort() : currentRelayPort(),
        channelId: Number(ui.channelId.value),
        senderId: safeSenderID,
        password: passwordToken,
        cryptoMode: ui.cryptoMode.value,
        codecMode: selectedCodecMode,
        txCodec: selectedTxCodec,
        selfMute: !!state.selfSenderMute,
        packetDebug: !!state.packetDebugEnabled,
        qosEnabled: ui.qosEnabled ? !!ui.qosEnabled.checked : true,
        fecEnabled: ui.fecEnabled ? !!ui.fecEnabled.checked : true,
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
      audioDebug("websocket-close", {
        code: event ? Number(event.code || 0) : 0,
        reason: event ? String(event.reason || "") : "",
      });
      const unexpected = !state.disconnectRequested;
      if (wsTokenRequired && !currentWSToken()) {
        appendLog(t("log_ws_auth_required"), "error");
      }
      if (event && Number(event.code) === 1006 && supportsAuthLogout()) {
        void checkAuthSessionAfterUnexpectedClose();
      }
      if (event && Number(event.code) && Number(event.code) !== 1000) {
        appendLog(`${t("log_ws_closed")} (code=${event.code})`, "warn");
      } else {
        appendLog(t("log_ws_closed"), "warn");
      }
      const willRetry = unexpected && state.reconnectAttempt < state.reconnectMaxAttempts;
      applyDisconnectedState({
        connectionKind: willRetry ? "reconnecting" : (unexpected ? "unexpected-disconnected" : "offline"),
        keepReconnect: willRetry,
      });
      if (willRetry) scheduleUnexpectedReconnect();
    };

    ws.onerror = () => {
      audioDebug("websocket-error");
      appendLog(t("log_ws_error"), "error");
    };
  }

  function disconnectRelay() {
    state.disconnectRequested = true;
    clearReconnectTimer();
    state.reconnectAttempt = 0;
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
      state.audioStats.rxReceived += 1;
      recordAudioActivity("rx-pcm", { bytes: bytes.byteLength - 1 });
      if (state.receiveMuted) {
        noteDroppedRxFrame("local-receive-mute", { bytes: bytes.byteLength - 1 });
      } else {
        state.player.playPCM(bytes.subarray(1), 8000);
      }
      return;
    }

    if (msgType === 0x12) {
      state.audioStats.rxReceived += 1;
      recordAudioActivity("rx-opus", { bytes: bytes.byteLength - 1 });
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

    if (event.type === "directory") {
      applyDirectoryProvisioning(event.directory);
      return;
    }

    if (event.type === "packet_debug") {
      state.serverPacketStats = event.packetStats && typeof event.packetStats === "object"
        ? event.packetStats
        : null;
      return;
    }

    if (event.type === "connected") {
      state.connected = true;
      state.selfSenderId = Number(event.senderId || 0);
      state.activeTalkers = [];
      state.talkerId = 0;
      state.talkAllowed = false;
      state.serverTalkTimeoutSec = 0;
      state.serverMultiTalkEnabled = false;
      state.serverMaxActiveTalkers = 1;
      stopTxTimeoutCountdown();
      clearExpectedLocalTalkRelease();
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
      if (typeof event.qosEnabled === "boolean" && ui.qosEnabled) {
        ui.qosEnabled.checked = event.qosEnabled;
      }
      if (typeof event.fecEnabled === "boolean" && ui.fecEnabled) {
        ui.fecEnabled.checked = event.fecEnabled;
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
      notifyEmbeddedSlotState();
      appendLog(t("log_connected_summary", {
        channel: formatDirectoryChannelLabel(Number(event.channelId || ui.channelId.value) || 0),
        sender: formatDirectorySpeakerLabel(Number(event.channelId || ui.channelId.value) || 0, Number(event.senderId) || 0),
        mode: event.cryptoMode,
        codec: effectiveBrowserCodec,
      }), "info");
      return;
    }

    if (event.type === "server_config") {
      const nextTimeout = Math.max(0, Number(event.talkTimeoutSec || 0));
      state.serverTalkTimeoutSec = Number.isFinite(nextTimeout) ? nextTimeout : 0;
      state.serverMultiTalkEnabled = !!event.multiTalkEnabled;
      state.serverMaxActiveTalkers = Math.max(1, Number(event.maxActiveTalkers || 1));
      syncTxTimeoutCountdownState();
      return;
    }

    if (event.type === "disconnected") {
      const ws = state.ws;
      appendLog(event.message || t("log_disconnected"), "warn");
      applyDisconnectedState();
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
      return;
    }

    if (event.type === "talker") {
      const prevTalkers = Array.isArray(state.activeTalkers) ? state.activeTalkers.slice() : [];
      const nextTalkers = Array.isArray(event.activeTalkers)
        ? event.activeTalkers
            .map((value) => Number(value || 0))
            .filter((value) => Number.isFinite(value) && value > 0)
        : [];
      const localTalkReleased =
        prevTalkers.includes(state.selfSenderId) &&
        !nextTalkers.includes(state.selfSenderId);
      const expectedLocalTalkRelease = localTalkReleased && consumeExpectedLocalTalkRelease();
      if (nextTalkers.includes(state.selfSenderId)) {
        clearExpectedLocalTalkRelease();
      }
      const localTalkTimedOut = localTalkReleased && !expectedLocalTalkRelease && state.pttPressed;
      const remoteTalkEnded =
        prevTalkers.some((talkerId) => talkerId !== state.selfSenderId) &&
        !nextTalkers.some((talkerId) => talkerId !== state.selfSenderId);
      const channelId = Math.max(0, Number(event.channelId || ui.channelId.value) || 0);
      const channel = formatDirectoryChannelLabel(channelId);
      nextTalkers
        .filter((talkerId) => !prevTalkers.includes(talkerId))
        .forEach((talkerId) => {
          appendLog(t("log_talker_started", {
            channel,
            talker: formatDirectorySpeakerLabel(channelId, talkerId),
          }), "info");
        });
      prevTalkers
        .filter((talkerId) => !nextTalkers.includes(talkerId))
        .forEach((talkerId) => {
          appendLog(t("log_talker_ended", {
            channel,
            talker: formatDirectorySpeakerLabel(channelId, talkerId),
          }), "info");
        });

      updateTalkerStatus(nextTalkers, event.talkAllowed);

      if (localTalkTimedOut) {
        handleLocalTxTimeout();
        return;
      }

      if (remoteTalkEnded) {
        playCue("pttOff");
      }

      if (state.pttPressed && !event.talkAllowed &&
          nextTalkers.some((talkerId) => talkerId !== state.selfSenderId)) {
        playCue("carrier");
      }
      return;
    }

    if (event.type === "peer_codec") {
      appendLog(t("log_peer_codec", {
        sender: formatDirectorySpeakerLabel(
          Number(event.channelId || ui.channelId.value) || 0,
          Number(event.senderId) || 0,
        ),
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

  function clearReconnectTimer() {
    if (!state.reconnectTimer) return;
    window.clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }

  function scheduleUnexpectedReconnect() {
    clearReconnectTimer();
    state.reconnectAttempt += 1;
    const attempt = state.reconnectAttempt;
    setConnectionView({ kind: "reconnecting", level: "error" });
    appendLog(t("log_ws_reconnect_attempt", { attempt, max: state.reconnectMaxAttempts }), "warn");
    state.reconnectTimer = window.setTimeout(() => {
      state.reconnectTimer = null;
      if (state.disconnectRequested || state.connected) return;
      connectRelay({ reconnect: true }).catch((err) => {
        appendLog(t("log_connect_failed", { error: err && err.message ? err.message : String(err) }), "error");
        const retry = state.reconnectAttempt < state.reconnectMaxAttempts;
        applyDisconnectedState({
          connectionKind: retry ? "reconnecting" : "unexpected-disconnected",
          keepReconnect: retry,
        });
        if (retry) scheduleUnexpectedReconnect();
      });
    }, 900 * attempt);
  }

  function resumeUnexpectedConnectionOnForeground() {
    if (state.disconnectRequested || state.connected || document.hidden) {
      return;
    }
    const kind = String((state.connectionView && state.connectionView.kind) || "");
    if (kind !== "reconnecting" && kind !== "unexpected-disconnected") {
      return;
    }
    // Android may freeze the page long enough for all scheduled retries to
    // expire while it is backgrounded. Restart the bounded retry sequence when
    // the user returns, instead of leaving the UI disconnected indefinitely.
    clearReconnectTimer();
    state.reconnectAttempt = 0;
    scheduleUnexpectedReconnect();
  }

  function applyDisconnectedState(options = {}) {
    clearPendingSettingsReconnect();
    if (!options.keepReconnect) clearReconnectTimer();
    state.connected = false;
    state.serverTalkTimeoutSec = 0;
    state.serverMultiTalkEnabled = false;
    state.serverMaxActiveTalkers = 1;
    stopTxTimeoutCountdown();
    clearExpectedLocalTalkRelease();
    cancelAudioTxTask(false);
    setPTT(false, false);
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
    updateTalkerStatus([], false);
    setConnectionView({ kind: options.connectionKind || "offline", level: options.connectionKind === "reconnecting" || options.connectionKind === "unexpected-disconnected" ? "error" : "warn" });
    notifyEmbeddedSlotState();
  }

  function applyInitialFormSettings() {
    const defaults = {
      relayHost: defaultRelayHost(),
      relayPort: "50000",
      channelId: "1",
      senderId: String(randomSenderID()),
      passwordHash: "",
      cryptoMode: "aes-gcm-v2",
      codecMode: initialOpusReady ? String(defaultOpusBitrate) : "1600",
      browserCodec: "opus",
      txCodec: initialOpusReady ? txCodecOpus : txCodecPCM,
      wsToken: initialWSToken,
      micVolumePercent: String(micVolumeDefaultPercent),
      receiveOnly: false,
      selfSenderMute: true,
      qosEnabled: true,
      fecEnabled: true,
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
      audioTxLoopEnabled: false,
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
    applyStartupQueryOverrides(merged);

    if (!merged.relayHost || !String(merged.relayHost).trim()) {
      merged.relayHost = defaults.relayHost;
    }
    state.startupLegacyPlainPassword = "";
    merged.passwordHash = normalizePasswordHashToken(merged.passwordHash || merged.password);
    if (!merged.passwordHash && typeof merged.password === "string" && merged.password.length > 0) {
      state.startupLegacyPlainPassword = merged.password;
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
    if (!merged.micVolumePercent) {
      merged.micVolumePercent = defaults.micVolumePercent;
    }
    if (fixedRelayEnabled) {
      merged.relayHost = defaults.relayHost;
      merged.relayPort = defaults.relayPort;
    }

    ui.relayHost.value = String(merged.relayHost);
    ui.relayPort.value = String(merged.relayPort);
    ui.channelId.value = String(merged.channelId);
    ui.senderId.value = String(merged.senderId);
    state.passwordHash = merged.passwordHash;
    ui.password.value = "";
    ui.cryptoMode.value = String(merged.cryptoMode);
    ui.browserCodec.value = normalizeBrowserCodec(merged.browserCodec);
    if (ui.wsToken) {
      ui.wsToken.value = String(merged.wsToken || "");
    }
    if (ui.txCodec) {
      ui.txCodec.value = normalizeTxCodec(merged.txCodec);
    }
    if (ui.qosEnabled) {
      ui.qosEnabled.checked = merged.qosEnabled !== false;
    }
    if (ui.fecEnabled) {
      ui.fecEnabled.checked = merged.fecEnabled !== false;
    }
    ui.codec2Lib.value = String(merged.codec2Lib || "");
    ui.opusLib.value = String(merged.opusLib || "");
    applyMicVolumeFromUI(merged.micVolumePercent, false);
    if (ui.receiveOnly) {
      ui.receiveOnly.checked = !!merged.receiveOnly;
    }
    state.receiveOnly = !!merged.receiveOnly;
    if (ui.selfSenderMute) {
      ui.selfSenderMute.checked = merged.selfSenderMute !== false;
    }
    state.selfSenderMute = ui.selfSenderMute ? !!ui.selfSenderMute.checked : true;
    sanitizeSelectedTxCodec(merged.codecMode);
    ui.cuePttOnEnabled.checked = !!merged.cuePttOnEnabled;
    ui.cuePttOffEnabled.checked = !!merged.cuePttOffEnabled;
    ui.cueCarrierEnabled.checked = !!merged.cueCarrierEnabled;
    ui.cuePttOnUrl.value = String(merged.cuePttOnUrl);
    ui.cuePttOffUrl.value = String(merged.cuePttOffUrl);
    ui.cueCarrierUrl.value = String(merged.cueCarrierUrl);
    ui.audioTxSlotCount.value = String(normalizeAudioTxSlotCount(merged.audioTxSlotCount));
    if (ui.audioTxLoopEnabled) {
      ui.audioTxLoopEnabled.checked = !!merged.audioTxLoopEnabled;
    }
    setAudioTxSlotCount(merged.audioTxSlotCount, false);
    applyFixedRelayUIState();
    applyPasswordInputPresentation();
    sanitizeStartupURLQuery();

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
      ui.wsToken,
      ui.txCodec,
      ui.receiveOnly,
      ui.selfSenderMute,
      ui.qosEnabled,
      ui.fecEnabled,
      ui.codec2Lib,
      ui.opusLib,
      ui.cuePttOnEnabled,
      ui.cuePttOffEnabled,
      ui.cueCarrierEnabled,
      ui.cuePttOnUrl,
      ui.cuePttOffUrl,
      ui.cueCarrierUrl,
      ui.audioTxSlotCount,
      ui.audioTxLoopEnabled,
    ];

    persistTargets.forEach((element) => {
      if (!element) {
        return;
      }
      element.addEventListener("input", persistFormSettings);
      element.addEventListener("change", persistFormSettings);
    });

    const reconnectTargets = [
      ui.relayHost,
      ui.relayPort,
      ui.channelId,
      ui.senderId,
      ui.password,
      ui.cryptoMode,
      ui.codecMode,
      ui.browserCodec,
      ui.wsToken,
      ui.txCodec,
      ui.qosEnabled,
      ui.fecEnabled,
      ui.codec2Lib,
      ui.opusLib,
    ];
    reconnectTargets.forEach((element) => {
      if (!element) {
        return;
      }
      element.addEventListener("change", scheduleSettingsReconnect);
    });

    if (ui.senderId && !ui.senderId.dataset.normalizeBound) {
      ui.senderId.dataset.normalizeBound = "1";
      ui.senderId.addEventListener("blur", () => {
        canonicalizeSenderIDField();
        persistFormSettings();
      });
    }

    if (ui.password && !ui.password.dataset.passwordUiBound) {
      ui.password.dataset.passwordUiBound = "1";
      ui.password.addEventListener("focus", () => {
        ui.password.select();
      });
      ui.password.addEventListener("input", () => {
        applyPasswordInputPresentation();
      });
      ui.password.addEventListener("blur", () => {
        applyPasswordInputPresentation();
      });
    }

    if (ui.micVolume && !ui.micVolume.dataset.micVolumeBound) {
      ui.micVolume.dataset.micVolumeBound = "1";
      const syncMicVolume = () => {
        applyMicVolumeFromUI(ui.micVolume.value, true);
      };
      ui.micVolume.addEventListener("input", syncMicVolume);
      ui.micVolume.addEventListener("change", syncMicVolume);
    }

    if (ui.receiveOnly && !ui.receiveOnly.dataset.receiveOnlyBound) {
      ui.receiveOnly.dataset.receiveOnlyBound = "1";
      ui.receiveOnly.addEventListener("change", () => {
        applyReceiveOnlyFromUI(true);
        persistFormSettings();
      });
    }
    if (ui.selfSenderMute && !ui.selfSenderMute.dataset.selfSenderMuteBound) {
      ui.selfSenderMute.dataset.selfSenderMuteBound = "1";
      ui.selfSenderMute.addEventListener("change", () => {
        applySelfSenderMuteFromUI();
        persistFormSettings();
      });
    }
  }

  function hasAutoConnectConfig() {
    const relayHost = fixedRelayEnabled
      ? effectiveFixedRelayHost()
      : currentRelayHost();
    const relayPort = fixedRelayEnabled
      ? Number(effectiveFixedRelayPort())
      : currentRelayPort();
    const channelID = Number.parseInt(String(ui.channelId ? ui.channelId.value : "").trim(), 10);
    const passwordHash = normalizePasswordHashToken(state.passwordHash);
    return (
      relayHost !== "" &&
      Number.isFinite(relayPort) &&
      relayPort > 0 &&
      Number.isInteger(channelID) &&
      channelID > 0 &&
      passwordHash !== ""
    );
  }

  async function ensureAutoConnectPasswordHash() {
    state.passwordHash = normalizePasswordHashToken(state.passwordHash);
    if (state.passwordHash) {
      return true;
    }

    let legacyPlain = String(state.startupLegacyPlainPassword || "");
    if (!legacyPlain) {
      const stored = readStoredSettings();
      if (stored && typeof stored.password === "string") {
        legacyPlain = stored.password;
      }
    }
    if (!legacyPlain) {
      return false;
    }

    const hashHex = await sha256Hex(legacyPlain);
    state.passwordHash = `${passwordHashPrefix}${hashHex}`;
    state.startupLegacyPlainPassword = "";
    applyPasswordInputPresentation();
    persistFormSettings();
    return true;
  }

  async function maybeAutoConnectOnStartup() {
    if (state.startupAutoConnectAttempted) {
      return;
    }
    state.startupAutoConnectAttempted = true;
    await ensureAutoConnectPasswordHash();
    if (!hasAutoConnectConfig()) {
      return;
    }
    clearPendingSettingsReconnect();
    persistFormSettings();
    try {
      await connectRelay();
    } catch (err) {
      appendLog(t("log_connect_failed", { error: err && err.message ? err.message : String(err) }), "error");
      applyDisconnectedState();
    }
  }

  function clearPendingSettingsReconnect() {
    if (!state.settingsReconnectTimer) {
      return;
    }
    window.clearTimeout(state.settingsReconnectTimer);
    state.settingsReconnectTimer = null;
  }

  function scheduleSettingsReconnect() {
    if (!state.connected || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    clearPendingSettingsReconnect();
    state.settingsReconnectTimer = window.setTimeout(() => {
      state.settingsReconnectTimer = null;
      if (!state.connected || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
        return;
      }
      appendLog(t("log_reconnecting_settings"), "warn");
      disconnectRelay();
      connectRelay().catch((err) => {
        appendLog(t("log_connect_failed", { error: err.message || err }), "error");
        applyDisconnectedState();
      });
    }, settingsReconnectDebounceMs);
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
    const passwordHash = normalizePasswordHashToken(state.passwordHash);
    const settings = {
      relayHost: fixedRelayEnabled ? effectiveFixedRelayHost() : currentRelayHost(),
      relayPort: fixedRelayEnabled ? String(effectiveFixedRelayPort()) : String(currentRelayPort() || ""),
      channelId: ui.channelId.value,
      senderId: ui.senderId.value,
      passwordHash,
      cryptoMode: ui.cryptoMode.value,
      codecMode: ui.codecMode.value,
      browserCodec: ui.browserCodec.value,
      wsToken: currentWSToken(),
      txCodec: selectedTxCodec,
      micVolumePercent: String(normalizeMicVolumePercent(ui.micVolume ? ui.micVolume.value : state.micVolumePercent)),
      receiveOnly: !!state.receiveOnly,
      selfSenderMute: !!state.selfSenderMute,
      qosEnabled: ui.qosEnabled ? !!ui.qosEnabled.checked : true,
      fecEnabled: ui.fecEnabled ? !!ui.fecEnabled.checked : true,
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
      audioTxLoopEnabled: !!(ui.audioTxLoopEnabled && ui.audioTxLoopEnabled.checked),
    };
    try {
      localStorage.setItem(settingsStorageKey, JSON.stringify(settings));
    } catch (_) {
      // Ignore persistence errors (private mode or storage denied).
    }
    persistLegacyWSToken(settings.wsToken);
  }

  function openMediaStorage() {
    return new Promise((resolve, reject) => {
      if (typeof indexedDB === "undefined") {
        reject(new Error("IndexedDB is not available"));
        return;
      }

      let request;
      try {
        request = indexedDB.open(mediaStorageDBName, mediaStorageVersion);
      } catch (err) {
        reject(err);
        return;
      }
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(mediaStorageStoreName)) {
          db.createObjectStore(mediaStorageStoreName, { keyPath: "key" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("failed to open media storage"));
      request.onblocked = () => reject(new Error("media storage is blocked by another tab"));
    });
  }

  async function runMediaStorageTransaction(mode, operation) {
    const db = await openMediaStorage();
    return new Promise((resolve, reject) => {
      let result;
      let settled = false;
      const finish = (callback, value) => {
        if (settled) {
          return;
        }
        settled = true;
        try {
          db.close();
        } catch (_) {
          // Ignore close errors.
        }
        callback(value);
      };

      let transaction;
      try {
        transaction = db.transaction(mediaStorageStoreName, mode);
      } catch (err) {
        finish(reject, err);
        return;
      }
      transaction.oncomplete = () => finish(resolve, result);
      transaction.onerror = () => finish(reject, transaction.error || new Error("media storage transaction failed"));
      transaction.onabort = () => finish(reject, transaction.error || new Error("media storage transaction aborted"));

      try {
        operation(transaction.objectStore(mediaStorageStoreName), (value) => {
          result = value;
        });
      } catch (err) {
        try {
          transaction.abort();
        } catch (_) {
          // Ignore abort errors after a completed transaction.
        }
        finish(reject, err);
      }
    });
  }

  function mediaStorageKeyForCue(kind) {
    return `${mediaStorageCuePrefix}${kind}`;
  }

  function mediaStorageKeyForAudioTxSlot(index) {
    return `${mediaStorageAudioTxPrefix}${index}`;
  }

  function isCueMediaKey(key) {
    return String(key || "").startsWith(mediaStorageCuePrefix);
  }

  function isAudioTxMediaKey(key) {
    return String(key || "").startsWith(mediaStorageAudioTxPrefix);
  }

  function mediaRecordFromFile(key, group, file, slotIndex = null) {
    if (!file || typeof file.size !== "number" || typeof file.arrayBuffer !== "function") {
      throw new Error("selected media file is invalid");
    }
    const size = Math.max(0, Math.floor(file.size));
    return {
      key,
      group,
      slotIndex,
      blob: file,
      name: String(file.name || "audio"),
      type: String(file.type || "application/octet-stream"),
      size,
      updatedAt: Date.now(),
    };
  }

  function normalizeStoredMediaRecord(record) {
    if (!record || typeof record !== "object" || !record.blob ||
        typeof record.blob.arrayBuffer !== "function" || typeof record.blob.size !== "number") {
      return null;
    }
    const key = String(record.key || "");
    if (!isCueMediaKey(key) && !isAudioTxMediaKey(key)) {
      return null;
    }
    const group = isCueMediaKey(key) ? "cue" : "audioTx";
    const size = Math.max(0, Math.floor(Number(record.size) || record.blob.size || 0));
    return {
      key,
      group,
      slotIndex: Number.isInteger(record.slotIndex) ? record.slotIndex : null,
      blob: record.blob,
      name: String(record.name || "audio"),
      type: String(record.type || record.blob.type || "application/octet-stream"),
      size,
      updatedAt: Number(record.updatedAt) || 0,
    };
  }

  async function listPersistedMediaRecords() {
    const records = await runMediaStorageTransaction("readonly", (store, setResult) => {
      const request = store.getAll();
      request.onsuccess = () => setResult(request.result || []);
    });
    return Array.isArray(records)
      ? records.map(normalizeStoredMediaRecord).filter((record) => record !== null)
      : [];
  }

  function calculatePersistedMediaUsage(records, replacingKey, replacement) {
    let cueBytes = 0;
    let audioTxBytes = 0;
    let totalBytes = 0;
    let replacedSize = 0;
    for (const record of records) {
      if (record.key === replacingKey) {
        replacedSize = record.size;
        continue;
      }
      totalBytes += record.size;
      if (record.group === "cue") {
        cueBytes += record.size;
      } else {
        audioTxBytes += record.size;
      }
    }

    totalBytes += replacement.size;
    if (replacement.group === "cue") {
      cueBytes += replacement.size;
    } else {
      audioTxBytes += replacement.size;
    }
    return { cueBytes, audioTxBytes, totalBytes, replacedSize };
  }

  async function ensureMediaStorageCapacity(records, replacement) {
    const usage = calculatePersistedMediaUsage(records, replacement.key, replacement);
    if (usage.cueBytes > maxCueFilesBytes) {
      throw new Error(`cue sound storage limit is ${formatByteSize(maxCueFilesBytes)}`);
    }
    if (usage.audioTxBytes > maxAudioTxFilesBytes) {
      throw new Error(`audio file TX storage limit is ${formatByteSize(maxAudioTxFilesBytes)}`);
    }
    if (usage.totalBytes > maxPersistedMediaBytes) {
      throw new Error(`local media storage limit is ${formatByteSize(maxPersistedMediaBytes)}`);
    }

    if (!navigator.storage || typeof navigator.storage.estimate !== "function") {
      return;
    }
    try {
      const estimate = await navigator.storage.estimate();
      const quota = Number(estimate && estimate.quota);
      const currentUsage = Number(estimate && estimate.usage);
      const additionalBytes = Math.max(0, replacement.size - usage.replacedSize);
      if (Number.isFinite(quota) && Number.isFinite(currentUsage) && currentUsage + additionalBytes > quota) {
        throw new Error("browser storage quota is exhausted");
      }
    } catch (err) {
      if (err && String(err.message || err).includes("quota")) {
        throw err;
      }
      // A failed estimate must not prevent normal IndexedDB storage.
    }
  }

  async function savePersistedMediaFile(key, group, file, slotIndex = null) {
    const record = mediaRecordFromFile(key, group, file, slotIndex);
    const records = await listPersistedMediaRecords();
    await ensureMediaStorageCapacity(records, record);
    await runMediaStorageTransaction("readwrite", (store) => {
      store.put(record);
    });
    requestPersistentMediaStorage();
    return record;
  }

  async function deletePersistedMediaFile(key) {
    await runMediaStorageTransaction("readwrite", (store) => {
      store.delete(key);
    });
  }

  async function deletePersistedAudioTxFilesFrom(index) {
    const records = await listPersistedMediaRecords();
    const keys = records
      .filter((record) => record.group === "audioTx" && Number.isInteger(record.slotIndex) && record.slotIndex >= index)
      .map((record) => record.key);
    if (keys.length === 0) {
      return;
    }
    await runMediaStorageTransaction("readwrite", (store) => {
      keys.forEach((key) => store.delete(key));
    });
  }

  async function clearPersistedMediaStorage() {
    const keys = (await listPersistedMediaRecords()).map((record) => record.key);
    if (keys.length === 0) {
      return;
    }
    await runMediaStorageTransaction("readwrite", (store) => {
      keys.forEach((key) => store.delete(key));
    });
  }

  function requestPersistentMediaStorage() {
    if (state.mediaStoragePersistenceRequested || !navigator.storage ||
        typeof navigator.storage.persist !== "function") {
      return;
    }
    state.mediaStoragePersistenceRequested = true;
    navigator.storage.persist().catch(() => {
      // Persistent storage is optional. IndexedDB still works in best-effort mode.
    });
  }

  function createCueFileEntry(file, metadata = {}, persisted = false) {
    return {
      file,
      objectUrl: URL.createObjectURL(file),
      name: String(metadata.name || file.name || "audio"),
      type: String(metadata.type || file.type || "application/octet-stream"),
      size: Math.max(0, Math.floor(Number(metadata.size) || file.size || 0)),
      persisted: !!persisted,
    };
  }

  function clearCueFileFromMemory(kind) {
    const previous = state.cueFiles[kind];
    if (previous && previous.objectUrl) {
      try {
        URL.revokeObjectURL(previous.objectUrl);
      } catch (_) {
        // Ignore revoke errors.
      }
    }
    state.cueFiles[kind] = null;
    updateCueFileStatus(kind);
  }

  function setCueFileFromRecord(kind, record) {
    clearCueFileFromMemory(kind);
    state.cueFiles[kind] = createCueFileEntry(record.blob, record, true);
    updateCueFileStatus(kind);
  }

  function formatByteSize(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) {
      return `${Math.round(bytes)} B`;
    }
    const units = ["KiB", "MiB", "GiB"];
    let scaled = bytes / 1024;
    let unitIndex = 0;
    while (scaled >= 1024 && unitIndex < units.length - 1) {
      scaled /= 1024;
      unitIndex += 1;
    }
    return `${scaled >= 10 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[unitIndex]}`;
  }

  function describeLocalMediaFile(entry, emptyLabel) {
    if (!entry || !entry.file) {
      return emptyLabel || t("media_file_none");
    }
    const params = {
      name: String(entry.name || entry.file.name || "audio"),
      size: formatByteSize(entry.size || entry.file.size),
    };
    return t(entry.persisted ? "media_file_saved" : "media_file_session", params);
  }

  function cueStatusElement(kind) {
    if (kind === "pttOn") {
      return ui.cuePttOnFileStatus;
    }
    if (kind === "pttOff") {
      return ui.cuePttOffFileStatus;
    }
    return ui.cueCarrierFileStatus;
  }

  function updateCueFileStatus(kind) {
    const element = cueStatusElement(kind);
    if (element) {
      element.textContent = describeLocalMediaFile(state.cueFiles[kind]);
    }
  }

  function refreshCueFileStatuses() {
    updateCueFileStatus("pttOn");
    updateCueFileStatus("pttOff");
    updateCueFileStatus("carrier");
    const storageControls = [
      ui.cuePttOnFile,
      ui.cuePttOffFile,
      ui.cueCarrierFile,
      ui.cuePttOnReset,
      ui.cuePttOffReset,
      ui.cueCarrierReset,
    ];
    storageControls.forEach((element) => {
      if (element) {
        element.disabled = !state.mediaFilesReady;
      }
    });
  }

  async function restorePersistedMediaFiles() {
    try {
      const records = await listPersistedMediaRecords();
      for (const record of records) {
        if (record.group === "cue") {
          const kind = record.key.slice(mediaStorageCuePrefix.length);
          if (kind === "pttOn" || kind === "pttOff" || kind === "carrier") {
            setCueFileFromRecord(kind, record);
          }
          continue;
        }
        if (record.group === "audioTx" && Number.isInteger(record.slotIndex) &&
            record.slotIndex >= 0 && record.slotIndex < state.audioTxSlots.length) {
          state.audioTxSlots[record.slotIndex] = {
            file: record.blob,
            name: record.name,
            type: record.type,
            size: record.size,
            persisted: true,
          };
        }
      }
    } catch (err) {
      appendLog(t("log_media_restore_failed", { error: err && err.message ? err.message : String(err) }), "warn");
    } finally {
      state.mediaFilesReady = true;
      refreshCueFileStatuses();
      refreshAudioTxSlotsUI();
    }
  }

  async function clearAllSavedMediaFiles() {
    if (state.audioTxTask || hasPendingAudioTxLoad()) {
      return;
    }
    if (typeof window.confirm === "function" && !window.confirm(t("media_clear_saved_confirm"))) {
      return;
    }

    let storedFilesCleared = true;
    try {
      await clearPersistedMediaStorage();
    } catch (err) {
      // Clear current-session files too; a later reload may restore files if the
      // browser denied IndexedDB deletion, and the warning makes that visible.
      storedFilesCleared = false;
      appendLog(t("log_media_restore_failed", { error: err && err.message ? err.message : String(err) }), "warn");
    }

    cleanupCueFiles();
    state.audioTxSlots = state.audioTxSlots.map(() => createAudioTxSlotState());
    persistFormSettings();
    refreshCueFileStatuses();
    refreshAudioTxSlotsUI();
    if (storedFilesCleared) {
      appendLog(t("log_media_storage_cleared"), "info");
    }
  }

  function bindCueControls() {
    const bindCueFileInput = (kind, input) => {
      if (!input) {
        return;
      }
      input.addEventListener("change", () => {
        const file = input.files && input.files[0];
        input.value = "";
        selectCueFile(kind, file).catch((err) => {
          appendLog(t("log_cue_play_failed", {
            label: cueControls(kind).label,
            error: err && err.message ? err.message : String(err),
          }), "warn");
        });
      });
    };
    bindCueFileInput("pttOn", ui.cuePttOnFile);
    bindCueFileInput("pttOff", ui.cuePttOffFile);
    bindCueFileInput("carrier", ui.cueCarrierFile);

    ui.cuePttOnTest.addEventListener("click", () => playCue("pttOn", true));
    ui.cuePttOffTest.addEventListener("click", () => playCue("pttOff", true));
    ui.cueCarrierTest.addEventListener("click", () => playCue("carrier", true));

    const bindCueReset = (kind, button) => {
      button.addEventListener("click", () => {
        resetCueToDefault(kind).catch((err) => {
          appendLog(t("log_cue_play_failed", {
            label: cueControls(kind).label,
            error: err && err.message ? err.message : String(err),
          }), "warn");
        });
      });
    };
    bindCueReset("pttOn", ui.cuePttOnReset);
    bindCueReset("pttOff", ui.cuePttOffReset);
    bindCueReset("carrier", ui.cueCarrierReset);

    window.addEventListener("beforeunload", cleanupCueFiles);
  }

  function bindAudioTxControls() {
    if (ui.clearSavedMediaBtn) {
      ui.clearSavedMediaBtn.addEventListener("click", () => {
        clearAllSavedMediaFiles().catch((err) => {
          appendLog(t("log_media_restore_failed", {
            error: err && err.message ? err.message : String(err),
          }), "warn");
        });
      });
    }
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
        status: ui.cuePttOnFileStatus,
        defaultUrl: cueDefaults.pttOnUrl,
        label: t("cue_ptt_on"),
      };
    }
    if (kind === "pttOff") {
      return {
        enabled: ui.cuePttOffEnabled,
        url: ui.cuePttOffUrl,
        file: ui.cuePttOffFile,
        status: ui.cuePttOffFileStatus,
        defaultUrl: cueDefaults.pttOffUrl,
        label: t("cue_ptt_off"),
      };
    }
    return {
      enabled: ui.cueCarrierEnabled,
      url: ui.cueCarrierUrl,
      file: ui.cueCarrierFile,
      status: ui.cueCarrierFileStatus,
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

  async function selectCueFile(kind, file) {
    clearCueFileFromMemory(kind);
    if (!file) {
      return;
    }

    const entry = createCueFileEntry(file, file, false);
    state.cueFiles[kind] = entry;
    updateCueFileStatus(kind);
    try {
      const record = await savePersistedMediaFile(mediaStorageKeyForCue(kind), "cue", file);
      entry.name = record.name;
      entry.type = record.type;
      entry.size = record.size;
      entry.persisted = true;
    } catch (err) {
      try {
        await deletePersistedMediaFile(mediaStorageKeyForCue(kind));
      } catch (_) {
        // Ignore cleanup errors; the current selection remains session-only.
      }
      appendLog(t("log_media_file_session_only", {
        name: entry.name,
        error: err && err.message ? err.message : String(err),
      }), "warn");
    }
    updateCueFileStatus(kind);
    appendLog(t("log_cue_local_selected", { label: cueControls(kind).label, name: entry.name }), "info");
  }

  async function resetCueToDefault(kind) {
    clearCueFileFromMemory(kind);
    await deletePersistedMediaFile(mediaStorageKeyForCue(kind));
    const controls = cueControls(kind);
    if (controls.url) {
      controls.url.value = controls.defaultUrl;
    }
    if (controls.file) {
      controls.file.value = "";
    }
    updateCueFileStatus(kind);
    persistFormSettings();
    appendLog(t("log_cue_reset_default", { label: controls.label }), "info");
  }

  function cleanupCueFiles() {
    clearCueFileFromMemory("pttOn");
    clearCueFileFromMemory("pttOff");
    clearCueFileFromMemory("carrier");
  }

  function normalizeAudioTxSlotCount(value) {
    const parsed = Number.parseInt(String(value || "").trim(), 10);
    if (!Number.isFinite(parsed)) {
      return 3;
    }
    return Math.max(1, Math.min(12, parsed));
  }

  function createAudioTxSlotState() {
    return {
      file: null,
      name: "",
      type: "",
      size: 0,
      persisted: false,
    };
  }

  function setAudioTxSlotCount(value, preserveExisting) {
    const count = normalizeAudioTxSlotCount(value);
    const keepExisting = preserveExisting !== false;
    const previousSlots = state.audioTxSlots;
    const next = [];
    for (let i = 0; i < count; i += 1) {
      if (keepExisting && previousSlots[i]) {
        next.push(previousSlots[i]);
      } else {
        next.push(createAudioTxSlotState());
      }
    }
    state.audioTxSlots = next;
    if (keepExisting && count < previousSlots.length) {
      deletePersistedAudioTxFilesFrom(count).catch((err) => {
        appendLog(t("log_media_restore_failed", {
          error: err && err.message ? err.message : String(err),
        }), "warn");
      });
    }
    if (ui.audioTxSlotCount) {
      ui.audioTxSlotCount.value = String(count);
    }
    refreshAudioTxSlotsUI();
  }

  function hasPendingAudioTxLoad() {
    return Number.isInteger(state.audioTxLoadingSlot) && state.audioTxLoadingSlot >= 0;
  }

  function cancelPendingAudioTxLoad() {
    const hadPendingLoad = hasPendingAudioTxLoad();
    state.audioTxLoadSequence += 1;
    if (hadPendingLoad) {
      state.audioTxLoadingSlot = -1;
      refreshAudioTxSlotsUI();
    }
    return hadPendingLoad;
  }

  function refreshAudioTxSlotsUI() {
    const audioTxBusy = !!state.audioTxTask || hasPendingAudioTxLoad();
    if (ui.clearSavedMediaBtn) {
      ui.clearSavedMediaBtn.disabled = !state.mediaFilesReady || audioTxBusy;
    }
    if (ui.audioTxSlotCount) {
      ui.audioTxSlotCount.disabled = audioTxBusy;
    }
    if (ui.audioTxLoopEnabled) {
      ui.audioTxLoopEnabled.disabled = audioTxBusy;
    }
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
    const loadingSlot = state.audioTxLoadingSlot;
    const hasPendingLoad = hasPendingAudioTxLoad();
    const hasBusyAudioTx = hasActiveTask || hasPendingLoad;
    const pttBusy = state.pttPressed && !hasActiveTask;
    const mediaFilesLoading = !state.mediaFilesReady;

    for (let i = 0; i < state.audioTxSlots.length; i += 1) {
      const slot = state.audioTxSlots[i] || createAudioTxSlotState();
      const row = document.createElement("div");
      row.className = "audio-tx-slot";
      const isActiveSlot = !!(activeTask && activeTask.slotIndex === i);
      const isLoadingSlot = loadingSlot === i;
      if (isActiveSlot) {
        row.classList.add("active");
      }
      if (isLoadingSlot) {
        row.classList.add("loading");
      }

      const head = document.createElement("div");
      head.className = "audio-tx-slot-head";

      const title = document.createElement("p");
      title.className = "audio-tx-slot-title";
      title.textContent = t("audio_tx_slot", { index: i + 1 });
      head.appendChild(title);

      const name = document.createElement("p");
      name.className = "audio-tx-slot-file";
      name.textContent = describeLocalMediaFile(slot, t("audio_tx_slot_empty"));
      head.appendChild(name);
      row.appendChild(head);

      const hiddenInput = document.createElement("input");
      hiddenInput.type = "file";
      hiddenInput.accept = "audio/*,.wav";
      hiddenInput.className = "audio-tx-file-input";
      hiddenInput.disabled = hasBusyAudioTx || mediaFilesLoading;
      hiddenInput.addEventListener("change", () => {
        const file = hiddenInput.files && hiddenInput.files[0];
        hiddenInput.value = "";
        setAudioTxSlotFile(i, file).catch((err) => {
          appendLog(t("log_audio_tx_failed", {
            index: i + 1,
            error: err && err.message ? err.message : String(err),
          }), "error");
        });
      });
      row.appendChild(hiddenInput);

      const actions = document.createElement("div");
      actions.className = "audio-tx-slot-actions";

      const sendBtn = document.createElement("button");
      sendBtn.type = "button";
      sendBtn.className = "btn";
      sendBtn.textContent = isActiveSlot
        ? t("audio_tx_stop")
        : (isLoadingSlot ? t("audio_tx_loading") : t("audio_tx_send"));
      sendBtn.disabled = isActiveSlot
        ? false
        : (!state.connected || !slot.file || hasBusyAudioTx || pttBusy || mediaFilesLoading || state.receiveOnly);
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
      selectBtn.disabled = hasBusyAudioTx || mediaFilesLoading;
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
      deleteBtn.disabled = hasBusyAudioTx || mediaFilesLoading || !slot.file;
      deleteBtn.addEventListener("click", () => {
        clearAudioTxSlotFile(i, true).catch((err) => {
          appendLog(t("log_audio_tx_failed", {
            index: i + 1,
            error: err && err.message ? err.message : String(err),
          }), "error");
        });
      });
      actions.appendChild(deleteBtn);

      row.appendChild(actions);
      ui.audioTxSlots.appendChild(row);
    }
  }

  async function setAudioTxSlotFile(index, file) {
    if (index < 0 || index >= state.audioTxSlots.length) {
      return;
    }
    if (!file) {
      await clearAudioTxSlotFile(index, false);
      return;
    }

    const slot = {
      file,
      name: String(file.name || "audio"),
      type: String(file.type || "application/octet-stream"),
      size: Math.max(0, Math.floor(file.size || 0)),
      persisted: false,
    };
    state.audioTxSlots[index] = slot;
    try {
      const record = await savePersistedMediaFile(mediaStorageKeyForAudioTxSlot(index), "audioTx", file, index);
      slot.name = record.name;
      slot.type = record.type;
      slot.size = record.size;
      slot.persisted = true;
    } catch (err) {
      try {
        await deletePersistedMediaFile(mediaStorageKeyForAudioTxSlot(index));
      } catch (_) {
        // Ignore cleanup errors; the current selection remains session-only.
      }
      appendLog(t("log_media_file_session_only", {
        name: slot.name,
        error: err && err.message ? err.message : String(err),
      }), "warn");
    }
    persistFormSettings();
    appendLog(t("log_audio_tx_slot_selected", { index: index + 1, name: slot.name }), "info");
    refreshAudioTxSlotsUI();
  }

  async function clearAudioTxSlotFile(index, emitLog) {
    if (index < 0 || index >= state.audioTxSlots.length) {
      return;
    }
    const slot = state.audioTxSlots[index];
    if (!slot) {
      return;
    }
    const hadFile = !!slot.file;
    state.audioTxSlots[index] = createAudioTxSlotState();
    persistFormSettings();
    refreshAudioTxSlotsUI();
    await deletePersistedMediaFile(mediaStorageKeyForAudioTxSlot(index));
    if (emitLog && hadFile) {
      appendLog(t("log_audio_tx_slot_cleared", { index: index + 1 }), "info");
    }
  }

  async function startAudioTxFromSlot(index) {
    if (state.audioTxTask || hasPendingAudioTxLoad()) {
      appendLog(t("log_audio_tx_busy"), "warn");
      return;
    }
    if (state.receiveOnly) {
      appendLog(t("log_audio_tx_receive_only"), "warn");
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

    // Resume synchronously from the click handler. Later decode/auth awaits are
    // no longer considered a user gesture by browsers with autoplay policies.
    let outputResumePromise = Promise.resolve();
    let txPacerLoadPromise = Promise.resolve(false);
    try {
      if (state.player) {
        outputResumePromise = state.player.resume();
        // Fetch/compile the clock worklet while authentication and file decoding
        // are in progress. Starting it only after decoding could otherwise make
        // the first few 20 ms file frames stale on a cold cache.
        txPacerLoadPromise = outputResumePromise
          .then(() => {
            const ctx = state.player && state.player.ctx;
            if (!ctx || !ctx.audioWorklet) {
              return false;
            }
            return loadAudioTxPacerModule(ctx).then(() => true);
          })
          .catch((err) => {
            audioDebug("audio-file-clock-preload-unavailable", {
              error: err && err.message ? err.message : String(err),
            });
            return false;
          });
      }
    } catch (_) {
      // The regular task startup reports an output failure if it remains unusable.
    }

    const loadSequence = state.audioTxLoadSequence + 1;
    state.audioTxLoadSequence = loadSequence;
    state.audioTxLoadingSlot = index;
    refreshAudioTxSlotsUI();
    try {
      if (!(await ensureAuthSessionBeforeTransmit("audio_tx"))) {
        return;
      }
      if (state.audioTxLoadSequence !== loadSequence || state.audioTxLoadingSlot !== index || state.receiveOnly) {
        return;
      }
      await outputResumePromise.catch(() => {});

      const frames = await decodeAudioFileToFrames(slot.file);
      // Do not let a cold worklet module turn the beginning of a file into a
      // timer-sized gap. A failed preload is harmless: startAudioTxClock()
      // selects its compatibility fallback below.
      await txPacerLoadPromise;
      if (state.audioTxLoadSequence !== loadSequence || state.audioTxLoadingSlot !== index || state.receiveOnly) {
        return;
      }
      if (!frames || frames.length === 0) {
        throw new Error("decoded audio is empty");
      }
      state.audioTxLoadingSlot = -1;
      refreshAudioTxSlotsUI();
      await startAudioTxTask(index, String(slot.name || slot.file.name || "audio"), frames);
    } finally {
      if (state.audioTxLoadSequence === loadSequence && state.audioTxLoadingSlot === index) {
        state.audioTxLoadingSlot = -1;
        refreshAudioTxSlotsUI();
      }
    }
  }

  async function decodeAudioFileToFrames(file) {
    if (typeof OfflineAudioContext === "undefined") {
      throw new Error(t("mic_not_supported"));
    }
    const sourceBytes = await file.arrayBuffer();
    // The relay accepts 160 mono samples per 20 ms frame, so its media clock is
    // fixed at 8 kHz. Decode directly in an OfflineAudioContext at that rate.
    // Decoding through a default AudioContext first (normally 44.1/48 kHz) and
    // then rendering again at 8 kHz performs an unnecessary second resample.
    // This cannot preserve source content above 4 kHz, but avoids degrading the
    // narrowband signal before it enters the existing PCM/Codec2/Opus contract.
    const targetSampleRate = 8000;
    const decodeContext = new OfflineAudioContext(1, 1, targetSampleRate);
    const decoded = await decodeContext.decodeAudioData(sourceBytes.slice(0));
    const targetSamples = Math.max(1, Math.ceil(decoded.duration * targetSampleRate));
    audioDebug("audio-file-decode", {
      name: String(file && file.name ? file.name : ""),
      decodedSampleRate: decoded.sampleRate,
      decodedChannels: decoded.numberOfChannels,
      targetSampleRate,
      targetChannels: 1,
      durationSec: decoded.duration,
    });
    const offline = new OfflineAudioContext(1, targetSamples, targetSampleRate);
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
  }

  function loadAudioTxPacerModule(ctx) {
    let loadPromise = audioTxPacerModulePromises.get(ctx);
    if (!loadPromise) {
      loadPromise = ctx.audioWorklet.addModule(resolveWorkletURL("audio-tx-pacer-worklet.js"));
      audioTxPacerModulePromises.set(ctx, loadPromise);
      loadPromise.catch(() => {
        if (audioTxPacerModulePromises.get(ctx) === loadPromise) {
          audioTxPacerModulePromises.delete(ctx);
        }
      });
    }
    return loadPromise;
  }

  class AudioTxPacer {
    constructor(player, onTick) {
      this.player = player;
      this.onTick = onTick;
      this.node = null;
      this.stopped = false;
    }

    async start() {
      const ctx = this.player && this.player.ctx;
      if (!ctx || !ctx.audioWorklet || typeof AudioWorkletNode === "undefined") {
        return false;
      }
      // A file may be played repeatedly with one AudioContext. Cache the module
      // per context so registerProcessor() is never evaluated twice.
      await loadAudioTxPacerModule(ctx);
      if (this.stopped) {
        return false;
      }
      const node = new AudioWorkletNode(ctx, "incomudon-audio-tx-pacer", {
        numberOfInputs: 0,
        numberOfOutputs: 1,
        outputChannelCount: [1],
      });
      node.port.onmessage = (event) => {
        const message = event && event.data;
        if (this.stopped || !message || message.type !== "tick") {
          return;
        }
        try {
          // The message can be delivered late when the page main thread is
          // deprioritized. currentTime at receipt lets the task skip frames
          // that are already stale instead of sending an old burst.
          this.onTick({
            ...message,
            receivedAudioTime: ctx.currentTime,
          });
        } finally {
          // Acknowledge one tick at a time. If the page main thread is held,
          // the worklet deliberately does not build a backlog of old frames.
          if (!this.stopped) {
            node.port.postMessage({ type: "ack" });
          }
        }
      };
      node.connect(ctx.destination);
      this.node = node;
      node.port.postMessage({
        type: "start",
        frameSamples: 160,
        sourceSampleRate: 8000,
      });
      return true;
    }

    stop() {
      this.stopped = true;
      if (!this.node) {
        return;
      }
      try {
        this.node.port.postMessage({ type: "stop" });
        this.node.port.onmessage = null;
        this.node.disconnect();
      } catch (_) {
        // The context may already have been closed during disconnect.
      }
      this.node = null;
    }
  }

  function audioTxClockTime(task, tick) {
    if (tick && tick.fallback) {
      return task.startAudioTime + ((performance.now() - task.startedAtMs) / 1000);
    }
    const workletTime = Number(tick && tick.audioTime);
    const receivedAudioTime = Number(tick && tick.receivedAudioTime);
    if (Number.isFinite(workletTime) && workletTime >= 0) {
      return Number.isFinite(receivedAudioTime) && receivedAudioTime >= workletTime
        ? receivedAudioTime
        : workletTime;
    }
    if (Number.isFinite(receivedAudioTime) && receivedAudioTime >= 0) {
      return receivedAudioTime;
    }
    if (state.player && state.player.ctx) {
      return state.player.ctx.currentTime;
    }
    return (performance.now() - task.startedAtMs) / 1000;
  }

  async function startAudioTxClock(task) {
    const pacer = new AudioTxPacer(state.player, (tick) => tickAudioTxTask(tick));
    task.pacer = pacer;
    try {
      if (await pacer.start()) {
        audioDebug("audio-file-clock", { clock: "AudioWorklet" });
        return;
      }
    } catch (err) {
      audioDebug("audio-file-clock-unavailable", {
        error: err && err.message ? err.message : String(err),
      });
    }
    pacer.stop();
    if (state.audioTxTask !== task || task.finishing) {
      return;
    }
    // Compatibility fallback for browsers without AudioWorklet. Chrome uses
    // the render-thread clock above, not this throttled window timer.
    task.timer = window.setInterval(() => tickAudioTxTask({ fallback: true }), 20);
    audioDebug("audio-file-clock", { clock: "window-timer-fallback" });
  }

  function stopAudioTxClock(task) {
    if (!task) {
      return;
    }
    if (task.timer) {
      window.clearInterval(task.timer);
      task.timer = null;
    }
    if (task.pacer) {
      task.pacer.stop();
      task.pacer = null;
    }
  }

  async function startAudioTxTask(slotIndex, name, frames) {
    if (state.receiveOnly) {
      return;
    }
    cancelAudioTxTask(false);
    state.txFrameIndex = 0;
    clearExpectedLocalTalkRelease();
    const ctx = state.player && state.player.ctx;
    const startAudioTime = ctx ? ctx.currentTime : 0;
    const task = {
      slotIndex,
      name,
      frames,
      next: 0,
      loop: !!(ui.audioTxLoopEnabled && ui.audioTxLoopEnabled.checked),
      timer: null,
      pacer: null,
      finishing: false,
      startAudioTime,
      startedAtMs: performance.now(),
    };
    state.audioTxTask = task;
    beginTxSession();
    state.pttPressed = true;
    ui.pttButton.classList.add("active");
    sendCommand({ type: "ptt", pressed: true });
    playCue("pttOn");
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    appendLog(t("log_audio_tx_start", { index: slotIndex + 1, name }), "info");

    // Send the first frame immediately; every later frame is scheduled from
    // AudioContext.currentTime by the render-thread pacer.
    tickAudioTxTask({ audioTime: startAudioTime, initial: true });
    if (state.audioTxTask !== task || task.finishing) {
      return;
    }
    await startAudioTxClock(task);
  }

  function tickAudioTxTask(tick) {
    const task = state.audioTxTask;
    if (!task || task.finishing) {
      return;
    }
    if (!state.connected || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      task.finishing = true;
      cancelAudioTxTask(false);
      return;
    }

    const nowAudioTime = audioTxClockTime(task, tick);
    const elapsedSec = Math.max(0, nowAudioTime - task.startAudioTime);
    const dueFrame = Math.max(0, Math.floor((elapsedSec + 0.0005) / audioFrameDurationSec));
    if (!tick || !tick.initial) {
      if (dueFrame > task.next) {
        const skipped = dueFrame - task.next;
        task.next = dueFrame;
        state.audioStats.audioTxSkipped += skipped;
        audioDebug("audio-file-skip", { skipped, dueFrame, name: task.name });
      }
      state.audioStats.audioTxTicks += 1;
      recordAudioActivity("audio-file-tick", { dueFrame, bytes: 320 });
    }

    if (!task.loop && task.next >= task.frames.length) {
      task.finishing = true;
      void finishAudioTxTask("log_audio_tx_completed", { index: task.slotIndex + 1, name: task.name }, "info");
      return;
    }

    const frameIndex = task.loop ? (task.next % task.frames.length) : task.next;
    const frame = task.frames[frameIndex];
    task.next += 1;
    transmitUplinkFrame(frame, "audio-file");
  }

  async function finishAudioTxTask(logKey, params, level) {
    const task = state.audioTxTask;
    if (!task) {
      return;
    }
    stopAudioTxClock(task);
    await flushAudioTxPipeline();
    if (state.audioTxTask !== task) {
      return;
    }

    if (state.pttPressed) {
      sendCommand({ type: "ptt", pressed: false });
      playCue("pttOff");
    }
    state.pttPressed = false;
    invalidateTxSession();
    ui.pttButton.classList.remove("active");
    state.txFrameIndex = 0;
    state.audioTxTask = null;
    stopTxTimeoutCountdown();
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();

    if (logKey) {
      appendLog(t(logKey, params || {}), level || "info");
    }
  }

  async function flushAudioTxPipeline() {
    if (state.uplinkCodec === "opus" && state.opusEncoder) {
      try {
        // flush() resolves after the output callback has emitted every prior
        // packet. WebSocket preserves message order, so no timer drain is needed.
        await state.opusEncoder.flush();
      } catch (_) {
        // Ignore encoder flush errors.
      }
    }
  }

  function cancelAudioTxTask(emitLog) {
    const cancelledPendingLoad = cancelPendingAudioTxLoad();
    const task = state.audioTxTask;
    if (!task) {
      if (cancelledPendingLoad && emitLog) {
        appendLog(t("log_audio_tx_aborted"), "warn");
      }
      return;
    }
    stopAudioTxClock(task);
    if (state.pttPressed) {
      sendCommand({ type: "ptt", pressed: false });
      playCue("pttOff");
    }
    state.audioTxTask = null;
    state.pttPressed = false;
    invalidateTxSession();
    ui.pttButton.classList.remove("active");
    stopTxTimeoutCountdown();
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

  function normalizeDirectoryName(value) {
    const name = String(value || "").trim();
    return name.length <= 128 && !/[\r\n\0]/.test(name) ? name : "";
  }

  function clearDirectoryProvisioning() {
    state.directoryChannels = Object.create(null);
    state.directorySpeakers = Object.create(null);
    state.directoryExpiryTimer = null;
    updateTalkerStatus(state.activeTalkers, state.talkAllowed);
    notifyEmbeddedSlotState();
  }

  function applyDirectoryProvisioning(document) {
    if (!document || typeof document !== "object") {
      return;
    }
    const expiresAt = Number(document.expiresAt || 0);
    const now = Date.now();
    if (!Number.isFinite(expiresAt) || expiresAt * 1000 <= now) {
      return;
    }
    const channels = Object.create(null);
    const speakers = Object.create(null);
    const rawChannels = Array.isArray(document.channels) ? document.channels : [];
    const rawSpeakers = Array.isArray(document.speakers) ? document.speakers : [];
    rawChannels.forEach((entry) => {
      const channelId = Number(entry && entry.channelId);
      const name = normalizeDirectoryName(entry && entry.name);
      if (Number.isInteger(channelId) && channelId > 0 && name) {
        channels[String(channelId)] = name;
      }
    });
    rawSpeakers.forEach((entry) => {
      const channelId = Number(entry && entry.channelId);
      const senderId = Number(entry && entry.senderId);
      const name = normalizeDirectoryName(entry && entry.name);
      if (Number.isInteger(channelId) && channelId > 0 && Number.isInteger(senderId) && senderId > 0 && name) {
        speakers[`${channelId}:${senderId}`] = name;
      }
    });
    state.directoryChannels = channels;
    state.directorySpeakers = speakers;
    if (state.directoryExpiryTimer) {
      window.clearTimeout(state.directoryExpiryTimer);
    }
    state.directoryExpiryTimer = window.setTimeout(
      clearDirectoryProvisioning,
      Math.min(300000, Math.max(0, expiresAt * 1000 - now + 50)),
    );
    updateTalkerStatus(state.activeTalkers, state.talkAllowed);
    notifyEmbeddedSlotState();
  }

  function directoryChannelName(channelId) {
    const normalized = Number(channelId) || 0;
    if (normalized <= 0) {
      return "";
    }
    return String(state.directoryChannels[String(normalized)] || "").trim();
  }

  function formatDirectoryChannelLabel(channelId) {
    const normalized = Number(channelId) || 0;
    if (normalized <= 0) {
      return "-";
    }
    const name = directoryChannelName(normalized);
    return name ? `${name} (${normalized})` : String(normalized);
  }

  function formatDirectorySpeakerLabel(channelId, senderId) {
    const normalizedChannel = Number(channelId) || 0;
    const normalizedSender = Number(senderId) || 0;
    if (normalizedSender <= 0) {
      return "-";
    }
    const name = state.directorySpeakers[`${normalizedChannel}:${normalizedSender}`];
    return name ? `${name} (${normalizedSender})` : String(normalizedSender);
  }

  function updateTalkerStatus(activeTalkers, talkAllowed) {
    const normalizedTalkers = Array.isArray(activeTalkers)
      ? activeTalkers
          .map((value) => Number(value || 0))
          .filter((value) => Number.isFinite(value) && value > 0)
      : [];
    state.activeTalkers = normalizedTalkers;
    state.talkerId = normalizedTalkers.find((talkerId) => talkerId !== state.selfSenderId)
      || (normalizedTalkers.includes(state.selfSenderId) ? state.selfSenderId : 0);
    state.talkAllowed = !!talkAllowed;
    syncTxTimeoutCountdownState();
    notifyEmbeddedSlotState();
    if (!ui.talkerStatus) {
      return;
    }
    if (state.activeTalkers.length === 0) {
      ui.talkerStatus.textContent = t("talker_none");
      updatePttButtonLabel();
      return;
    }
    const channelId = Number(ui.channelId ? ui.channelId.value : 0) || 0;
    const talkerText = state.activeTalkers
      .map((talkerId) => formatDirectorySpeakerLabel(channelId, talkerId))
      .join(", ");
    ui.talkerStatus.textContent = state.talkAllowed ? `${talkerText} (${t("talker_you")})` : talkerText;
    updatePttButtonLabel();
  }

  function clearTxTimeoutTicker() {
    if (!state.txTimeoutTicker) {
      return;
    }
    window.clearInterval(state.txTimeoutTicker);
    state.txTimeoutTicker = null;
  }

  function expectLocalTalkRelease() {
    if (state.selfSenderId > 0 && state.activeTalkers.includes(state.selfSenderId)) {
      state.expectedLocalTalkReleaseUntilMs = Date.now() + 5000;
    }
  }

  function clearExpectedLocalTalkRelease() {
    state.expectedLocalTalkReleaseUntilMs = 0;
  }

  function consumeExpectedLocalTalkRelease() {
    const expected = state.expectedLocalTalkReleaseUntilMs > Date.now();
    state.expectedLocalTalkReleaseUntilMs = 0;
    return expected;
  }

  function isLocalTxActiveForTimeout() {
    if (!state.connected) {
      return false;
    }
    if (state.serverTalkTimeoutSec <= 0) {
      return false;
    }
    if (!state.pttPressed || !state.talkAllowed) {
      return false;
    }
    if (!state.selfSenderId) {
      return false;
    }
    return state.activeTalkers.includes(state.selfSenderId);
  }

  function updatePttButtonLabel() {
    const label = document.getElementById("labelPttButton");
    if (!label) {
      return;
    }
    if (state.receiveOnly) {
      label.textContent = t("receive_only_mode");
      return;
    }
    if (isLocalTxActiveForTimeout() && state.txTimeoutRemainingSec > 0) {
      label.textContent = t("hold_to_talk_remaining", { seconds: state.txTimeoutRemainingSec });
      return;
    }
    label.textContent = t("hold_to_talk");
  }

  function stopTxTimeoutCountdown() {
    clearTxTimeoutTicker();
    state.txTimeoutDeadlineMs = 0;
    state.txTimeoutRemainingSec = 0;
    updatePttButtonLabel();
  }

  function restartTxTimeoutCountdown() {
    clearTxTimeoutTicker();
    if (state.serverTalkTimeoutSec <= 0) {
      stopTxTimeoutCountdown();
      return;
    }
    const maxSec = Math.max(1, Math.trunc(state.serverTalkTimeoutSec));
    state.txTimeoutDeadlineMs = Date.now() + (maxSec * 1000);
    state.txTimeoutRemainingSec = maxSec;
    updatePttButtonLabel();
    state.txTimeoutTicker = window.setInterval(() => {
      if (!isLocalTxActiveForTimeout()) {
        stopTxTimeoutCountdown();
        return;
      }
      const leftMs = state.txTimeoutDeadlineMs - Date.now();
      const leftSec = Math.max(0, Math.ceil(leftMs / 1000));
      if (leftSec !== state.txTimeoutRemainingSec) {
        state.txTimeoutRemainingSec = leftSec;
        updatePttButtonLabel();
      }
      if (leftMs <= 0) {
        handleLocalTxTimeout();
      }
    }, 200);
  }

  function syncTxTimeoutCountdownState() {
    if (!isLocalTxActiveForTimeout()) {
      stopTxTimeoutCountdown();
      return;
    }
    if (state.txTimeoutTicker) {
      updatePttButtonLabel();
      return;
    }
    restartTxTimeoutCountdown();
  }

  function forceStopTransmissionForTimeout() {
    cancelPendingAudioTxLoad();
    const task = state.audioTxTask;
    stopAudioTxClock(task);
    state.audioTxTask = null;
    clearExpectedLocalTalkRelease();
    if (state.pttPressed) {
      sendCommand({ type: "ptt", pressed: false });
    }
    state.pttPressed = false;
    invalidateTxSession();
    ui.pttButton.classList.remove("active");
    state.txFrameIndex = 0;
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    updatePttButtonLabel();
  }

  function handleLocalTxTimeout() {
    if (!state.pttPressed && !state.audioTxTask) {
      stopTxTimeoutCountdown();
      return;
    }
    stopTxTimeoutCountdown();
    playCue("carrier");
    forceStopTransmissionForTimeout();
    appendLog(t("log_tx_timeout_forced_off"), "warn");
  }

  function setConnectionView(next) {
    state.connectionView = {
      ...state.connectionView,
      ...next,
    };
    applyConnectionView();
    notifyEmbeddedSlotState();
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
      case "reconnecting":
        setConnectionStatus(t("status_reconnecting"), "error");
        return;
      case "unexpected-disconnected":
        setConnectionStatus(t("status_offline"), "error");
        return;
      default:
        setConnectionStatus(t("status_offline"), view.level || "warn");
        return;
    }
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

  function settingsUnlockSessionMatches(config) {
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

  function isSettingsUnlockSessionValid(config) {
    return settingsUnlockSessionMatches(config);
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

    if (ui.settingsLockCard) {
      ui.settingsLockCard.hidden = false;
    }
    if (ui.settingsLockDetails && locked) {
      ui.settingsLockDetails.open = true;
    }
    if (ui.settingsLockHeading) {
      ui.settingsLockHeading.textContent = t("settings_lock");
    }
    if (ui.labelSettingsMasterPassword) {
      ui.labelSettingsMasterPassword.textContent = t("settings_master_password");
    }
    if (ui.labelSettingsNewMasterPassword) {
      ui.labelSettingsNewMasterPassword.textContent = t("settings_new_master_password");
    }
    if (ui.labelSettingsConfirmMasterPassword) {
      ui.labelSettingsConfirmMasterPassword.textContent = t("settings_confirm_master_password");
    }
    if (ui.settingsUnlockButton) {
      ui.settingsUnlockButton.textContent = t("settings_unlock");
      ui.settingsUnlockButton.disabled = !enabled || !locked || state.settingsLockBusy;
    }
    if (ui.settingsEnableButton) {
      ui.settingsEnableButton.textContent = t("settings_enable");
      ui.settingsEnableButton.disabled = enabled || state.settingsLockBusy;
    }
    if (ui.settingsExportButton) {
      ui.settingsExportButton.textContent = t("settings_export");
      ui.settingsExportButton.disabled = locked || state.settingsLockBusy;
    }
    if (ui.settingsImportButton) {
      ui.settingsImportButton.textContent = t("settings_import");
      ui.settingsImportButton.disabled = locked || state.settingsLockBusy;
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
    if (ui.settingsUnlockForm) {
      ui.settingsUnlockForm.hidden = !enabled || !locked;
    }
    if (ui.settingsLockSetupForm) {
      ui.settingsLockSetupForm.hidden = enabled;
    }
    if (ui.settingsMasterPassword) {
      ui.settingsMasterPassword.disabled = !enabled || !locked || state.settingsLockBusy;
    }
    [ui.settingsNewMasterPassword, ui.settingsConfirmMasterPassword].forEach((input) => {
      if (input) {
        input.disabled = enabled || state.settingsLockBusy;
      }
    });

    [ui.channelId, ui.password, ui.senderId, ui.txCodec, ui.receiveOnly].forEach((element) => {
      if (element) {
        element.disabled = locked;
      }
    });
    applySensitiveRelayMasking(locked);
    if (ui.advancedSettingsDetails) {
      ui.advancedSettingsDetails.hidden = locked;
      if (locked) {
        ui.advancedSettingsDetails.open = false;
      }
    }
    if (ui.cueSettingsCard) {
      ui.cueSettingsCard.hidden = locked;
    }
    if (ui.audioTxSettingsCard) {
      ui.audioTxSettingsCard.hidden = locked;
    }

    if (!preserveStatus) {
      if (!enabled) {
        setSettingsLockStatus(t("settings_disabled_message"));
      } else {
        setSettingsLockStatus(t(locked ? "settings_locked_message" : "settings_unlocked_message"));
      }
    }
  }

  function portableSettingsSnapshot() {
    persistFormSettings();
    const stored = readStoredSettings();
    const settings = {};
    portableSettingsKeys.forEach((key) => {
      const value = stored[key];
      if (["string", "number", "boolean"].includes(typeof value)) settings[key] = value;
    });
    // Local cue/audio files live in IndexedDB and are deliberately not exported.
    delete settings.password;
    return settings;
  }

  function downloadPortableSettings() {
    if (isSettingsLocked()) return;
    const documentData = {
      format: "incomudon-pwa-settings",
      version: 1,
      page: isEmbeddedSlot ? "multi-slot" : "single",
      exportedAt: new Date().toISOString(),
      settings: portableSettingsSnapshot(),
    };
    const blob = new Blob([JSON.stringify(documentData, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = t("settings_export_file");
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(href), 0);
  }

  function importPortableSettingsDocument(documentData) {
    if (!documentData || documentData.format !== "incomudon-pwa-settings" ||
        documentData.version !== 1 || !documentData.settings || typeof documentData.settings !== "object") {
      throw new Error(t("settings_import_invalid"));
    }
    const next = { ...readStoredSettings() };
    portableSettingsKeys.forEach((key) => {
      const value = documentData.settings[key];
      if (["string", "number", "boolean"].includes(typeof value)) next[key] = value;
    });
    delete next.password;
    localStorage.setItem(settingsStorageKey, JSON.stringify(next));
  }

  async function importPortableSettingsFile(file) {
    if (isSettingsLocked() || !file) return;
    try {
      const parsed = JSON.parse(await file.text());
      importPortableSettingsDocument(parsed);
      window.alert(t("settings_imported"));
      window.location.reload();
    } catch (err) {
      const message = err && err.message ? err.message : String(err || "");
      window.alert(message === t("settings_import_invalid")
        ? message
        : t("settings_import_failed", { error: message }));
    }
  }

  function bindSettingsLockControls() {
    const setBusy = (busy, preserveStatus = false) => {
      state.settingsLockBusy = busy;
      applySettingsLockState(preserveStatus);
    };

    const enableSettingsLock = async () => {
      if (isSettingsLockEnabled() || state.settingsLockBusy) {
        return;
      }
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
      if (!isSettingsLocked() || state.settingsLockBusy) {
        return;
      }
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
      if (!isSettingsLockEnabled() || state.settingsLockBusy) {
        return;
      }
      state.settingsUnlocked = false;
      clearSettingsUnlockSession();
      clearSettingsLockInputs();
      applySettingsLockState();
    };

    const disableSettingsLock = () => {
      if (!isSettingsLockEnabled() || isSettingsLocked() || state.settingsLockBusy) {
        return;
      }
      if (!window.confirm(t("settings_disable_confirm"))) {
        return;
      }
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
    ui.settingsExportButton?.addEventListener("click", downloadPortableSettings);
    ui.settingsImportButton?.addEventListener("click", () => ui.settingsImportFile?.click());
    ui.settingsImportFile?.addEventListener("change", () => {
      const file = ui.settingsImportFile.files && ui.settingsImportFile.files[0];
      ui.settingsImportFile.value = "";
      void importPortableSettingsFile(file);
    });
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
    setText("headingAdvancedSettings", t("advanced_settings"));
    setText("labelCryptoMode", t("crypto_mode"));
    setText("labelCodecMode", t("codec_mode"));
    setText("labelBrowserCodec", t("browser_codec"));
    setText("labelWsToken", t("ws_token"));
    setText("labelTxCodec", t("tx_codec"));
    setText("labelMicVolume", t("mic_volume"));
    setText("labelReceiveOnly", t("receive_only"));
    setText("labelSelfSenderMute", t("self_sender_mute"));
    setText("labelQosEnabled", t("qos_enabled"));
    setText("labelFecEnabled", t("fec_enabled"));
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
    setText("headingPacketDebug", t("packet_debug"));
    setText("packetDebugReset", t("packet_debug_reset"));
    updatePttButtonLabel();
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
    refreshCueFileStatuses();
    setText("cuePttOnTest", t("test"));
    setText("cuePttOffTest", t("test"));
    setText("cueCarrierTest", t("test"));
    setText("cuePttOnReset", t("default"));
    setText("cuePttOffReset", t("default"));
    setText("cueCarrierReset", t("default"));
    setText("headingAudioTx", t("audio_tx_files"));
    setText("labelAudioTxSlotCount", t("audio_tx_slot_count"));
    setText("labelAudioTxLoopEnabled", t("audio_tx_loop"));
    setText("clearSavedMediaBtn", t("media_clear_saved"));
    setText("headingEvents", t("events"));
    setText("clearLogBtn", t("clear"));
    applyPasswordInputPresentation();
    updateMicVolumeDisplay();

    updateTalkerStatus(state.activeTalkers, state.talkAllowed);
    applyConnectionView();
    refreshAudioTxSlotsUI();
    applySettingsLockState();
    refreshPacketDebugView();
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

  function applyReceiveOnlyFromUI(stopTransmission) {
    const enabled = !!(ui.receiveOnly && ui.receiveOnly.checked);
    const changed = state.receiveOnly !== enabled;
    state.receiveOnly = enabled;
    if (enabled && stopTransmission) {
      const wasTransmitting = state.pttPressed;
      cancelAudioTxTask(true);
      if (wasTransmitting && state.pttPressed) {
        void setPTT(false);
      }
    }
    refreshPTTAvailability();
    refreshAudioTxSlotsUI();
    updatePttButtonLabel();
    if (changed) {
      notifyEmbeddedSlotState();
    }
  }

  function applySelfSenderMuteFromUI() {
    const enabled = ui.selfSenderMute ? !!ui.selfSenderMute.checked : true;
    const changed = state.selfSenderMute !== enabled;
    state.selfSenderMute = enabled;
    if (changed && state.connected) {
      sendCommand({ type: "set_self_mute", selfMute: enabled });
    }
    if (changed) {
      notifyEmbeddedSlotState();
    }
  }

  function refreshPTTAvailability() {
    ui.pttButton.disabled = !state.connected || state.micPermissionDenied || state.receiveOnly;
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

  function bitrateOptionLabel(value, txCodec) {
    if (normalizeTxCodec(txCodec) !== txCodecOpus) {
      return String(value);
    }
    const kbps = value / 1000;
    const label = Number.isInteger(kbps) ? String(kbps) : kbps.toFixed(1);
    return `${label} kbps`;
  }

  function normalizeBitrateForTxCodec(rawValue, txCodec) {
    const normalizedTxCodec = normalizeTxCodec(txCodec);
    const rawText = rawValue === undefined || rawValue === null ? "" : rawValue;
    const parsed = Number.parseInt(String(rawText), 10);
    let value = Number.isFinite(parsed) ? parsed : 0;

    if (normalizedTxCodec === txCodecOpus) {
      if (value <= 0) {
        value = defaultOpusBitrate;
      }
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

  function formatBitrateKbps(value) {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return "0";
    }
    const kbps = parsed / 1000;
    return Number.isInteger(kbps) ? String(kbps) : kbps.toFixed(1);
  }

  function resolveBrowserUplinkOpusBitrate(txCodec, codecMode) {
    if (normalizeTxCodec(txCodec) !== txCodecOpus) {
      return 20000;
    }
    return normalizeBitrateForTxCodec(codecMode, txCodecOpus);
  }

  function syncCodecModeOptions(preferredValue, forceOpusDefault = false) {
    if (!ui.codecMode) {
      return;
    }

    const selectedTxCodec = normalizeTxCodec(ui.txCodec ? ui.txCodec.value : state.txCodec);
    const options = bitrateOptionsForTxCodec(selectedTxCodec);
    let currentValue = preferredValue !== undefined ? preferredValue : ui.codecMode.value;
    if (forceOpusDefault && preferredValue === undefined && selectedTxCodec === txCodecOpus) {
      currentValue = defaultOpusBitrate;
    }
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
        option.textContent = bitrateOptionLabel(value, selectedTxCodec);
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
    const previous = state.txCodec;

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
    const switchedToOpus = previous !== txCodecOpus && selected === txCodecOpus;
    syncCodecModeOptions(preferredCodecMode, switchedToOpus);
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

  function sensitiveRelayValue(key, input) {
    if (input && input.dataset.lockMasked === "1") {
      return String(state.hiddenRelaySettings[key] || "").trim();
    }
    return String(input ? input.value : "").trim();
  }

  function currentRelayHost() {
    return sensitiveRelayValue("relayHost", ui.relayHost);
  }

  function currentRelayPort() {
    const value = sensitiveRelayValue("relayPort", ui.relayPort);
    return Number.parseInt(value, 10);
  }

  function applySensitiveRelayMasking(locked) {
    const fields = [
      ["relayHost", ui.relayHost],
      ["relayPort", ui.relayPort],
      ["wsToken", ui.wsToken],
    ];
    fields.forEach(([key, input]) => {
      if (!input) return;
      if (locked) {
        if (input.dataset.lockMasked !== "1") {
          state.hiddenRelaySettings[key] = String(input.value || "");
          input.value = "";
          input.defaultValue = "";
          input.dataset.lockMasked = "1";
        }
        input.placeholder = t("settings_value_hidden");
      } else if (input.dataset.lockMasked === "1") {
        input.value = String(state.hiddenRelaySettings[key] || "");
        input.defaultValue = "";
        input.placeholder = "";
        delete input.dataset.lockMasked;
      }
    });
  }

  function initializeWSToken(overrides = startupQueryOverrides) {
    const fromQuery = overrides && overrides.hasWsToken
      ? String(overrides.wsToken || "").trim()
      : "";
    if (fromQuery) {
      persistLegacyWSToken(fromQuery);
      return fromQuery;
    }
    const storedSettings = readStoredSettings();
    if (storedSettings && typeof storedSettings.wsToken === "string") {
      const storedToken = String(storedSettings.wsToken || "").trim();
      if (storedToken) {
        return storedToken;
      }
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

  function currentWSToken() {
    if (ui.wsToken) {
      return sensitiveRelayValue("wsToken", ui.wsToken);
    }
    return String(initialWSToken || "").trim();
  }

  function persistLegacyWSToken(value) {
    const token = String(value || "").trim();
    try {
      if (token) {
        localStorage.setItem(wsTokenStorageKey, token);
      } else {
        localStorage.removeItem(wsTokenStorageKey);
      }
    } catch (_) {
      // Ignore storage errors.
    }
    try {
      if (token) {
        sessionStorage.setItem(wsTokenStorageKey, token);
      } else {
        sessionStorage.removeItem(wsTokenStorageKey);
      }
    } catch (_) {
      // Ignore storage errors.
    }
  }

  function firstQueryValue(params, names) {
    if (!(params instanceof URLSearchParams) || !Array.isArray(names)) {
      return "";
    }
    for (let i = 0; i < names.length; i += 1) {
      const value = String(params.get(names[i]) || "").trim();
      if (value) {
        return value;
      }
    }
    return "";
  }

  function readStartupQueryOverrides() {
    const params = new URLSearchParams(window.location.search || "");
    const wsToken = firstQueryValue(params, ["ws_token", "token"]);
    const rawChannelId = firstQueryValue(params, ["channel_id", "channelId", "channel"]);
    const password = firstQueryValue(params, ["password", "pass", "pw"]);
    const rawTxCodec = firstQueryValue(params, ["tx_codec", "txCodec", "codec"]);
    const parsedChannelId = Number.parseInt(rawChannelId, 10);
    const channelId = Number.isInteger(parsedChannelId) && parsedChannelId > 0
      ? String(parsedChannelId)
      : "";
    const normalizedTxCodec = String(rawTxCodec || "").trim().toLowerCase();
    const txCodec =
      normalizedTxCodec === txCodecPCM ||
      normalizedTxCodec === txCodecCodec2 ||
      normalizedTxCodec === txCodecOpus
        ? normalizedTxCodec
        : "";

    return {
      wsToken,
      hasWsToken: wsToken !== "",
      channelId,
      hasChannelId: channelId !== "",
      password,
      hasPassword: password !== "",
      txCodec,
      hasTxCodec: txCodec !== "",
    };
  }

  function applyStartupQueryOverrides(settings) {
    if (!settings || typeof settings !== "object") {
      return;
    }
    if (startupQueryOverrides.hasChannelId) {
      settings.channelId = startupQueryOverrides.channelId;
    }
    if (startupQueryOverrides.hasPassword) {
      settings.password = startupQueryOverrides.password;
      settings.passwordHash = "";
    }
    if (startupQueryOverrides.hasTxCodec) {
      settings.txCodec = startupQueryOverrides.txCodec;
    }
    if (startupQueryOverrides.hasWsToken) {
      settings.wsToken = startupQueryOverrides.wsToken;
    }
  }

  function sanitizeStartupURLQuery() {
    const currentSearch = String(window.location.search || "");
    if (!currentSearch) {
      return;
    }
    if (!window.history || typeof window.history.replaceState !== "function") {
      return;
    }

    const url = new URL(window.location.href);
    url.search = "";
    if (startupQueryOverrides.hasWsToken) {
      url.searchParams.set("ws_token", startupQueryOverrides.wsToken);
    }
    if (state.packetDebugEnabled) {
      // Keep this opt-in diagnostic query across a reload. Unlike credentials,
      // it is safe to retain and is needed to restart the monitor.
      url.searchParams.set("packet_debug", "1");
    }
    if (isEmbeddedSlot) {
      url.searchParams.set("embed", "1");
      url.searchParams.set("slot", String(embeddedSlotIndex));
    }

    const next = `${url.pathname}${url.search}${url.hash}`;
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (next === current) {
      return;
    }

    window.history.replaceState(window.history.state, "", next);
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
    const normalizedLevel = normalizeLevel(level);
    notifyEmbeddedLog(text, normalizedLevel);
    const ts = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = normalizedLevel;
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
      releaseKeyboardFocus();
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

  async function setPTT(pressed, emitCue = true, force = false) {
    if (pressed && state.receiveOnly) {
      return;
    }
    if (!pressed) {
      clearExpectedLocalTalkRelease();
    }
    if (pressed && (state.audioTxTask || hasPendingAudioTxLoad())) {
      expectLocalTalkRelease();
      cancelAudioTxTask(true);
    }
    if (pressed && state.micPermissionDenied && !force) {
      return;
    }
    if (state.pttPressed === pressed) {
      syncTxTimeoutCountdownState();
      return;
    }
    state.pttPressed = pressed;
    if (pressed) {
      beginTxSession();
    } else {
      invalidateTxSession();
    }
    ui.pttButton.classList.toggle("active", pressed);
    updatePttButtonLabel();

    if (!state.connected) {
      state.pttPressed = false;
      ui.pttButton.classList.remove("active");
      stopTxTimeoutCountdown();
      notifyEmbeddedSlotState();
      return;
    }

    if (pressed && !force) {
      if (!(await ensureAuthSessionBeforeTransmit("ptt"))) {
        return;
      }
      if (!state.connected || !state.pttPressed) {
        return;
      }
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
      state.txFrameIndex = 0;
      stopTxTimeoutCountdown();
    }

    sendCommand({ type: "ptt", pressed });
    syncTxTimeoutCountdownState();
    notifyEmbeddedSlotState();
  }

  class MicCapture {
    constructor(onFrame, gainPercent = micVolumeDefaultPercent) {
      this.onFrame = onFrame;
      this.ctx = null;
      this.stream = null;
      this.source = null;
      this.inputGain = null;
      this.processor = null;
      this.workletNode = null;
      this.silence = null;
      this.started = false;
      this.gainPercent = normalizeMicVolumePercent(gainPercent);

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
      this.ctx.addEventListener("statechange", () => {
        audioDebug("microphone-context-state", {
          state: this.ctx ? this.ctx.state : "closed",
          currentTime: this.ctx ? this.ctx.currentTime : 0,
        });
      });
      this.downsampleRatio = this.ctx.sampleRate / 8000;

      this.source = this.ctx.createMediaStreamSource(this.stream);
      this.inputGain = this.ctx.createGain();
      this.inputGain.gain.value = this.gainPercent / 100;
      this.silence = this.ctx.createGain();
      this.silence.gain.value = 0;
      this.source.connect(this.inputGain);

      const workletReady = await this.tryStartWithWorklet();
      if (workletReady) {
        this.started = true;
        return;
      }

      this.processor = this.ctx.createScriptProcessor(2048, 1, 1);

      this.inputGain.connect(this.processor);
      this.processor.connect(this.silence);
      this.silence.connect(this.ctx.destination);

      this.processor.onaudioprocess = (event) => {
        const input = event.inputBuffer.getChannelData(0);
        this.pushInput(input);
      };

      this.started = true;
    }

    async tryStartWithWorklet() {
      if (!this.ctx || !this.inputGain || !this.silence) {
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

        this.inputGain.connect(this.workletNode);
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
      const frame = int16ToPCMBytes(samples.subarray(0, 160));
      recordAudioActivity("mic-generated", { bytes: frame.byteLength });
      this.onFrame(frame);
    }

    async resume() {
      if (!this.ctx) {
        return;
      }
      if (this.ctx.state === "suspended") {
        await this.ctx.resume();
      }
    }

    setGainPercent(percent) {
      this.gainPercent = normalizeMicVolumePercent(percent);
      if (this.inputGain) {
        this.inputGain.gain.value = this.gainPercent / 100;
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
      if (this.inputGain) {
        this.inputGain.disconnect();
        this.inputGain = null;
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
        recordAudioActivity("mic-generated", { bytes: frameBytes.byteLength });
        this.onFrame(frameBytes);
      }
      if (this.pcmStart > 2048 && this.pcmStart * 2 >= this.pcmBuffer.length) {
        this.pcmBuffer = this.pcmBuffer.slice(this.pcmStart);
        this.pcmStart = 0;
      }
    }
  }

  class OpusUplinkEncoder {
    constructor(onPacket, targetBitrate) {
      this.onPacket = onPacket;
      this.encoder = null;
      this.started = false;
      this.timestampUs = 0;
      this.packetContexts = [];
      this.sampleRate = 8000;
      this.channels = 1;
      const parsedBitrate = Number.parseInt(String(targetBitrate ?? ""), 10);
      this.targetBitrate = Number.isFinite(parsedBitrate) && parsedBitrate > 0 ? parsedBitrate : 20000;
      this.configuredBitrate = 0;
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

      let config = {
        codec: "opus",
        sampleRate: this.sampleRate,
        numberOfChannels: this.channels,
        bitrate: this.targetBitrate,
      };

      let support = await AudioEncoder.isConfigSupported(config);
      if ((!support || !support.supported) && this.targetBitrate !== 20000) {
        config = {
          ...config,
          bitrate: 20000,
        };
        support = await AudioEncoder.isConfigSupported(config);
      }
      if (!support || !support.supported) {
        throw new Error("Opus AudioEncoder configuration is not supported");
      }

      this.encoder = new AudioEncoder({
        output: (chunk) => {
          const bytes = new Uint8Array(chunk.byteLength);
          chunk.copyTo(bytes);
          const packetContext = this.packetContexts.length > 0
            ? this.packetContexts.shift()
            : null;
          if (packetContext === null) {
            // Do not let an output emitted after a closed/reset encoder cross
            // a PTT boundary. Every accepted source frame carries a session.
            noteDroppedTxFrame("opus-output-without-context");
            return;
          }
          this.onPacket(bytes, packetContext);
        },
        error: (err) => {
          appendLog(t("log_opus_encoder_error", { error: err.message || err }), "warn");
        },
      });
      this.encoder.configure(config);
      this.timestampUs = 0;
      this.configuredBitrate = Number.parseInt(String(config.bitrate), 10) || this.targetBitrate;
      this.started = true;
    }

    getConfiguredBitrate() {
      if (this.configuredBitrate > 0) {
        return this.configuredBitrate;
      }
      return this.targetBitrate;
    }

    queueSize() {
      return this.encoder ? Math.max(0, Number(this.encoder.encodeQueueSize || 0)) : 0;
    }

    isBackpressured() {
      return this.queueSize() >= txOpusMaxQueuedFrames;
    }

    encodeFrame(pcmFrame, packetContext = null) {
      if (!this.started || !this.encoder) {
        return false;
      }
      if (!pcmFrame || pcmFrame.length < 2) {
        return false;
      }

      const frameBytes = new Uint8Array(pcmFrame.length);
      frameBytes.set(pcmFrame);
      const frameSamples = Math.floor(frameBytes.length / 2);
      if (frameSamples <= 0) {
        return false;
      }

      const audioData = new AudioData({
        format: "s16",
        sampleRate: this.sampleRate,
        numberOfFrames: frameSamples,
        numberOfChannels: this.channels,
        timestamp: this.timestampUs,
        data: frameBytes,
      });

      this.packetContexts.push(packetContext);
      try {
        this.encoder.encode(audioData);
        this.timestampUs += Math.round((frameSamples * 1000000) / this.sampleRate);
        return true;
      } catch (_) {
        this.packetContexts.pop();
        return false;
      } finally {
        audioData.close();
      }
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
        this.packetContexts = [];
        this.configuredBitrate = 0;
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
      this.packetContexts = [];
      this.configuredBitrate = 0;
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
          if (shouldIgnoreOpusDecoderError(err)) {
            return;
          }
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
        if (shouldIgnoreOpusDecoderError(err)) {
          return;
        }
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
        if (shouldIgnoreOpusDecoderError(err)) {
          return;
        }
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

  function shouldIgnoreOpusDecoderError(err) {
    const text = String((err && err.message) ? err.message : err || "").toLowerCase();
    if (!text) {
      return false;
    }
    if (!state.connected) {
      return true;
    }
    return text.includes("closed codec") || text.includes("closed decoder");
  }

  class PCMPlayer {
    constructor() {
      this.ctx = null;
      this.nextPlayTime = 0;
      this.isAndroid = isAndroidBrowser();
      // Chrome Desktop used to schedule one short AudioBufferSourceNode per
      // packet. Use the same continuous AudioWorklet stream on every platform.
      this.streamMode = true;
      this.streamModeKind = "none";
      this.streamInitPromise = null;
      this.workletInitAttempted = false;
      this.workletNode = null;
      this.streamNode = null;
      this.streamSourceRate = 8000;
      this.streamPrimeSamples = this.isAndroid ? 1280 : 640;
      this.streamMaxSamples = this.isAndroid ? 12000 : 6000;
      this.workletStats = {
        bufferedSamples: 0,
        sourceSampleRate: 8000,
        primed: false,
        underrunBlocks: 0,
        underrunEvents: 0,
        droppedSamples: 0,
      };

      this.pendingRawChunks = [];
      this.pendingRawSamples = 0;
      this.scriptChunks = [];
      this.scriptOffset = 0;
      this.scriptBufferedSamples = 0;
      this.scriptPrimed = false;
      this.scriptHoldSample = 0;
      this.scriptUnderrunBlocks = 0;
      this.pendingDroppedSamples = 0;
      this.scriptDroppedSamples = 0;
      this.resampleFromRate = 0;
      this.resamplePos = 0;
      this.prevInputSample = 0;
      this.hasPrevInputSample = false;

      this.startupLeadSec = 0.05;
      this.catchupLeadSec = 0.03;
      this.softLagSec = -0.02;
      this.hardLagSec = -0.12;
      this.maxLeadSec = 0.8;
      this.declickSamples = 0;
      this.prevTailSample = 0;
      this.hasPrevTailSample = false;
      this.keepAliveSource = null;
      this.keepAliveGain = null;
      this.lastResumeAttemptMs = 0;
      this.muted = false;
      this.directSources = new Set();
    }

    setMuted(muted) {
      const next = !!muted;
      if (this.muted === next) {
        return;
      }
      this.muted = next;
      if (next) {
        this.stopDirectSources();
        this.resetTimeline();
      }
    }

    ensureContext() {
      if (this.ctx) {
        return this.ctx;
      }
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) {
        return null;
      }
      this.ctx = new AudioContextClass();
      this.ctx.addEventListener("statechange", () => {
        audioDebug("playback-context-state", {
          state: this.ctx ? this.ctx.state : "closed",
          currentTime: this.ctx ? this.ctx.currentTime : 0,
        });
      });
      return this.ctx;
    }

    async resume() {
      const ctx = this.ensureContext();
      if (!ctx) {
        throw new Error("Web Audio API is unavailable");
      }
      if (ctx.state !== "running") {
        await ctx.resume();
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
          const source = this.ctx.createConstantSource();
          source.offset.value = 0;
          source.connect(gain);
          source.start();
          this.keepAliveSource = source;
        } else {
          const oscillator = this.ctx.createOscillator();
          oscillator.type = "sine";
          oscillator.frequency.value = 18;
          oscillator.connect(gain);
          oscillator.start();
          this.keepAliveSource = oscillator;
        }
        this.keepAliveGain = gain;
      } catch (_) {
        // Keep playback usable even if the silent keep-alive source is absent.
      }
    }

    resumeIfNeeded() {
      if (!this.ctx || String(this.ctx.state || "") === "running") {
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
          return this.ensureStreamOutput();
        })
        .catch(() => {});
    }

    async ensureStreamOutput() {
      if (!this.streamMode || !this.ctx || this.streamModeKind !== "none") {
        return;
      }
      if (this.streamInitPromise) {
        return this.streamInitPromise;
      }
      this.streamInitPromise = this.initializeStreamOutput()
        .finally(() => {
          this.streamInitPromise = null;
        });
      return this.streamInitPromise;
    }

    async initializeStreamOutput() {
      if (!this.ctx) {
        return;
      }
      if (!this.workletInitAttempted && this.ctx.audioWorklet && typeof AudioWorkletNode !== "undefined") {
        this.workletInitAttempted = true;
        try {
          await this.ctx.audioWorklet.addModule(resolveWorkletURL("pcm-playback-worklet.js"));
          const node = new AudioWorkletNode(this.ctx, "incomudon-pcm-playback", {
            numberOfInputs: 0,
            numberOfOutputs: 1,
            outputChannelCount: [1],
          });
          node.port.onmessage = (event) => this.handleWorkletMessage(event && event.data);
          node.connect(this.ctx.destination);
          this.workletNode = node;
          this.streamModeKind = "worklet";
          this.configureWorklet(this.streamSourceRate);
          this.flushPendingRawSamples();
          audioDebug("playback-stream", { mode: "AudioWorklet" });
          return;
        } catch (err) {
          audioDebug("playback-worklet-unavailable", {
            error: err && err.message ? err.message : String(err),
          });
          if (this.workletNode) {
            try {
              this.workletNode.disconnect();
            } catch (_) {
              // Ignore an already disconnected node.
            }
            this.workletNode = null;
          }
        }
      }

      if (typeof this.ctx.createScriptProcessor === "function") {
        const node = this.ctx.createScriptProcessor(2048, 1, 1);
        node.onaudioprocess = (event) => {
          this.fillScriptOutput(event.outputBuffer.getChannelData(0));
        };
        node.connect(this.ctx.destination);
        this.streamNode = node;
        this.streamModeKind = "script";
        this.flushPendingRawSamples();
        audioDebug("playback-stream", { mode: "ScriptProcessor-fallback" });
        return;
      }

      // Very old browsers retain native AudioBufferSourceNode resampling as a
      // compatibility fallback. Modern Chrome follows the AudioWorklet path.
      this.streamMode = false;
      this.flushPendingRawSamples();
      audioDebug("playback-stream", { mode: "native-buffer-fallback" });
    }

    configureWorklet(sourceSampleRate) {
      if (!this.workletNode) {
        return;
      }
      this.streamSourceRate = Math.max(1, Number(sourceSampleRate) || 8000);
      this.workletNode.port.postMessage({
        type: "config",
        sourceSampleRate: this.streamSourceRate,
        primeSamples: this.streamPrimeSamples,
        maxSamples: this.streamMaxSamples,
      });
    }

    handleWorkletMessage(message) {
      if (!message || message.type !== "stats") {
        return;
      }
      const previousUnderruns = this.workletStats.underrunEvents;
      this.workletStats = {
        bufferedSamples: Math.max(0, Number(message.bufferedSamples) || 0),
        sourceSampleRate: Math.max(0, Number(message.sourceSampleRate) || 0),
        primed: !!message.primed,
        underrunBlocks: Math.max(0, Number(message.underrunBlocks) || 0),
        underrunEvents: Math.max(0, Number(message.underrunEvents) || 0),
        droppedSamples: Math.max(0, Number(message.droppedSamples) || 0),
      };
      if (state.audioDebugEnabled && this.workletStats.underrunEvents > previousUnderruns) {
        audioDebug("playback-underrun", this.workletStats);
      }
    }

    resetTimeline() {
      this.nextPlayTime = 0;
      this.prevTailSample = 0;
      this.hasPrevTailSample = false;
      this.resampleFromRate = 0;
      this.resamplePos = 0;
      this.prevInputSample = 0;
      this.hasPrevInputSample = false;
      this.pendingRawChunks = [];
      this.pendingRawSamples = 0;
      this.scriptChunks = [];
      this.scriptOffset = 0;
      this.scriptBufferedSamples = 0;
      this.scriptPrimed = false;
      this.scriptHoldSample = 0;
      this.scriptUnderrunBlocks = 0;
      if (this.workletNode) {
        try {
          this.workletNode.port.postMessage({ type: "reset" });
        } catch (_) {
          // Ignore a worklet that was torn down with the context.
        }
      }
    }

    resetDebugStats() {
      this.pendingDroppedSamples = 0;
      this.scriptDroppedSamples = 0;
      if (this.workletNode) {
        try {
          this.workletNode.port.postMessage({ type: "debug-reset" });
        } catch (_) {
          // A diagnostic reset must not alter the active audio stream.
        }
      }
    }

    stopDirectSources() {
      this.directSources.forEach((source) => {
        try {
          source.stop();
        } catch (_) {
          // Sources may already have completed.
        }
      });
      this.directSources.clear();
    }

    queuePendingRawSamples(samples, sampleRate) {
      if (!samples || samples.length <= 0) {
        return;
      }
      this.pendingRawChunks.push({ samples, sampleRate });
      this.pendingRawSamples += samples.length;
      while (this.pendingRawSamples > this.streamMaxSamples && this.pendingRawChunks.length > 0) {
        const dropped = this.pendingRawChunks.shift();
        this.pendingRawSamples -= dropped.samples.length;
        this.pendingDroppedSamples += dropped.samples.length;
      }
    }

    flushPendingRawSamples() {
      const pending = this.pendingRawChunks;
      this.pendingRawChunks = [];
      this.pendingRawSamples = 0;
      pending.forEach((entry) => {
        if (!entry || !entry.samples || entry.samples.length <= 0) {
          return;
        }
        if (this.streamModeKind === "worklet") {
          this.sendWorkletSamples(entry.samples, entry.sampleRate);
        } else if (this.streamModeKind === "script") {
          const output = this.resampleContinuous(entry.samples, entry.sampleRate, this.ctx.sampleRate);
          this.enqueueScriptSamples(output);
        } else {
          this.scheduleDirectSamples(entry.samples, entry.sampleRate);
        }
      });
    }

    sendWorkletSamples(samples, sourceSampleRate) {
      if (!this.workletNode || !samples || samples.length <= 0) {
        return;
      }
      const sourceRate = Math.max(1, Number(sourceSampleRate) || 8000);
      if (sourceRate !== this.streamSourceRate) {
        // The relay currently always sends 8 kHz. Reset rather than blending
        // incompatible clocks should a future codec supply a different rate.
        this.configureWorklet(sourceRate);
      }
      try {
        this.workletNode.port.postMessage({ type: "pcm", samples }, [samples.buffer]);
      } catch (err) {
        audioDebug("playback-worklet-post-failed", {
          error: err && err.message ? err.message : String(err),
        });
      }
    }

    enqueueRawStreamSamples(samples, sourceSampleRate) {
      if (this.streamModeKind === "worklet") {
        this.sendWorkletSamples(samples, sourceSampleRate);
        return;
      }
      if (this.streamModeKind === "script") {
        const output = this.resampleContinuous(samples, sourceSampleRate, this.ctx.sampleRate);
        this.enqueueScriptSamples(output);
        return;
      }
      if (this.streamMode) {
        this.queuePendingRawSamples(samples, sourceSampleRate);
        return;
      }
      this.scheduleDirectSamples(samples, sourceSampleRate);
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

      const sampleAt = (idx, previous, source) => {
        if (idx <= 0) return previous;
        const sourceIndex = idx - 1;
        if (sourceIndex < 0) return previous;
        if (sourceIndex >= source.length) return source[source.length - 1];
        return source[sourceIndex];
      };
      if (!this.hasPrevInputSample || this.resampleFromRate !== fromRate) {
        this.resampleFromRate = fromRate;
        this.resamplePos = 0;
        this.prevInputSample = input[0];
        this.hasPrevInputSample = true;
      }

      const previous = this.prevInputSample;
      const step = fromRate / toRate;
      const extendedLength = input.length + 1;
      let position = this.resamplePos;
      if (!Number.isFinite(position) || position < 0 || position >= extendedLength - 1) {
        position = 0;
      }
      const output = new Float32Array(Math.max(1, Math.ceil((extendedLength - 1 - position) / step) + 1));
      let outputLength = 0;
      while (position + 1 < extendedLength && outputLength < output.length) {
        const i0 = Math.floor(position);
        const fraction = position - i0;
        const a = sampleAt(i0, previous, input);
        const b = sampleAt(i0 + 1, previous, input);
        output[outputLength] = a + ((b - a) * fraction);
        outputLength += 1;
        position += step;
      }
      this.resamplePos = position - input.length;
      if (!Number.isFinite(this.resamplePos) || this.resamplePos < 0 || this.resamplePos > 1) {
        this.resamplePos = 0;
      }
      this.prevInputSample = input[input.length - 1];
      this.hasPrevInputSample = true;
      return outputLength === output.length ? output : output.slice(0, outputLength);
    }

    enqueueScriptSamples(samples) {
      if (!samples || samples.length <= 0) {
        return;
      }
      let overflow = (this.scriptBufferedSamples + samples.length) - this.streamMaxSamples;
      while (overflow > 0 && this.scriptChunks.length > 0) {
        const head = this.scriptChunks[0];
        const available = head.length - this.scriptOffset;
        if (available <= overflow) {
          this.scriptChunks.shift();
          this.scriptOffset = 0;
          this.scriptBufferedSamples -= available;
          this.scriptDroppedSamples += available;
          overflow -= available;
        } else {
          this.scriptOffset += overflow;
          this.scriptBufferedSamples -= overflow;
          this.scriptDroppedSamples += overflow;
          overflow = 0;
        }
      }
      this.scriptChunks.push(samples);
      this.scriptBufferedSamples += samples.length;
      this.scriptUnderrunBlocks = 0;
    }

    fillScriptOutput(output) {
      output.fill(0);
      if (!this.scriptPrimed) {
        if (this.scriptBufferedSamples < this.streamPrimeSamples) {
          return;
        }
        this.scriptPrimed = true;
      }
      let write = 0;
      while (write < output.length && this.scriptChunks.length > 0) {
        const head = this.scriptChunks[0];
        const available = head.length - this.scriptOffset;
        if (available <= 0) {
          this.scriptChunks.shift();
          this.scriptOffset = 0;
          continue;
        }
        const count = Math.min(available, output.length - write);
        output.set(head.subarray(this.scriptOffset, this.scriptOffset + count), write);
        write += count;
        this.scriptOffset += count;
        this.scriptBufferedSamples -= count;
        if (this.scriptOffset >= head.length) {
          this.scriptChunks.shift();
          this.scriptOffset = 0;
        }
      }
      if (write > 0) {
        this.scriptHoldSample = output[write - 1];
      }
      if (write < output.length) {
        let hold = this.scriptHoldSample;
        for (let i = write; i < output.length; i += 1) {
          output[i] = hold;
          hold *= 0.999;
        }
        this.scriptHoldSample = hold;
        this.scriptUnderrunBlocks += 1;
        if (this.scriptUnderrunBlocks >= 8) {
          this.scriptPrimed = false;
        }
      } else {
        this.scriptUnderrunBlocks = 0;
      }
    }

    scheduleDirectSamples(samples, sourceRate) {
      if (!this.ctx || !samples || samples.length <= 0) {
        return;
      }
      const output = samples;
      if (this.declickSamples > 0 && this.hasPrevTailSample) {
        const blendCount = Math.min(this.declickSamples, output.length);
        const previous = this.prevTailSample;
        for (let i = 0; i < blendCount; i += 1) {
          const ratio = (i + 1) / (blendCount + 1);
          output[i] = previous + ((output[i] - previous) * ratio);
        }
      }
      this.prevTailSample = output[output.length - 1];
      this.hasPrevTailSample = true;

      const now = this.ctx.currentTime;
      const lead = this.nextPlayTime - now;
      if (!Number.isFinite(this.nextPlayTime) || lead < this.hardLagSec || lead > this.maxLeadSec) {
        this.nextPlayTime = now + this.startupLeadSec;
        this.hasPrevTailSample = false;
      } else if (lead < this.softLagSec) {
        this.nextPlayTime = now + this.catchupLeadSec;
      }
      const buffer = this.ctx.createBuffer(1, output.length, sourceRate);
      buffer.copyToChannel(output, 0);
      const source = this.ctx.createBufferSource();
      source.buffer = buffer;
      source.connect(this.ctx.destination);
      this.directSources.add(source);
      source.onended = () => this.directSources.delete(source);
      source.start(this.nextPlayTime);
      this.nextPlayTime += buffer.duration;
    }

    playPCM(bytes, sampleRate = 8000) {
      if (!bytes || bytes.length < 2 || this.muted) {
        return;
      }
      const ctx = this.ensureContext();
      if (!ctx) {
        return;
      }
      this.resumeIfNeeded();
      const sampleCount = Math.floor(bytes.length / 2);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const input = new Float32Array(sampleCount);
      for (let i = 0; i < sampleCount; i += 1) {
        input[i] = view.getInt16(i * 2, true) / 32768;
      }
      const sourceRate = Number(sampleRate) > 0 ? Number(sampleRate) : 8000;
      if (this.streamMode) {
        this.ensureStreamOutput().catch(() => {});
        this.enqueueRawStreamSamples(input, sourceRate);
        return;
      }
      this.scheduleDirectSamples(input, sourceRate);
    }

    debugState() {
      const droppedSamples = this.streamModeKind === "worklet"
        ? Math.max(0, Number(this.workletStats.droppedSamples) || 0)
        : this.pendingDroppedSamples + this.scriptDroppedSamples;
      return {
        contextState: this.ctx ? this.ctx.state : "none",
        currentTime: this.ctx ? this.ctx.currentTime : 0,
        sampleRate: this.ctx ? this.ctx.sampleRate : 0,
        streamMode: this.streamModeKind,
        sourceSampleRate: this.streamSourceRate,
        jitterTargetMs: (this.streamPrimeSamples * 1000) / Math.max(1, this.streamSourceRate),
        jitterMaxMs: (this.streamMaxSamples * 1000) / Math.max(1, this.streamSourceRate),
        pendingRawSamples: this.pendingRawSamples,
        worklet: this.workletStats,
        scriptBufferedSamples: this.scriptBufferedSamples,
        droppedSamples,
      };
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
  if (!isEmbeddedSlot) {
    state.mic = new MicCapture((frame) => {
    if (!state.connected || !state.pttPressed || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    if (state.audioTxTask) {
      return;
    }
    transmitUplinkFrame(frame, "mic");
    }, state.micVolumePercent);
  }
  applyMicVolumeFromUI(state.micVolumePercent, false);
  if (isEmbeddedSlot) {
    window.addEventListener("message", handleEmbeddedSlotMessage);
    document.addEventListener("pointerdown", notifyEmbeddedSlotInteraction, true);
    window.setTimeout(notifyEmbeddedSlotState, 0);
  }
})();
