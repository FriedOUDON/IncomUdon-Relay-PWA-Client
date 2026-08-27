// Uses the AudioContext render clock rather than window timers.  The main
// thread acknowledges each tick so a throttled page never accumulates stale
// ticks that would later burst onto the relay.
class IncomudonAudioTxPacerProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.running = false;
    this.waitingForAck = false;
    this.frameSamples = 160;
    this.sourceSampleRate = 8000;
    this.samplesUntilTick = 0;
    this.port.onmessage = (event) => this.onMessage(event && event.data);
  }

  onMessage(message) {
    if (!message || typeof message !== "object") {
      return;
    }
    if (message.type === "start") {
      this.frameSamples = Math.max(1, Number(message.frameSamples) || 160);
      this.sourceSampleRate = Math.max(1, Number(message.sourceSampleRate) || 8000);
      this.samplesUntilTick = (this.frameSamples * sampleRate) / this.sourceSampleRate;
      this.waitingForAck = false;
      this.running = true;
      return;
    }
    if (message.type === "stop") {
      this.running = false;
      this.waitingForAck = false;
      return;
    }
    if (message.type === "ack" && this.running) {
      this.waitingForAck = false;
      // Preserve render-quantum overshoot. At 48 kHz, 20 ms is 960 samples,
      // while an AudioWorklet quantum is commonly 128 samples. Resetting to
      // 960 after each tick would drift to 21.33 ms and periodically drop a
      // valid frame; adding the period alternates 7/8 quanta around 20 ms.
      this.samplesUntilTick += (this.frameSamples * sampleRate) / this.sourceSampleRate;
      if (!Number.isFinite(this.samplesUntilTick) || this.samplesUntilTick <= 0) {
        this.samplesUntilTick = (this.frameSamples * sampleRate) / this.sourceSampleRate;
      }
    }
  }

  process(inputs, outputs) {
    const output = outputs && outputs[0] && outputs[0][0];
    if (output) {
      output.fill(0);
    }
    if (!this.running || this.waitingForAck) {
      return true;
    }

    const frames = output ? output.length : 128;
    this.samplesUntilTick -= frames;
    if (this.samplesUntilTick > 0) {
      return true;
    }

    this.waitingForAck = true;
    this.port.postMessage({ type: "tick", audioTime: currentTime });
    return true;
  }
}

registerProcessor("incomudon-audio-tx-pacer", IncomudonAudioTxPacerProcessor);
