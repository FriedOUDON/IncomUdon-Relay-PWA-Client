// Continuous 8 kHz PCM stream player. The browser main thread only supplies
// chunks; the AudioWorklet owns pacing, jitter buffering and sample-rate
// conversion so short AudioBufferSourceNode scheduling is not affected by
// hidden-page JavaScript timer throttling.
class IncomudonPCMPlaybackProcessor extends AudioWorkletProcessor {
  constructor() {
    super();

    this.chunks = [];
    this.chunkOffset = 0;
    this.bufferedSamples = 0;
    this.baseSampleIndex = 0;
    this.sourcePosition = 0;
    this.sourceSampleRate = 8000;

    this.primeSamples = 640;
    this.maxSamples = 6000;
    this.primed = false;
    this.holdSample = 0;
    this.underrunBlocks = 0;
    this.underrunEvents = 0;
    this.droppedSamples = 0;
    this.inUnderrun = false;
    this.lastStatsTime = -Infinity;
    this.resampleRadius = 12;

    this.port.onmessage = (event) => {
      this.onMessage(event && event.data);
    };
  }

  onMessage(message) {
    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type === "config") {
      const prime = Math.max(160, Number(message.primeSamples) || this.primeSamples);
      const max = Math.max(prime * 2, Number(message.maxSamples) || this.maxSamples);
      const sourceRate = Math.max(1, Number(message.sourceSampleRate) || this.sourceSampleRate);
      const sourceRateChanged = sourceRate !== this.sourceSampleRate;
      this.primeSamples = prime;
      this.maxSamples = max;
      this.sourceSampleRate = sourceRate;
      if (sourceRateChanged) {
        this.reset();
      }
      return;
    }

    if (message.type === "reset") {
      this.reset();
      return;
    }

    if (message.type === "debug-reset") {
      this.underrunEvents = 0;
      this.droppedSamples = 0;
      this.postStats(true);
      return;
    }

    if (message.type !== "pcm") {
      return;
    }

    let samples = null;
    if (message.samples instanceof Float32Array) {
      samples = message.samples;
    } else if (message.samples instanceof ArrayBuffer) {
      samples = new Float32Array(message.samples);
    } else if (ArrayBuffer.isView(message.samples)) {
      samples = new Float32Array(
        message.samples.buffer,
        message.samples.byteOffset,
        Math.floor(message.samples.byteLength / Float32Array.BYTES_PER_ELEMENT),
      );
    }

    if (!samples || samples.length <= 0) {
      return;
    }

    this.chunks.push(samples);
    this.bufferedSamples += samples.length;
    const overflow = this.bufferedSamples - this.maxSamples;
    if (overflow > 0) {
      // Live audio must catch up instead of replaying an old backlog.
      this.discardSamples(overflow);
      this.droppedSamples += overflow;
      if (this.sourcePosition < this.baseSampleIndex) {
        this.sourcePosition = this.baseSampleIndex;
      }
    }
    this.underrunBlocks = 0;
  }

  reset() {
    this.chunks = [];
    this.chunkOffset = 0;
    this.bufferedSamples = 0;
    this.baseSampleIndex = 0;
    this.sourcePosition = 0;
    this.primed = false;
    this.holdSample = 0;
    this.underrunBlocks = 0;
    this.inUnderrun = false;
  }

  discardSamples(count) {
    let remaining = Math.max(0, Math.min(this.bufferedSamples, Math.floor(count)));
    while (remaining > 0 && this.chunks.length > 0) {
      const head = this.chunks[0];
      const available = head.length - this.chunkOffset;
      if (available <= remaining) {
        this.chunks.shift();
        this.chunkOffset = 0;
        this.bufferedSamples -= available;
        this.baseSampleIndex += available;
        remaining -= available;
      } else {
        this.chunkOffset += remaining;
        this.bufferedSamples -= remaining;
        this.baseSampleIndex += remaining;
        remaining = 0;
      }
    }
  }

  sampleAt(index) {
    const relative = Math.floor(index - this.baseSampleIndex);
    if (relative < 0) {
      const head = this.chunks[0];
      return head && head.length > this.chunkOffset ? head[this.chunkOffset] : this.holdSample;
    }

    let offset = relative;
    for (let i = 0; i < this.chunks.length; i += 1) {
      const chunk = this.chunks[i];
      const start = i === 0 ? this.chunkOffset : 0;
      const available = chunk.length - start;
      if (offset < available) {
        return chunk[start + offset];
      }
      offset -= available;
    }

    const tail = this.chunks[this.chunks.length - 1];
    return tail && tail.length > 0 ? tail[tail.length - 1] : this.holdSample;
  }

  interpolate(position) {
    const center = Math.floor(position);
    const fraction = position - center;
    const radius = this.resampleRadius;
    const cutoff = Math.min(1, sampleRate / this.sourceSampleRate);
    let value = 0;
    let weightSum = 0;

    for (let tap = -radius + 1; tap <= radius; tap += 1) {
      const x = tap - fraction;
      const normalized = Math.abs(x) / radius;
      if (normalized >= 1) {
        continue;
      }
      const scaled = cutoff * x;
      const sinc = Math.abs(scaled) < 1e-8
        ? 1
        : Math.sin(Math.PI * scaled) / (Math.PI * scaled);
      // Blackman window: compact and sufficiently band-limited for the
      // 8 kHz voice stream while preserving a continuous frame boundary.
      const window = 0.42 + (0.5 * Math.cos(Math.PI * normalized)) +
        (0.08 * Math.cos(2 * Math.PI * normalized));
      const weight = cutoff * sinc * window;
      value += this.sampleAt(center + tap) * weight;
      weightSum += weight;
    }

    return Math.abs(weightSum) > 1e-8 ? value / weightSum : 0;
  }

  postStats(force = false) {
    if (!force && currentTime - this.lastStatsTime < 1) {
      return;
    }
    this.lastStatsTime = currentTime;
    this.port.postMessage({
      type: "stats",
      bufferedSamples: this.bufferedSamples,
      sourceSampleRate: this.sourceSampleRate,
      primed: this.primed,
      underrunBlocks: this.underrunBlocks,
      underrunEvents: this.underrunEvents,
      droppedSamples: this.droppedSamples,
    });
  }

  fillUnderrun(output, start) {
    let hold = this.holdSample;
    for (let i = start; i < output.length; i += 1) {
      output[i] = hold;
      hold *= 0.999;
    }
    this.holdSample = hold;
    this.underrunBlocks += 1;
    if (!this.inUnderrun) {
      this.inUnderrun = true;
      this.underrunEvents += 1;
      this.postStats(true);
    }
    if (this.underrunBlocks >= 8) {
      this.primed = false;
    }
  }

  process(inputs, outputs) {
    const output = outputs && outputs[0] && outputs[0][0];
    if (!output) {
      return true;
    }
    output.fill(0);

    if (!this.primed) {
      if (this.bufferedSamples < this.primeSamples) {
        this.postStats(false);
        return true;
      }
      this.primed = true;
      this.inUnderrun = false;
    }

    const step = this.sourceSampleRate / sampleRate;
    const radius = this.resampleRadius;
    let write = 0;
    const endSampleIndex = this.baseSampleIndex + this.bufferedSamples;
    while (write < output.length) {
      // Keep future taps available instead of synthesizing a frame boundary;
      // this adds only ~1.5 ms at 8 kHz and avoids a click at every packet.
      if (Math.ceil(this.sourcePosition) + radius >= endSampleIndex) {
        break;
      }
      output[write] = this.interpolate(this.sourcePosition);
      write += 1;
      this.sourcePosition += step;
    }

    if (write > 0) {
      this.holdSample = output[write - 1];
      this.discardSamples(Math.floor(this.sourcePosition) - radius - this.baseSampleIndex);
      this.underrunBlocks = 0;
      this.inUnderrun = false;
    }
    if (write < output.length) {
      this.fillUnderrun(output, write);
    }

    this.postStats(false);
    return true;
  }
}

registerProcessor("incomudon-pcm-playback", IncomudonPCMPlaybackProcessor);
