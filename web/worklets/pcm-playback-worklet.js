class IncomudonPCMPlaybackProcessor extends AudioWorkletProcessor {
  constructor() {
    super();

    this.chunks = [];
    this.chunkOffset = 0;
    this.bufferedSamples = 0;

    this.primeSamples = 4096;
    this.maxSamples = 96000;
    this.primed = false;
    this.holdSample = 0;
    this.underrunBlocks = 0;

    this.port.onmessage = (event) => {
      this.onMessage(event && event.data);
    };
  }

  onMessage(message) {
    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type === "config") {
      const prime = Math.max(256, Number(message.primeSamples) || this.primeSamples);
      const max = Math.max(prime * 2, Number(message.maxSamples) || this.maxSamples);
      this.primeSamples = prime;
      this.maxSamples = max;
      return;
    }

    if (message.type === "reset") {
      this.chunks = [];
      this.chunkOffset = 0;
      this.bufferedSamples = 0;
      this.primed = false;
      this.holdSample = 0;
      this.underrunBlocks = 0;
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
        Math.floor(message.samples.byteLength / 4),
      );
    }

    if (!samples || samples.length <= 0) {
      return;
    }

    if (this.bufferedSamples > this.maxSamples) {
      this.chunks = [];
      this.chunkOffset = 0;
      this.bufferedSamples = 0;
      this.primed = false;
    }

    let overflow = (this.bufferedSamples + samples.length) - this.maxSamples;
    while (overflow > 0 && this.chunks.length > 0) {
      const head = this.chunks[0];
      const available = head.length - this.chunkOffset;
      if (available <= overflow) {
        this.chunks.shift();
        this.chunkOffset = 0;
        this.bufferedSamples -= available;
        overflow -= available;
      } else {
        this.chunkOffset += overflow;
        this.bufferedSamples -= overflow;
        overflow = 0;
      }
    }

    this.chunks.push(samples);
    this.bufferedSamples += samples.length;
    this.underrunBlocks = 0;
  }

  process(inputs, outputs) {
    const output = outputs && outputs[0] && outputs[0][0];
    if (!output) {
      return true;
    }

    output.fill(0);

    if (this.bufferedSamples <= 0) {
      if (this.primed) {
        let hold = this.holdSample;
        for (let i = 0; i < output.length; i += 1) {
          output[i] = hold;
          hold *= 0.999;
        }
        this.holdSample = hold;
        this.underrunBlocks += 1;
        if (this.underrunBlocks >= 8) {
          this.primed = false;
        }
      }
      return true;
    }

    if (!this.primed) {
      if (this.bufferedSamples < this.primeSamples) {
        return true;
      }
      this.primed = true;
    }

    let write = 0;
    while (write < output.length && this.chunks.length > 0) {
      const head = this.chunks[0];
      const available = head.length - this.chunkOffset;
      if (available <= 0) {
        this.chunks.shift();
        this.chunkOffset = 0;
        continue;
      }
      const n = Math.min(available, output.length - write);
      output.set(head.subarray(this.chunkOffset, this.chunkOffset + n), write);
      write += n;
      this.chunkOffset += n;
      this.bufferedSamples -= n;
      if (this.chunkOffset >= head.length) {
        this.chunks.shift();
        this.chunkOffset = 0;
      }
    }

    if (write > 0) {
      this.holdSample = output[write - 1];
    }
    if (write < output.length) {
      let hold = this.holdSample;
      for (let i = write; i < output.length; i += 1) {
        output[i] = hold;
        hold *= 0.999;
      }
      this.holdSample = hold;
      this.underrunBlocks += 1;
    } else {
      this.underrunBlocks = 0;
    }

    return true;
  }
}

registerProcessor("incomudon-pcm-playback", IncomudonPCMPlaybackProcessor);
