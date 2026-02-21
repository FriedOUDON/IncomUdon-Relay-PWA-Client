class IncomudonMicCaptureProcessor extends AudioWorkletProcessor {
  constructor() {
    super();

    this.targetSampleRate = 8000;
    this.downsampleRatio = sampleRate / this.targetSampleRate;
    this.lpState = 0;

    this.inputBuffer = [];
    this.inputStart = 0;
    this.resampleOffset = 0;

    this.pcmBuffer = [];
    this.pcmStart = 0;
  }

  process(inputs, outputs) {
    const output = outputs && outputs[0] && outputs[0][0];
    if (output) {
      output.fill(0);
    }

    const input = inputs && inputs[0] && inputs[0][0];
    if (!input || input.length === 0) {
      return true;
    }

    for (let i = 0; i < input.length; i += 1) {
      this.inputBuffer.push(input[i]);
    }

    let availableInput = this.inputBuffer.length - this.inputStart;
    while (this.resampleOffset + this.downsampleRatio <= availableInput - 1) {
      const baseOffset = Math.floor(this.resampleOffset);
      const base = this.inputStart + baseOffset;
      const frac = this.resampleOffset - baseOffset;

      const a = this.inputBuffer[base];
      const b = this.inputBuffer[Math.min(base + 1, this.inputBuffer.length - 1)];
      const interpolated = a + (b - a) * frac;

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
      const frame = new Int16Array(160);
      for (let i = 0; i < 160; i += 1) {
        frame[i] = this.pcmBuffer[this.pcmStart + i];
      }
      this.pcmStart += 160;
      this.port.postMessage(frame.buffer, [frame.buffer]);
    }
    if (this.pcmStart > 2048 && this.pcmStart * 2 >= this.pcmBuffer.length) {
      this.pcmBuffer = this.pcmBuffer.slice(this.pcmStart);
      this.pcmStart = 0;
    }

    return true;
  }
}

function floatToInt16(value) {
  const clamped = Math.max(-1, Math.min(1, value));
  return clamped < 0 ? Math.round(clamped * 32768) : Math.round(clamped * 32767);
}

registerProcessor("incomudon-mic-capture", IncomudonMicCaptureProcessor);
