/**
 * Synthesized Cyber Audio Effects Engine using Web Audio API
 */

class ThreatAudioEngine {
  constructor() {
    this.ctx = null;
    this.enabled = true;
  }

  init() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.ctx = new AudioContext();
      }
    }
  }

  toggleSound(enabled) {
    this.enabled = enabled;
  }

  playBeep(freq = 440, type = 'sine', duration = 0.15, gainVal = 0.04) {
    if (!this.enabled) return;
    try {
      this.init();
      if (!this.ctx) return;
      if (this.ctx.state === 'suspended') {
        this.ctx.resume();
      }

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);

      gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch (e) {
      // Ignore audio context errors gracefully
    }
  }

  playAlert() {
    this.playBeep(880, 'sawtooth', 0.25, 0.05);
    setTimeout(() => this.playBeep(660, 'sawtooth', 0.2, 0.04), 120);
  }

  playShieldBlock() {
    this.playBeep(320, 'square', 0.18, 0.04);
    setTimeout(() => this.playBeep(220, 'square', 0.25, 0.05), 90);
  }

  playSuccess() {
    this.playBeep(523.25, 'sine', 0.12, 0.03);
    setTimeout(() => this.playBeep(659.25, 'sine', 0.12, 0.03), 80);
    setTimeout(() => this.playBeep(783.99, 'sine', 0.2, 0.04), 160);
  }

  playScan() {
    this.playBeep(1200, 'sine', 0.06, 0.02);
  }
}

export const threatAudio = new ThreatAudioEngine();
