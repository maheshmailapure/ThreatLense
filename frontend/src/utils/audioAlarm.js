let audioCtx = null;
let sirenOscillator1 = null;
let sirenOscillator2 = null;
let sirenGainNode = null;
let isAlarmPlaying = false;
let isMuted = localStorage.getItem('ai_ids_siren_muted') !== null ? localStorage.getItem('ai_ids_siren_muted') === 'true' : true;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) {
      audioCtx = new AudioContextClass();
    }
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

export const playIntrusionAlarm = (severity = 'CRITICAL') => {
  if (isMuted || isAlarmPlaying) return;

  try {
    const ctx = getAudioContext();
    if (!ctx) return;

    isAlarmPlaying = true;

    // Create gain node for volume control
    sirenGainNode = ctx.createGain();
    sirenGainNode.gain.setValueAtTime(0.15, ctx.currentTime);
    sirenGainNode.connect(ctx.destination);

    // Dual-tone security siren oscillator
    sirenOscillator1 = ctx.createOscillator();
    sirenOscillator2 = ctx.createOscillator();

    sirenOscillator1.type = 'sawtooth';
    sirenOscillator2.type = 'square';

    const now = ctx.currentTime;
    const duration = 2.0; // Play alarm for 2 seconds (short, non-disruptive)

    // Modulate pitch between 600Hz and 1200Hz for high-urgency siren
    const baseFreq = severity === 'CRITICAL' ? 880 : 660;
    const peakFreq = severity === 'CRITICAL' ? 1320 : 990;

    for (let i = 0; i < 4; i++) {
      const step = 0.5 * i;
      sirenOscillator1.frequency.setValueAtTime(baseFreq, now + step);
      sirenOscillator1.frequency.linearRampToValueAtTime(peakFreq, now + step + 0.25);
      sirenOscillator1.frequency.linearRampToValueAtTime(baseFreq, now + step + 0.5);

      sirenOscillator2.frequency.setValueAtTime(baseFreq / 2, now + step);
      sirenOscillator2.frequency.linearRampToValueAtTime(peakFreq / 2, now + step + 0.25);
    }

    sirenOscillator1.connect(sirenGainNode);
    sirenOscillator2.connect(sirenGainNode);

    sirenOscillator1.start(now);
    sirenOscillator2.start(now);

    // Stop after duration
    sirenOscillator1.stop(now + duration);
    sirenOscillator2.stop(now + duration);

    sirenOscillator1.onended = () => {
      isAlarmPlaying = false;
    };
  } catch (err) {
    console.error("Audio alarm error:", err);
    isAlarmPlaying = false;
  }
};

export const stopIntrusionAlarm = () => {
  try {
    if (sirenOscillator1) {
      sirenOscillator1.stop();
      sirenOscillator1.disconnect();
    }
    if (sirenOscillator2) {
      sirenOscillator2.stop();
      sirenOscillator2.disconnect();
    }
    if (sirenGainNode) {
      sirenGainNode.disconnect();
    }
  } catch (e) {
    // Ignore already stopped oscillator error
  }
  isAlarmPlaying = false;
};

export const toggleMuteAlarm = () => {
  isMuted = !isMuted;
  localStorage.setItem('ai_ids_siren_muted', String(isMuted));
  if (isMuted) {
    stopIntrusionAlarm();
  }
  return isMuted;
};

export const getMuteState = () => isMuted;
