import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

export default function SplashScreen({ onComplete }) {
  const [progress, setProgress] = useState(0);
  const voiceSpokenRef = useRef(false);

  // High-Tech Speech Synthesis Voice: "Loading ThreatLense System"
  const speakVoice = () => {
    if (voiceSpokenRef.current) return;
    voiceSpokenRef.current = true;

    try {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel(); // Clear any stale utterances
        const utterance = new SpeechSynthesisUtterance("Loading ThreatLense System");
        utterance.rate = 0.95;
        utterance.pitch = 1.05;
        utterance.volume = 1.0;
        utterance.lang = 'en-US';

        const assignVoiceAndSpeak = () => {
          const voices = window.speechSynthesis.getVoices();
          const selectedVoice = voices.find(
            (v) =>
              v.lang.startsWith('en') &&
              (v.name.includes('Natural') ||
                v.name.includes('Google') ||
                v.name.includes('Samantha') ||
                v.name.includes('David') ||
                v.name.includes('Zira') ||
                v.name.includes('English'))
          ) || voices.find((v) => v.lang.startsWith('en'));

          if (selectedVoice) {
            utterance.voice = selectedVoice;
          }
          window.speechSynthesis.speak(utterance);
        };

        if (window.speechSynthesis.getVoices().length > 0) {
          assignVoiceAndSpeak();
        } else {
          window.speechSynthesis.onvoiceschanged = () => {
            assignVoiceAndSpeak();
            window.speechSynthesis.onvoiceschanged = null;
          };
        }
      }
    } catch (err) {
      console.warn("Speech synthesis unavailable:", err);
    }
  };

  // Cyber Harmonic Audio Chime Synthesizer
  const playCyberChime = () => {
    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) return;
      const ctx = new AudioContextClass();
      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const now = ctx.currentTime;

      // 1. Warm Resonant Sub-Bass Swell
      const subOsc = ctx.createOscillator();
      const subGain = ctx.createGain();
      subOsc.type = 'sine';
      subOsc.frequency.setValueAtTime(75, now);
      subOsc.frequency.exponentialRampToValueAtTime(115, now + 1.2);
      subGain.gain.setValueAtTime(0.001, now);
      subGain.gain.linearRampToValueAtTime(0.16, now + 0.35);
      subGain.gain.exponentialRampToValueAtTime(0.0001, now + 2.4);
      subOsc.connect(subGain);
      subGain.connect(ctx.destination);
      subOsc.start(now);
      subOsc.stop(now + 2.5);

      // 2. C-Major Cyber Harmonic Pad (G4, C5, E5, G5, C6)
      const freqs = [392.0, 523.25, 659.25, 783.99, 1046.5];
      freqs.forEach((freq, idx) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'triangle';
        const start = now + 0.15 + idx * 0.14;
        osc.frequency.setValueAtTime(freq, start);

        gain.gain.setValueAtTime(0.001, start);
        gain.gain.linearRampToValueAtTime(0.10, start + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.85);

        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(start);
        osc.stop(start + 0.9);
      });

      // 3. Crisp Lock Tone at 2.7s
      setTimeout(() => {
        try {
          if (ctx.state === 'closed') return;
          const pingNow = ctx.currentTime;
          const pingOsc = ctx.createOscillator();
          const pingGain = ctx.createGain();
          pingOsc.type = 'sine';
          pingOsc.frequency.setValueAtTime(1318.51, pingNow);
          pingOsc.frequency.exponentialRampToValueAtTime(1567.98, pingNow + 0.12);
          pingGain.gain.setValueAtTime(0.001, pingNow);
          pingGain.gain.linearRampToValueAtTime(0.14, pingNow + 0.03);
          pingGain.gain.exponentialRampToValueAtTime(0.0001, pingNow + 0.4);
          pingOsc.connect(pingGain);
          pingGain.connect(ctx.destination);
          pingOsc.start(pingNow);
          pingOsc.stop(pingNow + 0.45);
        } catch (e) {}
      }, 2700);
    } catch (e) {
      console.warn("Audio context init deferred:", e);
    }
  };

  useEffect(() => {
    // Speak voice and play cyber chime on boot
    speakVoice();
    playCyberChime();

    const handleUserInteraction = () => {
      speakVoice();
      playCyberChime();
      window.removeEventListener('pointerdown', handleUserInteraction);
    };
    window.addEventListener('pointerdown', handleUserInteraction, { once: true });

    // Smooth 3.0-second timing sequence
    const duration = 3000;
    const startTime = Date.now();

    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const pct = Math.min(100, Math.round((elapsed / duration) * 100));
      setProgress(pct);

      if (elapsed >= duration) {
        clearInterval(interval);
        setTimeout(() => {
          onComplete();
        }, 180);
      }
    }, 25);

    return () => {
      clearInterval(interval);
      window.removeEventListener('pointerdown', handleUserInteraction);
    };
  }, [onComplete]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#eaf1ed] select-none overflow-hidden antialiased">
      {/* Dynamic Ambient Background Illumination */}
      <div className="absolute -top-[12%] -left-[10%] w-[55vw] h-[55vw] rounded-full bg-emerald-200/45 blur-[140px] pointer-events-none" />
      <div className="absolute -bottom-[12%] -right-[10%] w-[55vw] h-[55vw] rounded-full bg-cyan-200/40 blur-[150px] pointer-events-none" />
      <div className="absolute top-[28%] left-[26%] w-[48vw] h-[48vw] rounded-full bg-blue-200/30 blur-[130px] pointer-events-none" />

      {/* Main Glass-Neumorphic Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 1.05, filter: 'blur(12px)' }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="w-[92%] max-w-[460px] p-9 sm:p-12 rounded-[36px] bg-[#edf4f0]/95 backdrop-blur-2xl border border-white/80 shadow-[22px_22px_48px_rgba(152,174,165,0.4),-22px_-22px_48px_rgba(255,255,255,0.95)] flex flex-col items-center relative z-10 text-center"
      >
        {/* Animated Radar Halo & Logo Stage */}
        <div className="relative mb-8 flex items-center justify-center">
          {/* Outer Rotating Radar Ring */}
          <div className="absolute -inset-6 rounded-full border border-blue-400/20 border-dashed animate-[spin_12s_linear_infinite] pointer-events-none" />
          
          {/* Pulsing Cyan-Blue Glow */}
          <motion.div
            animate={{ scale: [0.95, 1.15, 0.95], opacity: [0.35, 0.75, 0.35] }}
            transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
            className="absolute inset-0 -m-5 rounded-full bg-gradient-to-tr from-blue-500/25 via-cyan-400/20 to-emerald-400/20 blur-xl pointer-events-none"
          />

          {/* Clean Soft Platform for Logo */}
          <div className="px-6 py-4 rounded-3xl bg-[#e4ece7]/90 shadow-[6px_6px_14px_rgba(152,174,165,0.35),-6px_-6px_14px_rgba(255,255,255,0.9)] border border-white/60 relative z-10 flex items-center justify-center">
            <motion.img
              initial={{ filter: 'brightness(0.95)' }}
              animate={{ filter: ['brightness(0.98)', 'brightness(1.08)', 'brightness(0.98)'] }}
              transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
              src="/threatlense_logo.png"
              alt="ThreatLense"
              className="h-14 sm:h-16 w-auto object-contain drop-shadow-[0_6px_16px_rgba(37,99,235,0.22)]"
            />
          </div>
        </div>

        {/* Minimalist High-Precision Progress Bar */}
        <div className="w-full space-y-3.5">
          {/* Neumorphic Track */}
          <div className="h-2.5 w-full rounded-full bg-[#e4ece7] shadow-[inset_2.5px_2.5px_5px_rgba(152,174,165,0.45),inset_-2.5px_-2.5px_5px_rgba(255,255,255,0.9)] overflow-hidden p-[2px] border border-white/50">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-blue-600 via-cyan-500 to-emerald-500 shadow-[0_0_12px_rgba(37,99,235,0.6)] relative"
              style={{ width: `${progress}%` }}
              transition={{ ease: 'easeOut', duration: 0.1 }}
            >
              {/* Shimmer light bar */}
              <div className="absolute right-0 top-0 bottom-0 w-3 bg-white/70 rounded-full blur-[1px]" />
            </motion.div>
          </div>

          {/* Clean Subtitle & Percentage Counter */}
          <div className="flex items-center justify-between text-xs font-semibold px-1">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
              <span className="text-slate-600 font-medium tracking-tight">
                Loading ThreatLense System...
              </span>
            </div>
            <span className="font-mono text-xs font-bold text-slate-700 bg-[#e4ece7] px-2.5 py-0.5 rounded-full shadow-[inset_1px_1px_2px_rgba(152,174,165,0.35),inset_-1px_-1px_2px_rgba(255,255,255,0.8)]">
              {progress}%
            </span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
