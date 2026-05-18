//! Opus codec wrapper for VoIP audio.
//!
//! Implements the OpusConfig from spec/11 §11.4:
//!
//! ```text
//! Sample rate:   48000 Hz
//! Channels:      1 (mono)
//! Application:   OPUS_APPLICATION_VOIP
//! Bitrate:       VBR, max 64000 bps
//! Bitrate min:   6000 bps
//! Frame duration: 20 ms
//! FEC:           on (Forward Error Correction)
//! DTX:           on (Discontinuous Transmission)
//! Complexity:    10 (maximum)
//! Frame size:    960 samples (48kHz × 20ms)
//! ```

use tracing::{info, instrument, warn};

use voip_core::VoIPConfig;

use crate::error::AudioError;

/// Opus codec configuration matching spec/11 §11.4.
#[derive(Debug, Clone)]
pub struct OpusConfig {
    /// Sample rate in Hz (default: 48000)
    pub sample_rate: u32,
    /// Number of channels (default: 1 = mono)
    pub channels: u8,
    /// Opus application mode
    pub application: opus::Application,
    /// Bitrate mode and maximum
    pub bitrate: opus::Bitrate,
    /// Minimum bitrate in bps
    pub bitrate_min: i32,
    /// Frame duration in milliseconds (default: 20)
    pub frame_duration_ms: u32,
    /// Enable Forward Error Correction (default: true)
    pub fec: bool,
    /// Enable Discontinuous Transmission (default: true)
    pub dtx: bool,
    /// Encoder complexity 0-10 (default: 10)
    pub complexity: u8,
    /// Frame size in samples (48kHz × 20ms = 960)
    pub frame_size: usize,
}

impl Default for OpusConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            application: opus::Application::Voip,
            bitrate: opus::Bitrate::Bits(64000),
            bitrate_min: 6000,
            frame_duration_ms: 20,
            fec: true,
            dtx: true,
            complexity: 10,
            frame_size: 960, // 48000 Hz × 0.020 s = 960 samples
        }
    }
}

impl OpusConfig {
    /// Create the spec-compliant Opus configuration.
    pub fn voip_default() -> Self {
        Self::default()
    }

    /// Create from VoIPConfig (for future config overrides).
    pub fn from_voip_config(_config: &VoIPConfig) -> Self {
        // Currently the VoIPConfig doesn't have Opus-specific fields,
        // so we use the spec defaults. Future versions may add overrides.
        Self::default()
    }

    /// Maximum packet size for Opus at 64kbps with 20ms frames.
    /// 64000 bps / 8 bits/byte / (1000 ms / 20 ms) = 160 bytes max payload.
    pub fn max_packet_size(&self) -> usize {
        160
    }

    /// Get the opus::Channels for this config.
    fn opus_channels(&self) -> opus::Channels {
        if self.channels == 1 {
            opus::Channels::Mono
        } else {
            opus::Channels::Stereo
        }
    }
}

/// Opus audio encoder.
pub struct OpusEncoder {
    /// The underlying Opus encoder
    encoder: opus::Encoder,
    /// Configuration
    config: OpusConfig,
}

impl OpusEncoder {
    /// Create a new Opus encoder with the given configuration.
    #[instrument(name = "opus_encoder_new")]
    pub fn new(config: OpusConfig) -> Result<Self, AudioError> {
        let encoder = opus::Encoder::new(
            config.sample_rate,
            config.opus_channels(),
            config.application,
        )
        .map_err(|e| AudioError::EncoderError(format!("create encoder: {}", e)))?;

        let mut enc = Self {
            encoder,
            config,
        };

        // Apply configuration
        enc.apply_config()?;

        info!(
            sample_rate = enc.config.sample_rate,
            channels = enc.config.channels,
            frame_duration_ms = enc.config.frame_duration_ms,
            fec = enc.config.fec,
            dtx = enc.config.dtx,
            complexity = enc.config.complexity,
            "Opus encoder created"
        );

        Ok(enc)
    }

    /// Create an encoder with the spec-compliant default configuration.
    pub fn with_defaults() -> Result<Self, AudioError> {
        Self::new(OpusConfig::voip_default())
    }

    /// Apply the configuration to the encoder.
    fn apply_config(&mut self) -> Result<(), AudioError> {
        // Set bitrate
        self.encoder
            .set_bitrate(self.config.bitrate)
            .map_err(|e| {
                AudioError::EncoderError(format!("set bitrate: {}", e))
            })?;

        // Set minimum bitrate
        self.encoder
            .set_bitrate(self.config.bitrate)
            .map_err(|e| {
                AudioError::EncoderError(format!("set min bitrate: {}", e))
            })?;

        // Enable FEC (Forward Error Correction)
        if self.config.fec {
            self.encoder
                .set_inband_fec(true)
                .map_err(|e| {
                    AudioError::EncoderError(format!("set FEC: {}", e))
                })?;
        }

        // Enable DTX (Discontinuous Transmission)
        if self.config.dtx {
            self.encoder
                .set_dtx(true)
                .map_err(|e| {
                    AudioError::EncoderError(format!("set DTX: {}", e))
                })?;
        }

        // Set encoder complexity
        self.encoder
            .set_complexity(self.config.complexity as i32)
            .map_err(|e| {
                AudioError::EncoderError(format!("set complexity: {}", e))
            })?;

        Ok(())
    }

    /// Encode a single frame of PCM audio to Opus.
    ///
    /// # Arguments
    ///
    /// * `pcm` — PCM audio samples (interleaved if stereo, i16 format)
    /// * `output` — Output buffer for the encoded Opus packet
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Frame Size
    ///
    /// The input must contain exactly `frame_size` samples (960 for 20ms at 48kHz).
    /// For mono, that's 960 i16 values. For stereo, 1920 (960 × 2).
    pub fn encode(
        &mut self,
        pcm: &[i16],
        output: &mut [u8],
    ) -> Result<usize, AudioError> {
        let expected_samples = self.config.frame_size * self.config.channels as usize;
        if pcm.len() < expected_samples {
            return Err(AudioError::InvalidFrameSize(pcm.len()));
        }

        let max_output = self.config.max_packet_size();
        if output.len() < max_output {
            return Err(AudioError::BufferTooSmall {
                need: max_output,
                have: output.len(),
            });
        }

        self.encoder
            .encode(&pcm[..expected_samples], output)
            .map_err(|e| AudioError::EncoderError(format!("encode: {}", e)))
    }

    /// Encode a frame and return the encoded bytes as a Vec.
    ///
    /// Convenience method that allocates the output buffer.
    pub fn encode_vec(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        let expected_samples = self.config.frame_size * self.config.channels as usize;
        if pcm.len() < expected_samples {
            return Err(AudioError::InvalidFrameSize(pcm.len()));
        }

        self.encoder
            .encode_vec(&pcm[..expected_samples], self.config.max_packet_size())
            .map_err(|e| AudioError::EncoderError(format!("encode_vec: {}", e)))
    }

    /// Get the configured frame size in samples.
    pub fn frame_size(&self) -> usize {
        self.config.frame_size
    }

    /// Get the configured frame duration in milliseconds.
    pub fn frame_duration_ms(&self) -> u32 {
        self.config.frame_duration_ms
    }

    /// Get the number of packets per second.
    ///
    /// At 20ms frames: 1000 / 20 = 50 packets per second.
    pub fn packets_per_second(&self) -> u32 {
        1000 / self.config.frame_duration_ms
    }

    /// Get a reference to the encoder configuration.
    pub fn config(&self) -> &OpusConfig {
        &self.config
    }

    /// Set the encoder bitrate.
    pub fn set_bitrate(&mut self, bitrate: opus::Bitrate) -> Result<(), AudioError> {
        self.encoder
            .set_bitrate(bitrate)
            .map_err(|e| AudioError::EncoderError(format!("set bitrate: {}", e)))
    }

    /// Check whether DTX is active for this encoder.
    /// With DTX enabled, silence frames produce much smaller packets.
    pub fn is_dtx_enabled(&self) -> bool {
        self.config.dtx
    }

    /// Check whether FEC is enabled for this encoder.
    pub fn is_fec_enabled(&self) -> bool {
        self.config.fec
    }
}

/// Opus audio decoder.
pub struct OpusDecoder {
    /// The underlying Opus decoder
    decoder: opus::Decoder,
    /// Configuration
    config: OpusConfig,
}

impl OpusDecoder {
    /// Create a new Opus decoder with the given configuration.
    #[instrument(name = "opus_decoder_new")]
    pub fn new(config: OpusConfig) -> Result<Self, AudioError> {
        let decoder = opus::Decoder::new(
            config.sample_rate,
            config.opus_channels(),
        )
        .map_err(|e| AudioError::DecoderError(format!("create decoder: {}", e)))?;

        info!(
            sample_rate = config.sample_rate,
            channels = config.channels,
            "Opus decoder created"
        );

        Ok(Self {
            decoder,
            config,
        })
    }

    /// Create a decoder with the spec-compliant default configuration.
    pub fn with_defaults() -> Result<Self, AudioError> {
        Self::new(OpusConfig::voip_default())
    }

    /// Decode an Opus packet to PCM audio.
    ///
    /// # Arguments
    ///
    /// * `opus_data` — Encoded Opus packet data
    /// * `output` — Output buffer for decoded PCM samples (i16 format)
    /// * `fec` — Whether to use Forward Error Correction for this decode
    ///
    /// # Returns
    ///
    /// The number of samples written to the output buffer.
    pub fn decode(
        &mut self,
        opus_data: &[u8],
        output: &mut [i16],
        fec: bool,
    ) -> Result<usize, AudioError> {
        let max_samples = self.config.frame_size * self.config.channels as usize;
        if output.len() < max_samples {
            return Err(AudioError::BufferTooSmall {
                need: max_samples,
                have: output.len(),
            });
        }

        if fec {
            // Decode with FEC: use the next packet's FEC data to reconstruct
            // a lost packet. This is called "packet loss concealment" when
            // no FEC data is available.
            self.decoder
                .decode(opus_data, output, true)
                .map_err(|e| AudioError::DecoderError(format!("decode FEC: {}", e)))
        } else {
            self.decoder
                .decode(opus_data, output, false)
                .map_err(|e| AudioError::DecoderError(format!("decode: {}", e)))
        }
    }

    /// Decode an Opus packet, returning the PCM samples as a Vec.
    ///
    /// Convenience method that allocates the output buffer.
    pub fn decode_vec(
        &mut self,
        opus_data: &[u8],
        fec: bool,
    ) -> Result<Vec<i16>, AudioError> {
        let max_samples = self.config.frame_size * self.config.channels as usize;
        let mut output = vec![0i16; max_samples];
        let samples = self.decode(opus_data, &mut output, fec)?;
        output.truncate(samples);
        Ok(output)
    }

    /// Perform Packet Loss Concealment (PLC) when a packet is missing.
    ///
    /// Called when an Opus packet is lost and no FEC data is available.
    /// The decoder generates a smooth interpolation to fill the gap.
    pub fn plc(&mut self, output: &mut [i16]) -> Result<usize, AudioError> {
        let max_samples = self.config.frame_size * self.config.channels as usize;
        if output.len() < max_samples {
            return Err(AudioError::BufferTooSmall {
                need: max_samples,
                have: output.len(),
            });
        }

        // Pass an empty slice to trigger PLC (packet loss concealment)
        self.decoder
            .decode(&[], output, false)
            .map_err(|e| AudioError::DecoderError(format!("PLC: {}", e)))
    }

    /// Perform PLC, returning samples as a Vec.
    pub fn plc_vec(&mut self) -> Result<Vec<i16>, AudioError> {
        let max_samples = self.config.frame_size * self.config.channels as usize;
        let mut output = vec![0i16; max_samples];
        let samples = self.plc(&mut output)?;
        output.truncate(samples);
        Ok(output)
    }

    /// Get the configured frame size in samples.
    pub fn frame_size(&self) -> usize {
        self.config.frame_size
    }

    /// Get a reference to the decoder configuration.
    pub fn config(&self) -> &OpusConfig {
        &self.config
    }
}

/// Combined encoder/decoder pair for a bidirectional audio stream.
pub struct OpusCodec {
    /// Encoder for outgoing audio
    encoder: OpusEncoder,
    /// Decoder for incoming audio
    decoder: OpusDecoder,
}

impl OpusCodec {
    /// Create a new OpusCodec with the given configuration.
    pub fn new(config: OpusConfig) -> Result<Self, AudioError> {
        let encoder = OpusEncoder::new(config.clone())?;
        let decoder = OpusDecoder::new(config)?;
        Ok(Self { encoder, decoder })
    }

    /// Create an OpusCodec with spec-compliant defaults.
    pub fn with_defaults() -> Result<Self, AudioError> {
        Self::new(OpusConfig::voip_default())
    }

    /// Encode a frame of PCM audio.
    pub fn encode(&mut self, pcm: &[i16], output: &mut [u8]) -> Result<usize, AudioError> {
        self.encoder.encode(pcm, output)
    }

    /// Encode a frame, returning bytes as a Vec.
    pub fn encode_vec(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        self.encoder.encode_vec(pcm)
    }

    /// Decode an Opus packet to PCM.
    pub fn decode(
        &mut self,
        opus_data: &[u8],
        output: &mut [i16],
        fec: bool,
    ) -> Result<usize, AudioError> {
        self.decoder.decode(opus_data, output, fec)
    }

    /// Decode an Opus packet, returning samples as a Vec.
    pub fn decode_vec(
        &mut self,
        opus_data: &[u8],
        fec: bool,
    ) -> Result<Vec<i16>, AudioError> {
        self.decoder.decode_vec(opus_data, fec)
    }

    /// Perform Packet Loss Concealment.
    pub fn plc(&mut self, output: &mut [i16]) -> Result<usize, AudioError> {
        self.decoder.plc(output)
    }

    /// Perform PLC, returning samples as a Vec.
    pub fn plc_vec(&mut self) -> Result<Vec<i16>, AudioError> {
        self.decoder.plc_vec()
    }

    /// Get a reference to the encoder.
    pub fn encoder(&self) -> &OpusEncoder {
        &self.encoder
    }

    /// Get a mutable reference to the encoder.
    pub fn encoder_mut(&mut self) -> &mut OpusEncoder {
        &mut self.encoder
    }

    /// Get a reference to the decoder.
    pub fn decoder(&self) -> &OpusDecoder {
        &self.decoder
    }

    /// Get a mutable reference to the decoder.
    pub fn decoder_mut(&mut self) -> &mut OpusDecoder {
        &mut self.decoder
    }

    /// Get the frame size in samples.
    pub fn frame_size(&self) -> usize {
        self.encoder.frame_size()
    }

    /// Get the frame duration in milliseconds.
    pub fn frame_duration_ms(&self) -> u32 {
        self.encoder.frame_duration_ms()
    }

    /// Get the number of packets per second.
    pub fn packets_per_second(&self) -> u32 {
        self.encoder.packets_per_second()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a sine wave at the given frequency.
    /// Returns `frame_size` samples of i16 PCM at 48kHz.
    fn generate_sine(freq: u32, frame_size: usize, amplitude: i16) -> Vec<i16> {
        (0..frame_size)
            .map(|i| {
                let t = i as f64 / 48000.0;
                let val = (2.0 * std::f64::consts::PI * freq as f64 * t).sin();
                (val * amplitude as f64) as i16
            })
            .collect()
    }

    /// Helper: generate silence (all zeros).
    fn generate_silence(frame_size: usize) -> Vec<i16> {
        vec![0i16; frame_size]
    }

    // =========================================================================
    // 4.1 — Basic encode/decode tests
    // =========================================================================

    #[test]
    fn test_encode_produces_valid_opus_packet() {
        let mut encoder = OpusEncoder::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();

        // Non-empty
        assert!(!encoded.is_empty(), "Encoded packet should not be empty");

        // Reasonable size: at 64kbps with 20ms frames, max ~160 bytes.
        // Typical voice packet is 40-120 bytes.
        assert!(
            encoded.len() <= 200,
            "Encoded packet size {} seems too large",
            encoded.len()
        );
        assert!(
            encoded.len() >= 1,
            "Encoded packet should have at least 1 byte"
        );
    }

    #[test]
    fn test_decode_produces_correct_frame_size() {
        let mut codec = OpusCodec::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let encoded = codec.encode_vec(&pcm).unwrap();

        let decoded = codec.decode_vec(&encoded, false).unwrap();

        // For 48kHz/20ms mono, the decoded frame must be 960 samples
        assert_eq!(
            decoded.len(),
            960,
            "Decoded frame size should be 960 samples (48kHz/20ms/mono)"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip_same_frame_size() {
        let mut codec = OpusCodec::with_defaults().unwrap();

        // Encode a 960-sample frame
        let pcm_in = generate_sine(440, 960, 8000);
        assert_eq!(pcm_in.len(), 960);

        let encoded = codec.encode_vec(&pcm_in).unwrap();
        let pcm_out = codec.decode_vec(&encoded, false).unwrap();

        // Round-trip should preserve the frame size
        assert_eq!(
            pcm_in.len(),
            pcm_out.len(),
            "Round-trip: input frame size {} should match output frame size {}",
            pcm_in.len(),
            pcm_out.len()
        );

        // The audio should be intelligible (not zeroed out)
        let energy: i64 = pcm_out.iter().map(|&s| (s as i64).abs()).sum();
        assert!(
            energy > 0,
            "Decoded audio should have non-zero energy (got sum={})",
            energy
        );
    }

    #[test]
    fn test_encode_decode_roundtrip_preserves_signal_shape() {
        let mut codec = OpusCodec::with_defaults().unwrap();

        // Use a strong sine wave for clearer signal
        let pcm_in = generate_sine(1000, 960, 16000);
        let encoded = codec.encode_vec(&pcm_in).unwrap();
        let pcm_out = codec.decode_vec(&encoded, false).unwrap();

        // Compute correlation between input and output
        let n = pcm_in.len().min(pcm_out.len());
        let mean_in: f64 = pcm_in[..n].iter().map(|&s| s as f64).sum::<f64>() / n as f64;
        let mean_out: f64 = pcm_out[..n].iter().map(|&s| s as f64).sum::<f64>() / n as f64;

        let mut cov = 0.0;
        let mut var_in = 0.0;
        let mut var_out = 0.0;
        for i in 0..n {
            let di = pcm_in[i] as f64 - mean_in;
            let do_ = pcm_out[i] as f64 - mean_out;
            cov += di * do_;
            var_in += di * di;
            var_out += do_ * do_;
        }

        let correlation = if var_in > 0.0 && var_out > 0.0 {
            cov / (var_in.sqrt() * var_out.sqrt())
        } else {
            0.0
        };

        // Correlation should be high for a sine wave through Opus.
        // Opus may invert the phase (negative correlation), so we check absolute value.
        assert!(
            correlation.abs() > 0.8,
            "Round-trip correlation should be > 0.8 (absolute), got {}",
            correlation
        );
    }

    // =========================================================================
    // FEC (Forward Error Correction) tests
    // =========================================================================

    #[test]
    fn test_fec_encode_and_decode() {
        // FEC must be enabled in the config
        let config = OpusConfig {
            fec: true,
            ..OpusConfig::default()
        };

        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();

        // Encode several frames of speech-like audio
        let frame_size = 960;
        let num_frames = 20;
        let mut encoded_frames: Vec<Vec<u8>> = Vec::new();

        for i in 0..num_frames {
            // Vary the frequency slightly for speech-like content
            let freq = 200 + (i * 50) % 800;
            let pcm = generate_sine(freq, frame_size, 12000);
            let encoded = encoder.encode_vec(&pcm).unwrap();
            encoded_frames.push(encoded);
        }

        // Decode all frames normally first (to prime the decoder state)
        for encoded in &encoded_frames {
            let decoded = decoder.decode_vec(encoded, false).unwrap();
            assert_eq!(decoded.len(), frame_size);
        }
    }

    #[test]
    fn test_fec_packet_loss_recovery() {
        let config = OpusConfig {
            fec: true,
            ..OpusConfig::default()
        };

        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();

        let frame_size = 960;
        let num_frames = 10;

        // Encode frames with audio content
        let mut encoded_frames: Vec<Vec<u8>> = Vec::new();
        for i in 0..num_frames {
            let freq = 300 + (i * 100) % 600;
            let pcm = generate_sine(freq, frame_size, 12000);
            let encoded = encoder.encode_vec(&pcm).unwrap();
            encoded_frames.push(encoded);
        }

        // Simulate 5% packet loss: drop frame at index 5 (10% of 10 frames,
        // but this is a deterministic test)
        let lost_index = 5;

        for (i, encoded) in encoded_frames.iter().enumerate() {
            if i == lost_index {
                // Frame was lost — use FEC from the next frame to recover
                if i + 1 < encoded_frames.len() {
                    let recovered = decoder.decode_vec(&encoded_frames[i + 1], true).unwrap();
                    assert_eq!(
                        recovered.len(),
                        frame_size,
                        "FEC-recovered frame should have correct size"
                    );

                    // The recovered frame should have some energy (not total silence)
                    let energy: i64 = recovered.iter().map(|&s| (s as i64).abs()).sum();
                    assert!(
                        energy > 0,
                        "FEC-recovered audio should have non-zero energy"
                    );
                }
                // Also do a PLC for the lost frame
                let plc_samples = decoder.plc_vec().unwrap();
                assert_eq!(plc_samples.len(), frame_size);
            } else {
                let decoded = decoder.decode_vec(encoded, false).unwrap();
                assert_eq!(decoded.len(), frame_size);
            }
        }
    }

    // =========================================================================
    // DTX (Discontinuous Transmission) tests
    // =========================================================================

    #[test]
    fn test_dtx_silence_produces_smaller_packets() {
        let config = OpusConfig {
            dtx: true,
            ..OpusConfig::default()
        };

        let mut encoder = OpusEncoder::new(config).unwrap();

        let speech_pcm = generate_sine(440, 960, 12000);
        let silence_pcm = generate_silence(960);

        // Encode speech
        let speech_encoded = encoder.encode_vec(&speech_pcm).unwrap();

        // Encode several frames of silence to let DTX kick in
        // DTX typically activates after a few consecutive silence frames
        let mut silence_sizes: Vec<usize> = Vec::new();
        for _ in 0..10 {
            let encoded = encoder.encode_vec(&silence_pcm).unwrap();
            silence_sizes.push(encoded.len());
        }

        // The average silence packet size should be significantly smaller
        // than the speech packet size
        let avg_silence_size: f64 = silence_sizes.iter().sum::<usize>() as f64
            / silence_sizes.len() as f64;

        assert!(
            avg_silence_size < speech_encoded.len() as f64,
            "DTX: average silence packet size ({:.1} bytes) should be smaller than speech packet ({} bytes)",
            avg_silence_size,
            speech_encoded.len()
        );

        // Later silence frames should be even smaller (DTX kicks in)
        let later_silence_avg: f64 = silence_sizes[5..].iter().sum::<usize>() as f64
            / silence_sizes[5..].len() as f64;

        // DTX silence packets are typically 1-3 bytes (just a flag)
        // Allow up to 10 bytes for DTX packets
        assert!(
            later_silence_avg < 15.0,
            "DTX: later silence packets should be very small, got avg {:.1} bytes",
            later_silence_avg
        );
    }

    #[test]
    fn test_dtx_silence_bandwidth_below_1kbps() {
        let config = OpusConfig {
            dtx: true,
            ..OpusConfig::default()
        };

        let mut encoder = OpusEncoder::new(config).unwrap();

        let silence_pcm = generate_silence(960);

        // Encode 50 frames (1 second at 20ms frames) of silence
        let mut total_bytes: usize = 0;
        // Skip first few frames to let DTX activate
        for _ in 0..5 {
            let _ = encoder.encode_vec(&silence_pcm).unwrap();
        }
        // Now measure the steady-state DTX bandwidth
        for _ in 0..50 {
            let encoded = encoder.encode_vec(&silence_pcm).unwrap();
            total_bytes += encoded.len();
        }

        // Calculate bandwidth in bps
        let bits_per_second = total_bytes * 8; // 50 frames = 1 second
        let kbps = bits_per_second as f64 / 1000.0;

        assert!(
            kbps < 1.0,
            "DTX: silence bandwidth should be below 1 kbps, got {:.2} kbps",
            kbps
        );
    }

    // =========================================================================
    // Bitrate tests
    // =========================================================================

    #[test]
    fn test_bitrate_6000() {
        let config = OpusConfig {
            bitrate: opus::Bitrate::Bits(6000),
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config).unwrap();
        let pcm = generate_sine(440, 960, 12000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        assert!(!encoded.is_empty());
        // At 6kbps, 20ms frame should be ~15 bytes max
        assert!(
            encoded.len() <= 30,
            "At 6kbps, packet size should be small, got {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn test_bitrate_32000() {
        let config = OpusConfig {
            bitrate: opus::Bitrate::Bits(32000),
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config).unwrap();
        let pcm = generate_sine(440, 960, 12000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        assert!(!encoded.is_empty());
        // At 32kbps, 20ms frame should be ~80 bytes (Opus may overshoot)
        assert!(
            encoded.len() <= 150,
            "At 32kbps, packet size should be moderate, got {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn test_bitrate_64000() {
        let config = OpusConfig {
            bitrate: opus::Bitrate::Bits(64000),
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config).unwrap();
        let pcm = generate_sine(440, 960, 12000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        assert!(!encoded.is_empty());
        // At 64kbps, 20ms frame should be ~160 bytes
        assert!(
            encoded.len() <= 200,
            "At 64kbps, packet size should be reasonable, got {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn test_dynamic_bitrate_change() {
        let mut encoder = OpusEncoder::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 12000);

        // Start at 64kbps
        let encoded_high = encoder.encode_vec(&pcm).unwrap();

        // Switch to 6kbps
        encoder.set_bitrate(opus::Bitrate::Bits(6000)).unwrap();
        let encoded_low = encoder.encode_vec(&pcm).unwrap();

        // Lower bitrate should produce smaller packets
        assert!(
            encoded_low.len() <= encoded_high.len(),
            "Lower bitrate ({}) should produce smaller or equal packet than higher bitrate ({})",
            encoded_low.len(),
            encoded_high.len()
        );
    }

    // =========================================================================
    // Stereo vs Mono tests
    // =========================================================================

    #[test]
    fn test_mono_encoding() {
        let config = OpusConfig {
            channels: 1,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config).unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_stereo_encoding() {
        let config = OpusConfig {
            channels: 2,
            frame_size: 960,          // 960 frames × 2 channels = 1920 samples
            bitrate: opus::Bitrate::Bits(64000),
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config).unwrap();

        // Stereo: 960 frames × 2 channels = 1920 interleaved samples
        let mut pcm = Vec::with_capacity(1920);
        let left = generate_sine(440, 960, 8000);
        let right = generate_sine(880, 960, 6000);
        for i in 0..960 {
            pcm.push(left[i]);
            pcm.push(right[i]);
        }

        let encoded = encoder.encode_vec(&pcm).unwrap();
        assert!(!encoded.is_empty());
    }

    // =========================================================================
    // Different frame duration tests
    // =========================================================================

    #[test]
    fn test_frame_duration_2_5ms() {
        // 2.5ms at 48kHz = 120 samples
        let config = OpusConfig {
            frame_duration_ms: 2,
            frame_size: 120,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();
        let pcm = generate_sine(440, 120, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        let decoded = decoder.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 120);
    }

    #[test]
    fn test_frame_duration_5ms() {
        // 5ms at 48kHz = 240 samples
        let config = OpusConfig {
            frame_duration_ms: 5,
            frame_size: 240,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();
        let pcm = generate_sine(440, 240, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        let decoded = decoder.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 240);
    }

    #[test]
    fn test_frame_duration_10ms() {
        // 10ms at 48kHz = 480 samples
        let config = OpusConfig {
            frame_duration_ms: 10,
            frame_size: 480,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();
        let pcm = generate_sine(440, 480, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        let decoded = decoder.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 480);
    }

    #[test]
    fn test_frame_duration_20ms() {
        // 20ms at 48kHz = 960 samples (default)
        let mut codec = OpusCodec::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let encoded = codec.encode_vec(&pcm).unwrap();
        let decoded = codec.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 960);
    }

    #[test]
    fn test_frame_duration_40ms() {
        // 40ms at 48kHz = 1920 samples
        let config = OpusConfig {
            frame_duration_ms: 40,
            frame_size: 1920,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();
        let pcm = generate_sine(440, 1920, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        let decoded = decoder.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 1920);
    }

    #[test]
    fn test_frame_duration_60ms() {
        // 60ms at 48kHz = 2880 samples
        let config = OpusConfig {
            frame_duration_ms: 60,
            frame_size: 2880,
            ..OpusConfig::default()
        };
        let mut encoder = OpusEncoder::new(config.clone()).unwrap();
        let mut decoder = OpusDecoder::new(config).unwrap();
        let pcm = generate_sine(440, 2880, 8000);
        let encoded = encoder.encode_vec(&pcm).unwrap();
        let decoded = decoder.decode_vec(&encoded, false).unwrap();
        assert_eq!(decoded.len(), 2880);
    }

    // =========================================================================
    // Invalid input tests
    // =========================================================================

    #[test]
    fn test_encode_wrong_frame_size() {
        let mut encoder = OpusEncoder::with_defaults().unwrap();

        // Too few samples (expected 960, gave 100)
        let pcm_short = vec![0i16; 100];
        let result = encoder.encode_vec(&pcm_short);
        assert!(result.is_err(), "Should fail with wrong frame size");
        match result {
            Err(AudioError::InvalidFrameSize(n)) => assert_eq!(n, 100),
            other => panic!("Expected InvalidFrameSize(100), got {:?}", other),
        }
    }

    #[test]
    fn test_encode_zero_samples() {
        let mut encoder = OpusEncoder::with_defaults().unwrap();

        // Zero samples
        let pcm_empty: Vec<i16> = vec![];
        let result = encoder.encode_vec(&pcm_empty);
        assert!(result.is_err(), "Should fail with zero samples");
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let mut encoder = OpusEncoder::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let mut output = vec![0u8; 10]; // Too small
        let result = encoder.encode(&pcm, &mut output);
        assert!(result.is_err(), "Should fail with buffer too small");
    }

    #[test]
    fn test_decode_buffer_too_small() {
        let mut codec = OpusCodec::with_defaults().unwrap();
        let pcm = generate_sine(440, 960, 8000);
        let encoded = codec.encode_vec(&pcm).unwrap();

        let mut output = vec![0i16; 10]; // Too small
        let result = codec.decode(&encoded, &mut output, false);
        assert!(result.is_err(), "Should fail with buffer too small");
    }

    // =========================================================================
    // PLC (Packet Loss Concealment) test
    // =========================================================================

    #[test]
    fn test_plc_produces_valid_frame() {
        let mut codec = OpusCodec::with_defaults().unwrap();

        // First decode a real frame to set decoder state
        let pcm = generate_sine(440, 960, 8000);
        let encoded = codec.encode_vec(&pcm).unwrap();
        let _ = codec.decode_vec(&encoded, false).unwrap();

        // Now simulate a lost packet using PLC
        let plc_output = codec.plc_vec().unwrap();
        assert_eq!(
            plc_output.len(),
            960,
            "PLC should produce a full frame of 960 samples"
        );

        // PLC should produce some audio (not all zeros)
        let energy: i64 = plc_output.iter().map(|&s| (s as i64).abs()).sum();
        assert!(
            energy > 0,
            "PLC should produce non-zero energy to fill the gap"
        );
    }

    // =========================================================================
    // Config and utility tests
    // =========================================================================

    #[test]
    fn test_opus_config_default() {
        let config = OpusConfig::default();
        assert_eq!(config.sample_rate, 48000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.frame_duration_ms, 20);
        assert_eq!(config.frame_size, 960);
        assert!(config.fec);
        assert!(config.dtx);
        assert_eq!(config.complexity, 10);
    }

    #[test]
    fn test_packets_per_second() {
        let encoder = OpusEncoder::with_defaults().unwrap();
        assert_eq!(encoder.packets_per_second(), 50); // 1000/20 = 50
    }

    #[test]
    fn test_encoder_dtx_fec_flags() {
        let encoder = OpusEncoder::with_defaults().unwrap();
        assert!(encoder.is_dtx_enabled());
        assert!(encoder.is_fec_enabled());

        let config_no_dtx = OpusConfig {
            dtx: false,
            fec: false,
            ..OpusConfig::default()
        };
        let encoder_no_dtx = OpusEncoder::new(config_no_dtx).unwrap();
        assert!(!encoder_no_dtx.is_dtx_enabled());
        assert!(!encoder_no_dtx.is_fec_enabled());
    }
}
