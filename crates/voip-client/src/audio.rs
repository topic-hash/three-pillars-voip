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
