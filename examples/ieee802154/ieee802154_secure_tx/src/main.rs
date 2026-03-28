//! IEEE 802.15.4 hardware-encrypted TX example.
//!
//! Demonstrates using the MAC-layer AES-CCM* hardware to encrypt
//! frames inline during transmission. The receiver must decrypt
//! in software using the same key and nonce parameters.
//!
//! This builds a raw frame with an Auxiliary Security Header and
//! sends it using `transmit_secured()`, which triggers the hardware
//! CCM* encryption engine.

#![no_std]
#![no_main]

extern crate alloc;

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{delay::Delay, main};
use esp_println::println;
use esp_radio::ieee802154::{Config, Ieee802154, TransmitSecurity};

// Example 128-bit key (DO NOT use in production)
const SECURITY_KEY: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10,
];

// Source extended address (must match frame's source address for nonce)
const EXT_ADDR: u64 = 0x1122334455667788;

// MIC size for security level 5 (ENC-MIC-32) = 4 bytes
const MIC_SIZE: usize = 4;
// FCS (Frame Check Sequence) = 2 bytes
const FCS_SIZE: usize = 2;

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default());

    esp_alloc::heap_allocator!(size: 24 * 1024);

    let delay = Delay::new();

    let mut ieee802154 = Ieee802154::new(peripherals.IEEE802154);
    ieee802154.set_config(Config {
        channel: 15,
        txpower: 20,
        ..Default::default()
    });

    // Configure hardware security (key + extended address written to SEC registers)
    ieee802154.set_transmit_security(&TransmitSecurity {
        key: SECURITY_KEY,
        ext_addr: EXT_ADDR,
    });

    let mut frame_counter: u32 = 0;
    let mut seq = 0u8;

    loop {
        // Build raw IEEE 802.15.4 frame with Auxiliary Security Header.
        //
        // Layout:
        //   Frame Control (2B) | Seq (1B) | Dst PAN (2B) | Dst Addr (2B) |
        //   Aux Sec Hdr: SecCtrl (1B) + FrameCounter (4B) |
        //   Payload (plaintext, HW encrypts) | MIC placeholder (4B) | FCS (2B)
        //
        // The frame length (PHR) must account for ALL bytes including MIC + FCS.
        // The hardware writes the MIC and FCS into the placeholder space.
        let mut frame = [0u8; 40];
        let mut i = 0;

        // Frame Control: data frame (0x01), security enabled (0x08),
        // PAN ID compression (0x40) = 0x0049
        frame[i] = 0x49;
        i += 1; // FC low byte
        frame[i] = 0x00;
        i += 1; // FC high byte

        // Sequence number
        frame[i] = seq;
        i += 1;

        // Destination PAN ID (broadcast)
        frame[i] = 0xFF;
        i += 1;
        frame[i] = 0xFF;
        i += 1;

        // Destination short address (broadcast)
        frame[i] = 0xFF;
        i += 1;
        frame[i] = 0xFF;
        i += 1;

        // Auxiliary Security Header
        // Security Control: security level 5 (ENC-MIC-32), key ID mode 0
        frame[i] = 0x05;
        i += 1;

        // Frame Counter (little-endian)
        let fc_bytes = frame_counter.to_le_bytes();
        frame[i..i + 4].copy_from_slice(&fc_bytes);
        i += 4;

        // payload_offset: byte index where plaintext payload begins
        // (relative to frame data start, NOT the length byte)
        let payload_offset = i as u8;

        // Plaintext payload (hardware encrypts this in-place during TX)
        let payload = b"Hello secure!";
        frame[i..i + payload.len()].copy_from_slice(payload);
        i += payload.len();

        // MIC placeholder (4 bytes for ENC-MIC-32 / security level 5)
        // The hardware writes the computed MIC here during encryption.
        i += MIC_SIZE;

        // FCS placeholder (hardware computes CRC)
        i += FCS_SIZE;

        println!(
            "TX secured frame seq={} fc={} offset={} len={}",
            seq, frame_counter, payload_offset, i
        );

        ieee802154
            .transmit_secured(&frame[..i], payload_offset, false)
            .ok();

        seq = seq.wrapping_add(1);
        frame_counter += 1;

        delay.delay_millis(1000u32);
    }
}
