//! IEEE 802.15.4 RX validation for hardware CCM* encryption.
//!
//! Receives raw frames in promiscuous mode on channel 15 and prints
//! hex dumps. Used to verify that the secure TX example is actually
//! encrypting the payload (the "Hello secure!" plaintext should NOT
//! appear in the raw frame bytes when hardware security is enabled).

#![no_std]
#![no_main]

extern crate alloc;

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::main;
use esp_println::println;
use esp_radio::ieee802154::{Config, Ieee802154};

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default());

    esp_alloc::heap_allocator!(size: 24 * 1024);

    let mut ieee802154 = Ieee802154::new(peripherals.IEEE802154);

    ieee802154.set_config(Config {
        channel: 15,
        promiscuous: true,
        rx_when_idle: true,
        auto_ack_rx: false,
        auto_ack_tx: false,
        ..Default::default()
    });

    println!("=== Secure RX Validator ===");
    println!("Listening on channel 15 (promiscuous mode)");
    println!("Expecting encrypted frames from secure TX example");
    println!();

    // The plaintext we expect to NOT see if encryption is working
    const PLAINTEXT: &[u8] = b"Hello secure!";

    ieee802154.start_receive();

    let mut frame_count = 0u32;

    loop {
        if let Some(raw) = ieee802154.raw_received() {
            frame_count += 1;
            let len = raw.data[0] as usize;
            let frame_bytes = if len > 0 && len < raw.data.len() {
                &raw.data[1..=len]
            } else {
                &raw.data[1..raw.data.len().min(32)]
            };

            println!("--- Frame #{} (ch={}, len={}) ---", frame_count, raw.channel, len);

            // Print hex dump
            for (j, chunk) in frame_bytes.chunks(16).enumerate() {
                // Hex
                print!("  {:04x}: ", j * 16);
                for b in chunk {
                    print!("{:02x} ", b);
                }
                // ASCII
                print!(" |");
                for b in chunk {
                    if *b >= 0x20 && *b < 0x7f {
                        print!("{}", *b as char);
                    } else {
                        print!(".");
                    }
                }
                println!("|");
            }

            // Check if plaintext appears anywhere in the frame
            let contains_plaintext = frame_bytes
                .windows(PLAINTEXT.len())
                .any(|w| w == PLAINTEXT);

            if contains_plaintext {
                println!("  *** PLAINTEXT FOUND — encryption NOT working! ***");
            } else if len > 12 {
                // Only check frames long enough to potentially contain our payload
                // Frame Control (2) + Seq (1) + Dst PAN (2) + Dst Addr (2) + SecHdr (5) = 12
                println!("  (no plaintext found — encryption may be active)");
            }
            println!();
        }
    }
}

/// Minimal print! macro (no format args, just raw str)
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        esp_println::print!($($arg)*)
    };
}
