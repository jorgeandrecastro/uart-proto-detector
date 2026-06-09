// Copyright (C) 2026 Jorge Andre Castro <georgeandrec@gmail.com>
// SPDX-License-Identifier: GPL-2.0-or-later

//! Tests unitaires pour `uart-proto-detector`.
//!
//! Ces tests s'exécutent en environnement `std` sur la machine hôte (`cargo test`).
//! Ils couvrent les cas nominaux, les cas limites et les chemins d'erreur.

use uart_proto_detector::{
    GenericParser, PacketLengthStrategy, ParserConfig, ParserError, BUFFER_SIZE,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn feed(parser: &mut GenericParser, bytes: &[u8]) -> Option<Vec<u8>> {
    for &b in bytes {
        match parser.parse_byte(b) {
            Ok(Some(packet)) => return Some(packet.to_vec()),
            Ok(None) => {}
            Err(e) => panic!("Erreur inattendue : {:?}", e),
        }
    }
    None
}

// ─── Tests longueur fixe ──────────────────────────────────────────────────────

#[test]
fn fixed_length_happy_path() {
    let config = ParserConfig {
        header: &[0xAA, 0x55],
        length_strategy: PacketLengthStrategy::Fixed(6),
    };
    let mut parser = GenericParser::new(config);

    let stream: &[u8] = &[0xAA, 0x55, 0x01, 0x02, 0x03, 0x04];
    let result = feed(&mut parser, stream);
    assert_eq!(result, Some(vec![0xAA, 0x55, 0x01, 0x02, 0x03, 0x04]));
}

#[test]
fn fixed_length_garbage_before_header() {
    let config = ParserConfig {
        header: &[0xAA, 0x55],
        length_strategy: PacketLengthStrategy::Fixed(4),
    };
    let mut parser = GenericParser::new(config);

    // Octets parasites suivis d'une trame valide
    let stream: &[u8] = &[0x00, 0xFF, 0xDE, 0xAA, 0x55, 0xBE, 0xEF];
    let result = feed(&mut parser, stream);
    assert_eq!(result, Some(vec![0xAA, 0x55, 0xBE, 0xEF]));
}

#[test]
fn fixed_length_multiple_packets() {
    let config = ParserConfig {
        header: &[0xFF],
        length_strategy: PacketLengthStrategy::Fixed(3),
    };
    let mut parser = GenericParser::new(config);

    let mut packets: Vec<Vec<u8>> = Vec::new();
    let stream: &[u8] = &[0xFF, 0x01, 0x02, 0xFF, 0x03, 0x04];

    for &b in stream {
        if let Ok(Some(p)) = parser.parse_byte(b) {
            packets.push(p.to_vec());
        }
    }

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], vec![0xFF, 0x01, 0x02]);
    assert_eq!(packets[1], vec![0xFF, 0x03, 0x04]);
}

// ─── Tests longueur dynamique ─────────────────────────────────────────────────

#[test]
fn length_byte_happy_path() {
    // Trame : [0xAA, 0x55, LEN, ...payload..., CRC]
    // LEN = taille payload + 1 octet CRC, offset = 3 (header 2 + octet LEN lui-même)
    let config = ParserConfig {
        header: &[0xAA, 0x55],
        length_strategy: PacketLengthStrategy::LengthByte { index: 2, offset: 3 },
    };
    let mut parser = GenericParser::new(config);

    // LEN = 0x03 → longueur totale = 3 + 3 = 6
    let stream: &[u8] = &[0xAA, 0x55, 0x03, 0x10, 0x20, 0xCK];
    // On remplace 0xCK par une valeur réelle
    let stream: &[u8] = &[0xAA, 0x55, 0x03, 0x10, 0x20, 0x30];
    let result = feed(&mut parser, stream);
    assert_eq!(result, Some(vec![0xAA, 0x55, 0x03, 0x10, 0x20, 0x30]));
}

#[test]
fn length_byte_payload_zero() {
    // LEN = 0x00 → longueur totale = 0 + offset
    let config = ParserConfig {
        header: &[0xBB],
        length_strategy: PacketLengthStrategy::LengthByte { index: 1, offset: 2 },
    };
    let mut parser = GenericParser::new(config);

    // longueur totale = 0 + 2 = 2 → trame [0xBB, 0x00]
    let stream: &[u8] = &[0xBB, 0x00];
    let result = feed(&mut parser, stream);
    assert_eq!(result, Some(vec![0xBB, 0x00]));
}

// ─── Tests d'erreur ───────────────────────────────────────────────────────────

#[test]
fn error_packet_too_large_fixed() {
    let config = ParserConfig {
        header: &[0xAA],
        length_strategy: PacketLengthStrategy::Fixed(BUFFER_SIZE + 1),
    };
    let mut parser = GenericParser::new(config);

    // Premier octet valide (en-tête)
    assert_eq!(parser.parse_byte(0xAA), Ok(None));
    // Deuxième octet → le parser tente de fixer la longueur et détecte le dépassement
    let result = parser.parse_byte(0x01);
    assert_eq!(result, Err(ParserError::PacketTooLarge(BUFFER_SIZE + 1)));
}

#[test]
fn error_packet_too_large_length_byte() {
    let config = ParserConfig {
        header: &[0xCC],
        // offset = 2, donc LEN = 255 → total = 257 > BUFFER_SIZE
        length_strategy: PacketLengthStrategy::LengthByte { index: 1, offset: 2 },
    };
    let mut parser = GenericParser::new(config);

    parser.parse_byte(0xCC).unwrap(); // en-tête OK
    let result = parser.parse_byte(0xFF); // LEN = 255 → total = 257
    assert_eq!(result, Err(ParserError::PacketTooLarge(257)));
}

#[test]
fn error_invalid_length_byte_index() {
    let config = ParserConfig {
        header: &[0xDD],
        length_strategy: PacketLengthStrategy::LengthByte {
            index: BUFFER_SIZE, // index hors limite
            offset: 0,
        },
    };
    let mut parser = GenericParser::new(config);

    parser.parse_byte(0xDD).unwrap();
    // Envoyer suffisamment d'octets pour dépasser l'index invalide
    // En pratique l'erreur est déclenchée avant d'atteindre BUFFER_SIZE
    // (le buffer overflow se déclenche en premier) — on vérifie simplement
    // qu'aucun paquet n'est retourné et qu'une erreur est émise.
    let mut got_error = false;
    for i in 0u8..10 {
        match parser.parse_byte(i) {
            Err(ParserError::InvalidLengthByteIndex) => {
                got_error = true;
                break;
            }
            Err(_) | Ok(_) => {}
        }
    }
    assert!(got_error, "InvalidLengthByteIndex aurait dû être retourné");
}

#[test]
fn error_buffer_overflow_recovery() {
    // Protocole Fixed(200) > BUFFER_SIZE(128) → BufferOverflow avant la fin
    let config = ParserConfig {
        header: &[0xEE],
        length_strategy: PacketLengthStrategy::Fixed(200),
    };
    let mut parser = GenericParser::new(config);

    // L'en-tête est valide
    parser.parse_byte(0xEE).unwrap();
    // Le dépassement de taille est détecté dès la fixation de la longueur
    let result = parser.parse_byte(0x01);
    assert_eq!(result, Err(ParserError::PacketTooLarge(200)));

    // Après l'erreur, le parser doit être réinitialisé et prêt à recevoir
    // une nouvelle trame valide
    assert_eq!(parser.bytes_accumulated(), 0);
    assert_eq!(parser.expected_length(), None);
}

// ─── Tests des méthodes d'introspection ───────────────────────────────────────

#[test]
fn introspection_bytes_accumulated() {
    let config = ParserConfig {
        header: &[0x01, 0x02],
        length_strategy: PacketLengthStrategy::Fixed(5),
    };
    let mut parser = GenericParser::new(config);

    assert_eq!(parser.bytes_accumulated(), 0);
    parser.parse_byte(0x01).unwrap();
    assert_eq!(parser.bytes_accumulated(), 1);
    parser.parse_byte(0x02).unwrap();
    assert_eq!(parser.bytes_accumulated(), 2);
}

#[test]
fn introspection_expected_length_fixed() {
    let config = ParserConfig {
        header: &[0xAB],
        length_strategy: PacketLengthStrategy::Fixed(10),
    };
    let mut parser = GenericParser::new(config);

    assert_eq!(parser.expected_length(), None);
    parser.parse_byte(0xAB).unwrap(); // en-tête complet
    parser.parse_byte(0x00).unwrap(); // premier octet après l'en-tête → longueur fixée
    assert_eq!(parser.expected_length(), Some(10));
}