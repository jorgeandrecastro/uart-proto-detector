// Copyright (C) 2026 Jorge Andre Castro <georgeandrec@gmail.com>
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # uart-proto-detector
//!
//! Bibliothèque universelle `no_std` pour la détection et le découpage de trames
//! UART sur systèmes embarqués.
//!
//! ## Fonctionnement
//!
//! Le parser accumule les octets reçus un à un, valide l'en-tête, détermine la
//! longueur attendue selon la stratégie choisie, puis retourne la trame complète.
//! La validation du CRC est volontairement **exclue** de cette bibliothèque : chaque
//! composant implémentant son propre algorithme, cette responsabilité revient au code
//! appelant.
//!
//! ## Exemple minimal
//!
//! ```rust
//! use uart_proto_detector::{GenericParser, ParserConfig, PacketLengthStrategy};
//!
//! // Protocole avec en-tête [0xAA, 0x55] et longueur fixe de 8 octets
//! let config = ParserConfig {
//!     header: &[0xAA, 0x55],
//!     length_strategy: PacketLengthStrategy::Fixed(8),
//! };
//!
//! let mut parser = GenericParser::new(config);
//!
//! let stream: &[u8] = &[0xAA, 0x55, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
//! for &byte in stream {
//!     match parser.parse_byte(byte) {
//!         Ok(Some(packet)) => { /* traiter le paquet complet */ }
//!         Ok(None)         => { /* trame en cours d'accumulation */ }
//!         Err(e)           => { /* gérer l'erreur */ }
//!     }
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ─── Taille du buffer interne ───────────────────────────────────────────────

/// Taille du buffer d'accumulation en octets.
///
/// Peut être surchargée à la compilation via la feature `large-buffer` ou en
/// modifiant directement cette constante selon les contraintes mémoire de la
/// cible.
pub const BUFFER_SIZE: usize = 128;

// ─── Erreurs ─────────────────────────────────────────────────────────────────

/// Erreurs pouvant survenir lors du parsing d'une trame UART.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserError {
    /// Le buffer interne a été dépassé avant la fin d'une trame valide.
    ///
    /// Cela indique généralement un protocole mal configuré (longueur trop
    /// grande) ou un flux de données corrompu.
    BufferOverflow,

    /// La longueur calculée à partir de l'octet de longueur dépasse
    /// [`BUFFER_SIZE`], ce qui rendrait la trame impossible à stocker.
    ///
    /// Contient la longueur calculée.
    PacketTooLarge(usize),

    /// L'index de l'octet de longueur (champ `index` de
    /// [`PacketLengthStrategy::LengthByte`]) est supérieur ou égal à
    /// [`BUFFER_SIZE`], ce qui constitue une configuration invalide.
    InvalidLengthByteIndex,
}

// ─── Stratégie de longueur ───────────────────────────────────────────────────

/// Stratégie utilisée pour déterminer la longueur totale d'une trame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketLengthStrategy {
    /// La trame a une longueur totale fixe (en-tête inclus).
    ///
    /// # Exemple
    ///
    /// Pour un protocole dont chaque trame fait toujours 8 octets :
    ///
    /// ```rust
    /// # use uart_proto_detector::PacketLengthStrategy;
    /// let strategy = PacketLengthStrategy::Fixed(8);
    /// ```
    Fixed(usize),

    /// Un octet situé à la position `index` dans le buffer indique le nombre
    /// d'octets restants après lui-même. `offset` est ajouté à cette valeur
    /// pour obtenir la longueur totale de la trame.
    ///
    /// **Longueur totale** = `buffer[index] as usize + offset`
    ///
    /// # Exemple
    ///
    /// Pour un protocole dont l'octet à l'index 2 indique la taille du payload,
    /// et où la trame totale inclut 3 octets de structure supplémentaires
    /// (en-tête + octet de longueur + CRC) :
    ///
    /// ```rust
    /// # use uart_proto_detector::PacketLengthStrategy;
    /// let strategy = PacketLengthStrategy::LengthByte { index: 2, offset: 3 };
    /// ```
    LengthByte {
        /// Position de l'octet de longueur dans le buffer (base 0).
        index: usize,
        /// Valeur ajoutée à l'octet de longueur pour obtenir la longueur totale.
        offset: usize,
    },
}

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration complète d'un protocole UART.
///
/// Cette structure est `Copy` afin de pouvoir être stockée statiquement ou
/// dupliquée sans coût mémoire significatif.
///
/// # Exemple
///
/// ```rust
/// use uart_proto_detector::{ParserConfig, PacketLengthStrategy};
///
/// const MY_PROTOCOL: ParserConfig = ParserConfig {
///     header: &[0xFF, 0xAA],
///     length_strategy: PacketLengthStrategy::LengthByte { index: 2, offset: 4 },
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ParserConfig {
    /// Séquence d'octets d'en-tête identifiant le début d'une trame valide.
    ///
    /// Tous les octets reçus avant que l'en-tête complet soit reconnu sont
    /// ignorés.
    pub header: &'static [u8],

    /// Méthode utilisée pour déterminer la longueur totale de la trame.
    pub length_strategy: PacketLengthStrategy,
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parser générique pour protocoles UART.
///
/// Accumule les octets reçus, valide l'en-tête et retourne une référence vers
/// la trame complète dès qu'elle est disponible.
///
/// **Note :** La vérification du CRC n'est pas effectuée par ce parser. Elle
/// doit être réalisée par le code appelant après réception d'une trame complète,
/// car chaque protocole définit son propre algorithme.
///
/// # Exemple
///
/// ```rust
/// use uart_proto_detector::{GenericParser, ParserConfig, PacketLengthStrategy};
///
/// let config = ParserConfig {
///     header: &[0xAA, 0x55],
///     length_strategy: PacketLengthStrategy::Fixed(6),
/// };
/// let mut parser = GenericParser::new(config);
///
/// // Simuler un flux d'octets
/// let bytes: &[u8] = &[0xAA, 0x55, 0x01, 0x02, 0x03, 0x04];
/// for &b in bytes {
///     if let Ok(Some(packet)) = parser.parse_byte(b) {
///         assert_eq!(packet.len(), 6);
///     }
/// }
/// ```
pub struct GenericParser {
    config: ParserConfig,
    buffer: [u8; BUFFER_SIZE],
    bytes_read: usize,
    expected_length: Option<usize>,
}

impl GenericParser {
    /// Crée un nouveau parser à partir d'une [`ParserConfig`].
    #[inline]
    pub fn new(config: ParserConfig) -> Self {
        Self {
            config,
            buffer: [0u8; BUFFER_SIZE],
            bytes_read: 0,
            expected_length: None,
        }
    }

    /// Réinitialise l'état interne du parser.
    ///
    /// Appelé automatiquement après chaque trame complète ou en cas d'erreur.
    /// Peut aussi être appelé manuellement en cas de timeout ou de flush du bus.
    #[inline]
    pub fn reset(&mut self) {
        self.bytes_read = 0;
        self.expected_length = None;
    }

    /// Soumet un octet au parser.
    ///
    /// # Valeur de retour
    ///
    /// | Résultat       | Signification                                              |
    /// |----------------|------------------------------------------------------------|
    /// | `Ok(None)`     | Trame en cours d'accumulation, aucune action requise.      |
    /// | `Ok(Some(…))`  | Trame complète disponible dans la slice retournée.         |
    /// | `Err(…)`       | Erreur de parsing ; le parser a été réinitialisé.          |
    ///
    /// La slice retournée par `Ok(Some(…))` pointe sur le buffer interne et
    /// n'est valide que jusqu'au prochain appel à [`parse_byte`](Self::parse_byte)
    /// ou [`reset`](Self::reset).
    ///
    /// # Erreurs
    ///
    /// Retourne [`ParserError::BufferOverflow`] si le buffer est plein avant
    /// qu'une trame valide ne soit reçue, ou [`ParserError::PacketTooLarge`] si
    /// la longueur calculée dépasse [`BUFFER_SIZE`].
    pub fn parse_byte(&mut self, byte: u8) -> Result<Option<&[u8]>, ParserError> {
        // Sécurité anti-débordement : ne devrait pas se produire en usage normal
        if self.bytes_read >= BUFFER_SIZE {
            self.reset();
            return Err(ParserError::BufferOverflow);
        }

        self.buffer[self.bytes_read] = byte;
        self.bytes_read += 1;

        // ── 1. Validation de l'en-tête ────────────────────────────────────────
        let header_len = self.config.header.len();
        if self.bytes_read <= header_len {
            let pos = self.bytes_read - 1;
            if self.buffer[pos] != self.config.header[pos] {
                // Mauvais en-tête : réinitialisation et attente du prochain octet
                self.reset();
            }
            return Ok(None);
        }

        // ── 2. Détermination de la longueur attendue ──────────────────────────
        if self.expected_length.is_none() {
            match self.config.length_strategy {
                PacketLengthStrategy::Fixed(len) => {
                    if len > BUFFER_SIZE {
                        self.reset();
                        return Err(ParserError::PacketTooLarge(len));
                    }
                    self.expected_length = Some(len);
                }

                PacketLengthStrategy::LengthByte { index, offset } => {
                    if index >= BUFFER_SIZE {
                        self.reset();
                        return Err(ParserError::InvalidLengthByteIndex);
                    }
                    if self.bytes_read > index {
                        let total = self.buffer[index] as usize + offset;
                        if total > BUFFER_SIZE {
                            self.reset();
                            return Err(ParserError::PacketTooLarge(total));
                        }
                        self.expected_length = Some(total);
                    }
                }
            }
        }

        // ── 3. Vérification de complétude ─────────────────────────────────────
        if let Some(target_len) = self.expected_length {
            if self.bytes_read == target_len {
                let final_len = self.bytes_read;
                self.reset();
                // SAFETY: final_len <= BUFFER_SIZE (garanti par les vérifications ci-dessus)
                return Ok(Some(&self.buffer[..final_len]));
            }
        }

        Ok(None)
    }

    /// Retourne le nombre d'octets actuellement accumulés dans le buffer.
    #[inline]
    pub fn bytes_accumulated(&self) -> usize {
        self.bytes_read
    }

    /// Retourne la longueur de trame attendue, si elle a déjà été déterminée.
    #[inline]
    pub fn expected_length(&self) -> Option<usize> {
        self.expected_length
    }
}