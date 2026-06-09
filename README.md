# uart-proto-detector

> Bibliothèque universelle `no_std` pour la détection et le découpage de trames UART sur systèmes embarqués.

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

---

## Fonctionnalités

- **`no_std`** — compatible avec tous les environnements bare-metal (ARM Cortex-M, RISC-V, Xtensa…)
- **Zéro dépendance externe** : aucun HAL imposé, aucun allocateur requis
- **Deux stratégies de longueur** : taille fixe ou octet de longueur dynamique
- **Gestion d'erreurs typée** via `ParserError` (pas de panic en production)
- **CRC volontairement exclu** : chaque protocole définit son propre algorithme ; la validation se fait dans le code appelant

## Installation

```toml
# Cargo.toml
[dependencies]
uart-proto-detector = "0.1"
```

## Utilisation rapide

```rust
use uart_proto_detector::{GenericParser, ParserConfig, PacketLengthStrategy};

// Protocole avec en-tête fixe [0xAA, 0x55] et trame de 8 octets
let config = ParserConfig {
    header: &[0xAA, 0x55],
    length_strategy: PacketLengthStrategy::Fixed(8),
};
let mut parser = GenericParser::new(config);

// Dans votre ISR ou boucle de lecture UART :
fn on_byte_received(parser: &mut GenericParser, byte: u8) {
    match parser.parse_byte(byte) {
        Ok(Some(packet)) => {
            // Trame complète : vérifier le CRC ici selon votre protocole,
            // puis traiter les données.
        }
        Ok(None) => {
            // Accumulation en cours, rien à faire.
        }
        Err(e) => {
            // Le parser s'est réinitialisé automatiquement.
            // Loguer ou signaler l'erreur si nécessaire.
        }
    }
}
```

## Stratégies de longueur

### `Fixed(n)`

La trame fait toujours `n` octets (en-tête inclus).

```rust
PacketLengthStrategy::Fixed(12)
```

### `LengthByte { index, offset }`

Un octet situé à la position `index` dans le buffer indique la taille du payload.
La longueur totale est calculée ainsi :

```
longueur_totale = buffer[index] + offset
```

**Exemple :** protocole `[HDR1, HDR2, LEN, ...payload..., CRC]`

```rust
// index = 2 (position de LEN), offset = 3 (HDR1 + HDR2 + octet LEN lui-même)
PacketLengthStrategy::LengthByte { index: 2, offset: 3 }
```

## Validation CRC

La bibliothèque retourne la trame brute complète. La vérification du CRC est
intentionnellement laissée au code appelant :

```rust
Ok(Some(packet)) => {
    if !my_crc_check(packet) {
        // rejeter la trame
        return;
    }
    process(packet);
}
```

## Gestion des erreurs

```rust
pub enum ParserError {
    BufferOverflow,              // buffer plein avant fin de trame
    PacketTooLarge(usize),       // longueur calculée > BUFFER_SIZE
    InvalidLengthByteIndex,      // index de l'octet de longueur hors limites
}
```

Toutes les erreurs réinitialisent automatiquement le parser.

## Constantes configurables

| Constante | Valeur par défaut | Description |
|-----------|-------------------|-------------|
| `BUFFER_SIZE` | `128` | Taille du buffer d'accumulation en octets |

Pour modifier `BUFFER_SIZE`, patchez la constante dans la bibliothèque ou ouvrez
une issue pour demander le support d'une feature de configuration générique.

## Licence

Copyright (C) 2026 Jorge Andre Castro  
Distribué sous les termes de la [GNU General Public License v2.0 ou ultérieure](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).