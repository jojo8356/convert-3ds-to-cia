# convert-3ds-to-cia

Convert Nintendo 3DS ROM files (.3ds) to CIA format for installation on CFW consoles.

## Features

- **Built-in decryption** - Decrypts encrypted ROMs automatically using AES-128-CTR (no xorpads or 3DS hardware needed for standard encryption)
- **Zip support** - Reads .3ds files directly from zip archives
- **Xorpad fallback** - Falls back to xorpad-based decryption for seed-encrypted (9.6+) titles
- **Parallel processing** - CRC32 checksums computed in parallel via Rayon

## Usage

1. Place your `.3ds` or `.zip` files in a `roms/` folder next to the executable
2. Run the executable:
   ```
   ./3ds-to-cia
   ```
3. Converted `.cia` files will appear in the `cia/` folder

### Options

- `--verbose` / `-v` - Show detailed output during conversion

## Supported encryption types

| Type | Firmware | Status |
|------|----------|--------|
| FW1 (slot 0x2C) | All | Decrypted automatically |
| FW7 (slot 0x25) | 7.x+ | Decrypted automatically |
| FW9.3 | 9.3+ | Decrypted automatically |
| FW9.6 | 9.6+ | Decrypted automatically |
| Seed crypto | 9.6+ | Requires xorpads |

## Building from source

```bash
cargo build --release
```

The binary will be at `target/release/3ds-to-cia`.

## License

See [LICENSE](LICENSE) for details.
