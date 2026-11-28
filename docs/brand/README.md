# Brand

| File | Use |
|---|---|
| `icon.svg`, `icon.png` | The icon: favicons, avatars, app and tab icons, chat emoji. Readable down to 16 px. The PNG is 512 × 512. |
| `logo.svg`, `logo.png` | Icon and wordmark, for light backgrounds. |
| `social-preview.svg`, `social-preview.png` | 1280 × 640 card for the repository's GitHub social preview and for link previews elsewhere. |

The SVGs are the sources; the PNGs are renders of them.

The icon follows the uBix family tile (uBixSys blue `#0f62fe`, white shapes at full and
55% opacity). Four key shares around a seal, one share faint: a threshold of shares unseals the vault.

The wordmark is IBM Plex Sans, `uBix` light and `Vault` semibold. In SVG it is live text that
falls back to Helvetica Neue or Arial where Plex is not installed.

## Regenerating the PNGs

After editing an SVG:

```sh
rsvg-convert -w 512 -h 512 docs/brand/icon.svg -o docs/brand/icon.png
rsvg-convert -h 160 docs/brand/logo.svg -o docs/brand/logo.png
rsvg-convert -w 1280 -h 640 docs/brand/social-preview.svg -o docs/brand/social-preview.png
```

Install IBM Plex Sans (static TTF, weights 300 and 600) before rendering if you want the exact face.

## GitHub social preview

GitHub has no API for this setting, so a person uploads `social-preview.png` by hand:
Settings → General → Social preview → Upload an image.

## Use of the brand

These files are in use by the project and are not covered by the code license. See
[TRADEMARKS.md](../../TRADEMARKS.md).
