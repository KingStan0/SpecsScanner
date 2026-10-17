# Changelog

All notable changes to SpecsScanner are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-10-17

### Fixed

- Report header: the brand row (logo, host tag, search box, theme buttons) was
  clipped to a thin strip because it shared the `.bar` CSS class with progress
  bars; the header row now uses its own `.topbar` class.
- Progress bars (storage usage, disk wear/life) now render their colored fill -
  the same class collision had zeroed it.
- Overview hero: the "Uptime" row now shows the real uptime (it read a summary
  value that is never set on that path).
- `-Redact`: Wi-Fi network names (SSID) are now replaced with
  `EXAMPLE-NETWORK`; the previous key pattern could never match.
- Displays, Network, Peripherals and Windows update history no longer render a
  phantom empty card or timeline row when their collector has no data (the
  `@($null)` array-expansion trap).
- Overview summary text: no more phantom "Disk health needs attention" or
  security-check lines on machines without that data.
- README: corrected the documented semantic color variable names
  (`--fg-ok` / `--fg-warn` / `--fg-bad` / `--fg-info`).

## [2.1.1] - 2026-10-17

### Fixed

- `Get-Help .\SpecsScanner.ps1` now shows the full synopsis, parameters,
  examples and links. `#Requires -Version 5.1` moved below the comment help
  block, which is required for PowerShell to read it (the version gate itself
  still works).
- Removed a no-op statement and an unused variable in the Windows tile
  renderer, and an unused icon from the SVG registry. No report changes.

## [2.1.0] - 2026-10-17

### Added

- Windows section: a **Last update** tile and **Last update installed** row show
  when Windows last received an update (date + KB number).
- Overview hero: the Windows installation date now appears in the identity
  block ("Installed") right below the OS line.

## [2.0.1] - 2026-10-17

Code-quality release: no functional or visual changes. The script now passes
[PSScriptAnalyzer](https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview)
1.25.0 (its default rule set) with zero findings.

### Changed

- Internal functions renamed to Microsoft's approved verbs and singular nouns:
  section collectors are now `Read-*` (was `Collect-*`), `Build-HtmlReport`,
  `Build-HtmlHero` and `Build-AutoSummary` are now `ConvertTo-*`, `New-Section`
  is now `ConvertTo-Section`, and so on.
- `Add-SectionTable` is invoked with named parameters everywhere.
- Colored `Write-Host` console output is now an explicitly declared and
  justified exception to the "avoid Write-Host" rule.

### Fixed

- Date parsing helpers no longer use empty `catch` blocks and are marginally
  faster.
- Removed three unused variables left over from earlier refactors.
- Report footer and JSON `scanner.version` now read `2.0.1`.

## [2.0.0] - 2026-10-17

The "ultimate dashboard" release: a complete redesign of the HTML report plus
new sharing and personalization options. The report layout, design system and
component library are now considered final and extensible - new sections plug
into the existing system without any redesign.

### Added

- **Overview dashboard**: bento hero with device identity, an auto-written
  plain-language summary anyone can read (no jargon), four KPI tiles
  (CPU, memory ring, GPU, storage) and a system-health pill strip.
- **Widgets per section** rendered above the raw tables: stat tiles, memory and
  battery rings, free-space bars, disk cards with SMART wear/temperature,
  volume bars, network LED cards with copyable IPv4/MAC/gateway/DNS,
  memory module cards, monitor cards, a security checklist with plain-language
  explanations for every check, a Windows update timeline and peripheral chips.
- **Search everywhere**: press `/` to focus the live filter, `Esc` to clear,
  with a no-matches empty state and a live row counter.
- **Sortable tables**: click (or Enter/Space on) any header; numeric, version
  and date columns sort correctly via `data-v` sort keys; `aria-sort` kept
  in sync.
- **Click-to-copy** on identifiers (serials, MACs, IPs, hostnames, UUIDs) with
  a toast confirmation and a copied-cell flash.
- **Theme control**: three-way Auto / Latte / Mocha segmented switch; Auto
  follows the OS in real time; cross-fade transition via View Transitions API
  where supported; choice remembered per browser.
- **`-Accent`** parameter: pick any of the 14 Catppuccin hues as the dashboard
  accent (default Mauve).
- **`-Redact`** parameter: replaces hostname, user names, serial numbers, MAC
  addresses, IP addresses, SSIDs and owner/org strings with deterministic
  placeholders for safe sharing; redacted reports are visibly marked.
- **`-Theme Auto`** option (in addition to Mocha and Latte).
- Scroll-progress hairline, scroll-spy navigation, collapse/expand all button,
  footer with project link and a print button.
- Inline SVG favicon, `theme-color` meta, `@media (forced-colors: active)`
  support, `::selection` styling and full `prefers-reduced-motion` handling.
- New **Firewall** collection (profiles table + per-profile state) and
  Windows Update history timeline.
- Full CSS design-system rewrite: theme-aware `--fg-*` token layer, semantic
  status colors, and a programmatically verified WCAG AA contrast pass for
  both themes.

### Changed

- Report chrome is "quiet": structural accents no longer use status colors;
  green/yellow/red now appear only for actual health meaning.
- Memory summary shows installed RAM in the hero/KPIs (e.g. "24.00 GB") while
  keeping Windows-visible memory in the detail section, matching how Windows
  itself reports it.
- JSON output bumped to `"version": "2.0.0"`.

### Fixed

- Version-like table values (e.g. driver versions) now sort semantically
  instead of as floats.
- Removed all "(s)" pluralization artifacts from captions.
- Fixed un-suppressed `ArrayList.Add` calls that could pollute section objects
  with stray indices on some systems.

### Removed

- Section entrance animations (design rule: no entrance motion - only hover
  micro-transitions, open/close and theme cross-fade).

## [1.0.0] - 2026-10-17

### Added

- Initial release: single-file PowerShell CLI scanning 14 sections
  (System, CPU, Memory, Graphics, Displays, Storage, Network, Audio, Battery,
  Security, Windows, Peripherals, Installed Software, Services).
- Single self-contained HTML report (Catppuccin Mocha / Latte with toggle),
  zero network requests, offline-safe; JSON output via `-Format Both`.
- `-Sections`, `-OutputPath`, `-NoOpen`, `-Theme` parameters; works unelevated
  with clear annotations for details that need admin rights.
- True VRAM via registry (beats the WMI 4 GB cap), SMART data, BitLocker, TPM
  and battery health detail when elevated.
