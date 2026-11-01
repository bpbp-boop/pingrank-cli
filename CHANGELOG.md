# Changelog

Each release on GitHub uses its section from this file as its notes.

## v0.8.1 (2026-11-01)

- No changes to the app. This release tests automatic updates from v0.8.0.

## v0.8.0 (2026-11-01)

- The app now updates itself. About every six hours the service asks
  pingrank.gg for the newest version. When it finds one, it downloads the
  installer from GitHub, checks the checksum and the signature, and installs
  it between games. The tray icon closes during the update and comes back
  after it.
- To turn updates off, untick **Install updates automatically** in the tray
  menu, or run `pingrank updates off` as administrator. `pingrank updates`
  shows the current setting.
- This version does not reach you by itself: install it by hand once. Later
  versions arrive by themselves.

## v0.7.16 (2026-11-01)

- Detects six more games: FiveM, Team Fortress 2, ARC Raiders, Dead by
  Daylight, DayZ and Delta Force.
- Knows more of Valve's relays: Sydney, Singapore, Hong Kong and Tokyo, and
  four relays Valve rents in Frankfurt, London, Vienna and Fujairah. CS2,
  Dota 2 and Team Fortress 2 results through these relays now show as relay
  results. See [relay networks](https://pingrank.gg/faq#relay).
- Finds Rocket League's game server on its new ports. Rocket League moved its
  servers to ports 9001–9102 in September.

## v0.7.15 (2026-09-29)

- Detects four more games: Rust, EA Sports FC (FC 25 and FC 26), WARDOGS and
  Path of Exile (1 and 2).

## v0.7.14 (2026-09-05)

- Tells Valorant's game traffic apart from its voice and test traffic. The
  app now measures only the game server.

## v0.7.13 (2026-08-28)

- The app and installer now carry a code signature from a Certum
  certificate.

## v0.7.12 (2026-08-12)

- New `--version` flag (or `-v`) prints the app version.
- Removed the `pingrank submit` command. `pingrank record` shares each session
  itself.

## v0.7.11 (2026-07-23)

- The installer ends on a clear "finished" screen.

## v0.7.10 (2026-07-22)

- No changes to the app. Release process fix only.

## v0.7.9 (2026-07-22)

- Fixes IPv6 game traffic. Windows reports IPv6 traffic with a different
  event code, and the app rejected those events, so it missed games that
  reach their servers over IPv6. The app now accepts them.
- The v0.7.8 build failed, so this is the first release with the fix.

## v0.7.6 (2026-07-19)

- First public release.
