# Windows MSI

The WiX source installs three static x64 binaries and the website icon under
`%ProgramFiles%\PingRank`:

- `pingrank.exe` — the existing CLI
- `pingrank-service.exe` — automatic LocalSystem service (`PingRank`)
- `pingrank-tray.exe` — per-user notification-area status companion
- `pingrank.ico` — the PingRank.gg website favicon used by the tray and shell

Interactive installs launch the tray immediately. Silent installs leave it for
the next user sign-in so no GUI process is accidentally started in session 0.
Interactive installs end with a success screen. It points to the tray icon and
the Start menu entry.

The service stores its identity, status, access-path cache, and sessions under
`%ProgramData%\PingRank`. Uninstall removes installed binaries, the service,
and the tray startup registration, but deliberately preserves recorded
sessions.

To build locally with WiX installed:

```powershell
New-Item -ItemType Directory -Force dist
go build -trimpath -o dist\pingrank.exe .\cmd\pingrank
go build -trimpath -o dist\pingrank-service.exe .\cmd\pingrank-service
go build -trimpath -ldflags "-H windowsgui" -o dist\pingrank-tray.exe .\cmd\pingrank-tray
wix extension add -g WixToolset.UI.wixext/6.0.2
wix build packaging\pingrank.wxs -ext WixToolset.UI.wixext -arch x64 -d SourceDir=dist -d Version=0.7.0 -pdbtype none -out dist\pingrank.gg-0.7.0-x64.msi
```

The release workflow stamps all three binaries with the tag version and builds
the MSI on a Windows runner.

## winget

`winget/` holds manifests for the community repository
([microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)) under
the identifier `PingRank.PingRank`. They match the v0.7.6 release exactly;
the hash and ProductCode come from the released MSI. Both change with every
build, so for any later version regenerate with `wingetcreate new
<msi-url>` instead of editing by hand.

winget does not wait on Authenticode: it verifies each installer against
the hash in its manifest, and Microsoft's pipeline scans every submission.
The signing gate below is for the MSI players download from the site.

To list the package:

1. Submit the first version: `wingetcreate new <msi-url>` regenerates the
   manifests and opens the PR to microsoft/winget-pkgs. A moderator
   reviews a first submission; expect a few days.
2. After it merges, turn on automatic submission of later releases: fork
   microsoft/winget-pkgs under this account, create a classic personal
   access token with `public_repo` scope, and store it as the
   `WINGET_TOKEN` secret on this repo. The "Submit to winget" step in the
   release workflow activates once the secret exists.

## Public-release safety gates

Before distributing a public build:

- Authenticode-sign all three EXEs and the final MSI with the same stable
  publisher identity, and use a trusted timestamp service. GitHub artifact
  attestations are useful provenance, but do not replace Authenticode for
  Windows reputation and publisher verification. This gate is for the
  direct download; the winget listing does not wait on it.
- Test the exact signed artifacts in long-running sessions against supported
  games using Easy Anti-Cheat, EA AntiCheat, BattlEye, Riot Vanguard, and
  RICOCHET where applicable. Record the client, game, anti-cheat, Windows, and
  PingRank versions and the outcome; repeat this matrix for each release.
- Publish the monitoring design (documented ETW APIs, provider GUID, keyword
  and event IDs, PID filtering, no injection, no game handles, and no driver)
  and seek compatibility review or allowlisting from anti-cheat vendors where
  they offer a channel. Describe results as compatibility testing, never as a
  guarantee that bans are impossible.
