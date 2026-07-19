# Windows MSI

The WiX source installs three static x64 binaries and the website icon under
`%ProgramFiles%\PingRank`:

- `pingrank.exe` — the existing CLI
- `pingrank-service.exe` — automatic LocalSystem service (`PingRank`)
- `pingrank-tray.exe` — per-user notification-area status companion
- `pingrank.ico` — the PingRank.gg website favicon used by the tray and shell

Interactive installs launch the tray immediately. Silent installs leave it for
the next user sign-in so no GUI process is accidentally started in session 0.

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
wix build packaging\pingrank.wxs -arch x64 -d SourceDir=dist -d Version=0.7.0 -pdbtype none -out dist\pingrank.gg-0.7.0-x64.msi
```

The release workflow stamps all three binaries with the tag version and builds
the MSI on a Windows runner.

## Public-release safety gates

Before distributing a public build:

- Authenticode-sign all three EXEs and the final MSI with the same stable
  publisher identity, and use a trusted timestamp service. GitHub artifact
  attestations are useful provenance, but do not replace Authenticode for
  Windows reputation and publisher verification.
- Test the exact signed artifacts in long-running sessions against supported
  games using Easy Anti-Cheat, EA AntiCheat, BattlEye, Riot Vanguard, and
  RICOCHET where applicable. Record the client, game, anti-cheat, Windows, and
  PingRank versions and the outcome; repeat this matrix for each release.
- Publish the monitoring design (documented ETW APIs, provider GUID, keyword
  and event IDs, PID filtering, no injection, no game handles, and no driver)
  and seek compatibility review or allowlisting from anti-cheat vendors where
  they offer a channel. Describe results as compatibility testing, never as a
  guarantee that bans are impossible.
