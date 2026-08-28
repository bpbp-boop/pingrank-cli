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

The release workflow stamps and signs all three binaries. It then builds and
signs the MSI on a Windows runner. A manual run makes the same signed files but
does not publish a release.

## Code signing

The release workflow uses the Certum SimplySign cloud certificate for this
publisher:

```text
Open Source Developer Boden Phillip Garman
```

The workflow checks for certificate thumbprint
`2D9973F2187731CEEC973E9FCA542B73ACFE81F5`. It signs each file with SHA-256 and
uses Certum's time stamp service. It stops SimplySign before it uploads or
publishes files.

Configure the public GitHub mirror before the first signed run:

1. Create an environment named `code-signing`.
2. Add a required reviewer. This makes each signing run wait for approval.
3. Add the environment secret `CERTUM_USERNAME`. Set it to the SimplySign
   account name.
4. Add the environment secret `CERTUM_OTP_URI`. Set it to the full
   `otpauth://` value from the SimplySign activation QR code.

The OTP URI contains the seed that generates each login code. It grants access
to signing. Keep it secret. Do not put it in a repository secret, file, command,
issue, or log. If the activation QR code is no longer available, use Certum's
regain-access process to get a new QR code. Store its `otpauth://` value in a
password manager and in the protected GitHub environment.

The workflow names one fixed SimplySign helper commit. It also checks the
SHA-256 of the SimplySign Desktop installer before it runs the installer. Review
and update both values when Certum requires a new desktop version.

Run the workflow by hand once before the next release. Enter the next version
without a leading `v`. Download the `signed-windows` artifact and check the
Digital Signatures tab on the three EXEs and the MSI. Windows must show the
publisher above and a valid time stamp.

## winget

`winget/` holds manifests for the community repository
([microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)) under
the identifier `PingRank.PingRank`. They match the v0.7.12 release exactly;
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
