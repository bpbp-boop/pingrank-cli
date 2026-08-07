# PingRank.gg

PingRank measures your real ping while you play. It finds the game you are
running, finds the server the game talks to, and times the round trip.
Players who share their recordings power the ISP rankings at
[pingrank.gg](https://pingrank.gg).

```
> pingrank

game: Counter-Strike 2 (pid [21384])
candidate endpoints (2):
 1. udp 155.133.252.1:27015  confidence: high
      latency: 11/12.4/15 ms min/avg/max, 0% loss
 ...
```

## Install

Download the `.msi` from the [releases page](https://github.com/bpbp-boop/pingrank-cli/releases/latest)
and run it. It installs:

- the `pingrank` command-line tool,
- a Windows service that records supported games while you play,
- a tray icon that shows what the service is doing.

The service shares recordings by default. Use `pingrank record -no-share`
to keep a recording on your machine. Uninstalling keeps your recorded
sessions.

The installed service already has the rights it needs — you do not have
to do anything. Only if you run `pingrank` yourself in a terminal, run it
**as administrator**: without that, Windows does not show UDP
connections, and most games use UDP.

## Usage

```
pingrank              one shot: find the game, find its server, ping it, report
pingrank --json       the same data as JSON
pingrank --watch      keep running; report again when the server changes
pingrank --game x.exe measure a specific exe instead of a detected game

pingrank record       record a whole session: waits for a game, samples its
                      server every 10 s until the game exits (or ctrl+c),
                      then prints a summary and stores the session
  -no-share             keep the recording on this machine
  -interval <dur>       time between samples (default 10s, minimum 5s)
  -for <dur>            stop after a fixed time
  -json                 stream records as JSONL
  -game <exe>           as above
pingrank sessions     list stored sessions (game, duration, p50, loss)
pingrank show <name>  print a stored session (-json for the raw records)
pingrank submit <name> send one stored session to pingrank.gg
  -dry-run              print what would be sent; send nothing
  -flush                retry queued submissions only
  -server <url>         use a different server
pingrank access       test how your connection reaches the internet
                      (CGNAT, NAT64, DS-Lite, native, …)
  -refresh              run the tests again now
  -json                 the full evidence as JSON
pingrank parse-log    read match servers from a game's own log file
  -game <id>            log format (currently rocketleague)
  -json                 structured JSON
```

If no known game is running, `pingrank` lists candidate programs for
`--game` and exits.

## How it works

1. **Detect.** The tool reads the Windows process list. It matches program
   names against its list of games. It does not open the game process.
2. **Find the server.** Windows reports each connection the game makes:
   the address, the port, and the packet counts. The tool selects the
   connection that carries the match.
3. **Ping.** The tool times the round trip to that server. It asks in the
   game's own protocol when the game has one. If not, it sends a standard
   ping. If the server does not answer, it times the last router that does
   answer, and it marks that result as an estimate.

The [pingrank.gg FAQ](https://pingrank.gg/faq) explains each method.

## What leaves your machine

Nothing, until a recording is shared. A shared recording contains:

- the ping stats for each server (latency, jitter, loss),
- the game name and the app version,
- evidence about how your connection reaches the internet,
- a random installation ID, made on your machine.

It contains no account, no MAC address, and no hardware ID.
`pingrank submit -dry-run` shows the exact bytes before anything is sent.
The server uses your IP address once, to find your ISP, then discards it.
The full inventory is at [pingrank.gg/privacy](https://pingrank.gg/privacy).

If an upload fails, the tool stores it and tries again later. A failed
upload never interrupts a recording.

## Safe with anti-cheat

PingRank watches Windows, never the game:

- It loads no code into the game.
- It does not read the game's memory or its files.
- It does not capture your traffic. It reads only the facts Windows
  reports about each connection: addresses, ports, and packet counts.
- It uses only documented Windows interfaces — the same ones the Windows
  Resource Monitor uses.

## Limitations

A standard ping reports whole milliseconds, and some networks slow pings
down. Last-hop results read a little low; they are marked as estimates.

## Add a game

One entry in [internal/detect/signatures.json](internal/detect/signatures.json):
`gameId`, `displayName`, `exeNames`, and optional hints (known server
ports, a game-protocol probe, relay networks). About 22 games ship today.
Pull requests are welcome.

## Build from source

```
go build ./cmd/pingrank
```

Windows amd64. One static binary. No cgo.

## Releases

GitHub Actions builds every tagged release from this source
([release.yml](.github/workflows/release.yml)) — never a developer
machine. To check that a download came from this source:

```
gh attestation verify pingrank.exe --owner bpbp-boop
```

or compare its SHA-256 with `checksums.txt`.

## License

[MIT](LICENSE).
