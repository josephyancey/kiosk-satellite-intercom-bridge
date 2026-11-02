# Intercom Bridge

A [Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) plugin that lets Kiosk Satellite
kiosks and [TECHO5](https://github.com/HuskerMinion/techo5) Echos call and announce to each other.
It runs inside a kiosk, so there is no server to keep up.

## What it does

- **Echos show up on the kiosks.** Each TECHO5 device appears in **Call a kiosk** like any other
  kiosk, and calling it rings the Echo. Calling a room by voice works too.
- **Kiosks show up on the Echos.** Each kiosk appears in the TECHO5 call list, and "call the
  kitchen" from an Echo rings the kitchen kiosk.
- **Answering works either way**, including a kiosk's auto-answer and an Echo's Drop In.
- **Announcements cross over.** A kiosk's **Announce to all** plays on the Echos, and an Echo's
  announcement plays on the kiosks.
- **Calls can hang up on silence**, for an Echo that has no button to end them.

## One bridge at a time

Only one bridge runs on the network at a time. The one running advertises itself over mDNS, and
the copies on other kiosks stand by. When the running one stops, because its kiosk restarted or
lost its network, a standby takes over within about a minute. So you can install it on two or
three kiosks, or on the whole fleet.

## Installation

### Community Plugins (Recommended)

Intercom Bridge is listed in [Community Plugins](https://kiosksatellite.com/plugins/). Use the button below to open it in your Kiosk Satellite and install it.

[![Install in Kiosk Satellite](https://kiosksatellite.com/img/badges/plugin-add.svg)](https://kiosksatellite.com/redirect/plugin/?repository=josephyancey/intercom-bridge-plugin)

Or search for `Intercom Bridge` in **Settings > Plugin Manager > Browse plugins** in Kiosk Satellite.

### Manual

1. Open **Settings > Plugin Manager** in Kiosk Satellite and turn on **Enable Plugins**.
2. Choose **Add plugin**, paste `https://github.com/josephyancey/intercom-bridge-plugin` and choose **Preview**.
3. Review the plugin and choose **Trust and install**.

## Set up

1. On the TECHO5 devices, set a house word under **Sound & Voice**.
2. Install the plugin on a kiosk that stays on. On a fleet leader, add it to a fleet profile to
   give every follower a standby copy.
3. Open the plugin and enter the **Kiosk Satellite intercom key** (from **Settings > Intercom**) and
   the **TECHO5 house word**, then enable it.

Within a minute the plugin's status shows the kiosks and Echos it found, and the Remote Admin
Overview has an **Intercom bridge** tile.

Kiosk Satellite's intercom encryption (TLS) must be off: the bridge does not speak it yet.

## Settings

| Setting | Default | What it is |
|---|---|---|
| Kiosk Satellite intercom key | | The fleet's intercom key. |
| TECHO5 house word | | The house word on the TECHO5 devices. |
| Echo name suffix | none | Added to each Echo's name in the kiosks' list, like ` (Echo)`. |
| Hang up after silence | 0 s | End a call once neither side has spoken this long. 0 is off. |
| Silence level | -55 dBFS | Below this counts as silence. |
| Volume to Echos / to kiosks | 0 dB | Make one side louder or quieter on the other. |
| This kiosk's address | found | The IPv4 address devices reach this kiosk on. |
| Status port | 8790 | Serves `/status`, which other bridges check. |
| First / last stand-in port | 41000-41099 | Each kiosk and Echo gets a stand-in on one of these ports. |

`http://<kiosk>:8790/status` shows whether this copy is the one running, what it found, and calls
in progress.

## How it works

Every Echo gets a stand-in kiosk, advertised on this kiosk's address with its own port, which the
kiosks list and call. Every kiosk gets a stand-in TECHO5 device the same way. A call to a stand-in
becomes a call to the real device, and the bridge carries the audio, converting Kiosk Satellite's
80 ms frames to TECHO5's 20 ms ones. The TECHO5 side uses the same Noise handshake the devices do
(Noise_NNpsk0_25519_ChaChaPoly_SHA256, keyed by the house word); the Kiosk Satellite side follows
the protocol [Kiosk Phone](https://github.com/mpjanofsky/kiosk-phone) documented. No Kiosk
Satellite code is used.

The plugin needs no special capabilities. It reaches Android's mDNS service through the app.

## Where data goes

Nothing leaves your network. The plugin talks only to the kiosks and TECHO5 devices it finds over
mDNS, and to other copies of itself. Call audio and announcements pass through it between those
devices, encrypted on the TECHO5 side and sent as Kiosk Satellite's own intercom sends them on the
kiosk side; it records nothing. The intercom key and house word stay on the kiosk. The status page
on port 8790 has no password and lists the devices found, their addresses and calls in progress,
to anyone on the network.

## Building

Needs Python 3, JDK 17 or newer, and an Android SDK with a platform and build-tools.

```sh
python3 tools/test.py
python3 tools/build.py
```

The ZIP lands in `dist/`. For a test build, use **Plugin Manager > Developer Tools > Install from
ZIP**. Releases are built by GitHub Actions from a published release tag.

## License

MIT. The SDK and build tools under `sdk/` and `tools/` come from the
[Kiosk Satellite plugin template](https://github.com/jxlarrea/kiosk-satellite-plugins) under
Apache-2.0 (`LICENSE-SDK`). See `THIRD_PARTY.md`.
