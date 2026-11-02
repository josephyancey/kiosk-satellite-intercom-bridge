# Intercom Bridge

A [Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) plugin that lets Kiosk Satellite kiosks and [TECHO5](https://github.com/HuskerMinion/techo5) Echos call and announce to each other. Each Echo shows up in the kiosks' intercom list like any other kiosk, and each kiosk shows up in the Echos' call list.

Calling works either way, by touch or by voice ("call the kitchen" from an Echo rings the kitchen kiosk), and so does answering, including a kiosk's auto-answer and an Echo's Drop In. A kiosk's **Announce to all** plays on the Echos, and an Echo's announcement plays on the kiosks. Calls can also hang up on silence, for an Echo that has no button to end them.

## Installation

### Community Plugins (Recommended)

Intercom Bridge is listed in [Community Plugins](https://kiosksatellite.com/plugins/). Use the button below to open it in your Kiosk Satellite and install it.

[![Install in Kiosk Satellite](https://kiosksatellite.com/img/badges/plugin-add.svg)](https://kiosksatellite.com/redirect/plugin/?repository=josephyancey/kiosk-satellite-intercom-bridge)

Or search for `Intercom Bridge` in **Settings > Plugin Manager > Browse plugins** in Kiosk Satellite.

### Manual

1. Open **Settings > Plugin Manager** in Kiosk Satellite and turn on **Enable Plugins**.
2. Choose **Add plugin**, paste `https://github.com/josephyancey/kiosk-satellite-intercom-bridge` and choose **Preview**.
3. Review the plugin and choose **Trust and install**.

## Setup

1. Set a house word on the TECHO5 devices under **Sound & Voice**.
2. Turn off intercom encryption (TLS) under **Intercom** on the kiosks. The bridge does not speak it yet.
3. Enable the plugin on a kiosk that stays on and enter the **Kiosk Satellite intercom key** (from **Settings > Intercom**) and the **TECHO5 house word**. Within a minute the status line shows the kiosks and Echos it found, and the Remote Admin Overview has an **Intercom bridge** tile.

Only one bridge runs on the network at a time, so it is safe to install it on several kiosks: the others stand by, and one takes over within about a minute if the running one goes away. With a fleet, install it on the leader and add it to the profile's **Plugins** row, with **Plugin secrets** on under the profile's Credentials so the key and house word go along too. Leave **This kiosk's address** empty there, so each kiosk finds its own.

## Settings

| Setting | What it does |
| --- | --- |
| Kiosk Satellite intercom key | The fleet's intercom key. Stored as a secret, masked in the Plugin Manager |
| TECHO5 house word | The house word on the TECHO5 devices. Stored as a secret |
| Echo name suffix | Added to each Echo's name in the kiosks' list, such as ` (Echo)`. Empty by default |
| Hang up after silence | Ends a call once neither side has spoken this long. 0 s, the default, is off |
| Silence level | Sound below this, -55 dBFS by default, counts as silence for the hang-up |
| Volume to Echos | Makes kiosks louder or quieter on the Echos, 0 dB by default |
| Volume to kiosks | Makes Echos louder or quieter on the kiosks, 0 dB by default |
| This kiosk's address | The IPv4 address kiosks and Echos reach this kiosk on. Empty finds it |
| Status port | Serves `/status`, which other bridges check before they stand by. 8790 unless you change it |
| First / last stand-in port | Each kiosk and Echo gets a stand-in on one of these ports, 41000 to 41099 |

`http://<kiosk>:8790/status` shows whether this copy is the one running, what it found and the calls in progress.

## How it works

Every Echo gets a stand-in kiosk, advertised over mDNS on this kiosk's address with its own port, which the kiosks list and call. Every kiosk gets a stand-in TECHO5 device the same way. A call to a stand-in becomes a call to the real device, and the bridge carries the audio between them, converting Kiosk Satellite's 80 ms frames to TECHO5's 20 ms ones.

- The TECHO5 side uses the same Noise handshake the devices do (Noise_NNpsk0_25519_ChaChaPoly_SHA256, keyed by the house word).
- The Kiosk Satellite side follows the intercom protocol [Kiosk Phone](https://github.com/mpjanofsky/kiosk-phone) documented. No Kiosk Satellite code is used.
- The running bridge advertises `_intercom-bridge._tcp`. A copy that finds one alive stands by and looks again every 30 seconds. If two run at once, the one that started first stays.

The plugin needs no capabilities. It reaches Android's mDNS service through the app's context.

Nothing leaves your network. The plugin talks only to the kiosks and Echos it finds and to other copies of itself. Call audio and announcements pass through it without being recorded, and the key and house word stay on the kiosk.

## Limits

- Kiosk Satellite's intercom encryption (TLS) must be off.
- The status page has no password. Anyone on the network can see the devices found, their addresses and the calls in progress.
- Kiosks and Echos must hear each other's mDNS. Across VLANs, the router has to relay it.

## Build and test

Install Python 3, JDK 17 or newer and an Android SDK with a platform and build-tools. Set `ANDROID_HOME` and `JAVA_HOME` as needed.

```sh
python3 tools/test.py
python3 tools/build.py
```

The build writes `dist/intercom-bridge-<version>.zip`. For local testing, install it with **Plugin Manager > Developer Tools > Install from ZIP**. Without a local SDK, `build.sh` runs both inside the `ghcr.io/cirruslabs/flutter` image:

```sh
docker run --rm -v "$PWD:/src" ghcr.io/cirruslabs/flutter:3.44.0 sh /src/build.sh
```

The SDK sources in `sdk/` and the build tools in `tools/` come from the [Kiosk Satellite plugin SDK](https://github.com/jxlarrea/kiosk-satellite-plugins).

## License

[Apache-2.0](LICENSE). Kiosk Satellite has its own application license. The handshake in `Sealed.java` follows TECHO5's (MIT, Copyright (c) 2026 TECHO5 contributors), and the X25519 code in `Crypto.java` follows [TweetNaCl](https://tweetnacl.cr.yp.to), which is in the public domain. The handset in the icon is `phone_in_talk` from Google's [Material Icons](https://github.com/google/material-design-icons), also Apache-2.0.
