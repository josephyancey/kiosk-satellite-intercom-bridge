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

Only one bridge runs on the network at a time, so it is safe to install it on several kiosks: the others stand by, and one takes over within a minute or two if the running one goes away. With a fleet, install it on the leader and add it to the profile's **Plugins** row, with **Plugin secrets** on under the profile's Credentials so the key and house word go along too. Leave **This kiosk's address** empty there, so each kiosk finds its own.

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

`http://<kiosk>:8790/status` shows whether this copy is the one running, what it found, how its last mDNS looks went and the calls in progress.

## How it works

Every Echo gets a stand-in kiosk, advertised over mDNS on this kiosk's address with its own port, which the kiosks list and call. Every kiosk gets a stand-in TECHO5 device the same way. A call to a stand-in becomes a call to the real device, and the bridge carries the audio between them, converting Kiosk Satellite's 80 ms frames to TECHO5's 20 ms ones. Each stand-in is marked as one in its mDNS record, so a bridge never stands in for another bridge's stand-ins. Version 1.0.2 also knows the unmarked stand-ins of earlier versions, but those earlier versions do not know the mark, so update every copy.

- The TECHO5 side uses the same Noise handshake the devices do (Noise_NNpsk0_25519_ChaChaPoly_SHA256, keyed by the house word).
- The Kiosk Satellite side follows the intercom protocol [Kiosk Phone](https://github.com/mpjanofsky/kiosk-phone) documented. No Kiosk Satellite code is used.
- The running bridge advertises `_intercom-bridge._tcp`. A copy that finds one alive stands by and looks again every 30 seconds. It takes over after two looks in a row clearly found none running. A look in doubt, one that failed or found a bridge it could not reach, never counts as clear, so a missed answer does not start a second bridge; only about five minutes of such looks, for a bridge that went without saying goodbye, let it take over. If two run at once anyway, the one that started first stays.

The plugin needs no capabilities. It finds devices by listening to mDNS itself, the way Kiosk Satellite finds its fleet, since some Android builds' mDNS service misses much of what kiosks announce. It listens only to the mDNS group, so it never takes replies meant for Android or Kiosk Satellite, and holds a Wi-Fi multicast lock while it runs. It advertises through Android's mDNS service, which also does the looking if the group cannot be joined; the status page then says why, under `listener`. Android's service announces a stand-in only once, and Kiosk Satellite drops a kiosk it has not heard from in 100 seconds, so the bridge also announces every stand-in to the group itself every 30 seconds, and says goodbye for each when it goes. The status page shows how that goes, under `announcing`.

Nothing leaves your network. The plugin talks only to the kiosks and Echos it finds and to other copies of itself. Call audio and announcements pass through it without being recorded, and the key and house word stay on the kiosk.

## Trust model

The bridge joins two intercoms, so a secret for either one now reaches both:

- **Anyone with the house word can ring every kiosk**, not just the Echos. A kiosk set to auto-answer then streams its microphone to whoever called. Treat the house word like the intercom key, and turn off auto-answer on kiosks where that matters.
- **Anyone with the intercom key can ring every Echo**, and an Echo with Drop In on answers by itself.
- **Announcements also take the house word in plain text.** Older TECHO5 devices send it in the `X-Techo5-House` header instead of signing, and the bridge accepts that too, as the devices do. Anyone who can watch the network can read it from such a request.
- **Requests are checked as early as each protocol allows.** A kiosk's call token is checked before its body is parsed; an announcement's signature covers its voice, so that body is read first, within a 640 KB cap. The bridge also limits how many connections it serves and how much data it holds for senders it hasn't checked yet, since it runs inside Kiosk Satellite.
- **Only bridges with the same intercom key count** when one decides whether to stand by. The status page proves the key with an HMAC of a nonce the asking bridge sends, so a host that only claims to be a bridge is ignored.

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

[Apache-2.0](LICENSE). Kiosk Satellite has its own application license. This plugin is not affiliated with or endorsed by Kiosk Satellite or TECHO5. The handshake in `Sealed.java` follows TECHO5's (MIT, Copyright (c) 2026 TECHO5 contributors), and the X25519 code in `Crypto.java` follows [TweetNaCl](https://tweetnacl.cr.yp.to), which is in the public domain. The handset in the icon is `phone_in_talk` from Google's [Material Icons](https://github.com/google/material-design-icons), also Apache-2.0.
