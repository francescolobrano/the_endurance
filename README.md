# The Endurance

A show-risk monitor for live-show Macs. It watches the machine that runs your show (QLab and other key apps), tells you at a glance how close it is to trouble, and serves everything as a web page you can open from your phone.

Crafted by Francesco Lo Brano. Version 0.9.0 (pre-release).

> **Status: pre-release.** Developed and used on real shows, but several features have only been tested with simulations. See [Tested / untested](#tested--untested).

## What it does

- **DEFCON level (5 to 1):** a single risk score built from CPU, per-core load, RAM and memory pressure, swap, temperature, thermal limit, disk and key-app usage, with a history log (exportable as PDF/CSV).
- **Key app monitoring:** QLab (active cue timers over OSC), Keynote, Reaper, Smaart (multi-input SPL), PowerPoint, Live Professor (DSP load) and a "QLab + Live Professor" combined mode. More readers are marked beta.
- **Main / backup Macs:** reads other Macs running The Endurance or QLab on the network, pings, and a manual QLab main-to-backup sync (locked in SHOW mode).
- **Network and disk views:** interfaces, device discovery, disk space, throughput, latency and S.M.A.R.T. status.
- **OSC monitor:** live view of OSC messages on chosen interfaces.
- **Workspace autosave** for QLab, **EDIT / SHOW** modes, and an opt-in choice of which network ports the app may touch.
- Runs with a native control window on the Mac and a web page designed for Safari on iPhone (default port `8080`).

Everything is local. Nothing is sent to the internet, and the browser is never opened automatically.

## Requirements

- macOS (Apple Silicon or Intel). Python 3 is **bundled** in the release, so nothing has to be installed.
- For QLab: OSC enabled in the workspace (TCP, port 53000).
- For Smaart: API enabled (default `localhost:26000`), with logging on for the inputs you want to see.
- For Live Professor: *Options > Project Options > Osc Control* enabled, input port 8000, output port 9000, and the *OSC Controller Address* set to `127.0.0.1`.

## Install

1. Download the latest zip from the [Releases](../../releases) page. It contains the app, a PDF install guide and a short PDF presentation.
2. Unzip it. If a previous version is open, quit it first.
3. The app is **not signed with an Apple developer certificate**, so macOS will block the first launch. The install guide in the zip lists the exact steps and the Terminal commands to open it.
4. Start the monitor from the control window, then open `http://<MAC-IP>:8080` on your phone.

## Repository layout

```
The_Endurance.app/Contents/
  MacOS/launcher                   bash launcher and control commands
  Resources/endurance.py           monitor and web server (Python standard library only)
  Resources/endurance_temp.py      CPU temperature reader (IOKit), run as a separate process
  Resources/endurance_window.js    control window (JXA + WebKit)
  Resources/window.html            control window page
  Info.plist
```

The bundled Python runtimes (`python-aarch64`, `python-x86_64`) are not in the repository. They are included only in the zip attached to each release. To run from source, use any Python 3 with `python3 endurance.py`.

## Tested / untested

Tested on real Macs (Apple Silicon, MacBook Pro and Air): the core monitor, DEFCON, QLab cue timers, Smaart multi-input SPL and Live Professor DSP load.

Not yet tested on real hardware or workspaces:

- QLab main-to-backup sync
- Call between two Macs
- PowerPoint through OSC (OSCPoint) and PowerPoint Automation
- Quit from the Dock menu
- Beta key-app readers (Ableton, Arena, vMix and others)
- Scale of the Live Professor DSP value (assumed 0 to 1, shown as a percentage)

## Disclaimer

The Endurance is a monitoring aid, not a guarantee. It can be wrong or silent. Do not rely on it as the only safeguard for a live show. Use it at your own risk; see the license for the full warranty disclaimer.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Francesco Lo Brano.
