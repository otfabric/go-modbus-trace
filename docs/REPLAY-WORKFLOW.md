# From a trace to a virtual device

A packet trace of a Modbus/TCP installation can become a virtual device: `mbtracectl` exports what the clients read as an [MBCAP](https://github.com/otfabric/go-modbus-capture) capture, and [modbusctl](https://github.com/otfabric/modbusctl) serves it. This page is the workflow and what to expect from the result. The design behind it is in [MBCAP-EXPORT.md](MBCAP-EXPORT.md).

## 1. Look at the trace

```sh
mbtracectl info    site.pcapng                       # format, interfaces, drops, snap length, quality
mbtracectl flows   site.pcapng                       # which flows are Modbus/TCP, on which ports
mbtracectl summary site.pcapng --server-port 502,1502
```

`summary` lists every server and unit with its functions, statuses, clients and latency, the poll patterns (what each client asks for, how often, how regularly, how often the answer changes), and the address ranges read and written. Check:

- **Drops and gaps** (`info`): a capture that lost packets lost reads; the export says so but cannot bring them back.
- **Roles** (`flows`): a connection whose handshake was not captured gets its roles from the port (`--server-port`) or the traffic. Name the servers with `--server` when in doubt.
- **Writes** (`summary`, "addresses read (written)"): a write is not replayed. A value written after the last read keeps its pre-write value in the replay.

Several files of one capture (a ring buffer, say) are read as one trace: `mbtracectl summary ring_*.pcapng`.

## 2. Export

```sh
mbtracectl export mbcap site.pcapng -o site.mbcap --report site.report.json
mbcapctl verify site.mbcap && mbcapctl info site.mbcap
```

Only answered reads that were paired with certainty become samples: FC01–04, 07, 08 (data-returning sub-functions), 11, 12, 17, 20, 24 and 43/14, and their exception responses. Everything else is counted in the report by reason (`write_function`, `unanswered`, `resynced`, ...) and never written. The report's identity `transactions_seen = samples_written + change_only_dropped + sum(excluded)` always holds.

Useful options:

- `--from 10m --to 20m`, `--server`, `--unit`, `--fc`: export part of the trace. A window does not carry in the values read before it.
- `--name 10.0.0.2:502/1=Inverter`: a label for a target.
- `--change-only`: drop repeated identical responses. The replay is the same under sample and hold; only the poll cadence is lost.
- `--format jsonl|csv`: a readable capture (`.jsonl`, long `.csv`); `mbcapctl convert` converts between all three.
- `--warn-replay-memory 512MiB`: warn when the replay is estimated to need more (default 1 GiB, `0` turns it off).

Read the warnings: `unit_collision`, `stale_after_write`, `capture_drops`, `gap_in_window`, `role_guessed`, `single_sample_target`, `time_disorder`, `replay_memory`. Every export also warns `format_draft`: MBCAP is a draft, and a 1.0 reader will not read today's file.

## 3. Serve

```sh
modbusctl server replay --input site.mbcap --listen 127.0.0.1 --port 1502 \
        --speed 1 --loops 0 --before-first absent --missing exception
modbusctl server static --input site.mbcap --listen 127.0.0.1 --port 1502 \
        --target 2 --unit 1 --at 10m
```

`replay` plays the capture in time (`--speed`, `--loops`, `--from`); `static` serves the values as they were at one moment (`--at`). modbusctl listens on every interface by default: give `--listen 127.0.0.1` unless the device must be reachable.

## 4. What a replay is and is not

1. **Sample and hold.** A value holds from its sample until the next sample of the same address (FC01–04), of the same request (FC07, 08, 11, 12, 17, 20, 24) or of the same identity object (FC43). Nothing is interpolated.
2. **Only what was read exists.** A passive trace holds exactly what the observed clients asked for. Anything else is answered per `--missing`; `exception` makes absent data visible.
3. **Writes are not replayed.** A value changed by a write shows up at its next read; `stale_after_write` names the ranges where no read followed.
4. **Recorded exceptions are not served** as device state.
5. **Strict timing** needs `--before-first absent`; the default `hold` serves the first sample from the start.
6. **Unit collisions.** Two servers that both use unit 1 are two targets, and one listener cannot serve both. Run one replay per target (`--target N --port P`) or remap one with `--unit`.
7. **Times** are when the capture point saw each response complete, not device timestamps; latency is not replayed.
8. **Several clients** of one device are merged by time; at nearly the same time the later sample wins.
9. **Memory.** modbusctl loads the whole capture: about 12 MiB plus 750 bytes per sample plus 36 bytes per changed value, which the report estimates. The file size says nothing about it. For a long trace, export a window.
