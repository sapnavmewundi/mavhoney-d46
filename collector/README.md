# collector/ — active low-interaction MAVLink deception honeypot

- `mavlink_honeypot.py`: the TCP listener daemon that generated the released
  dataset. It is an **active, low-interaction deception honeypot**: on each
  connection it emits a MAVLink HEARTBEAT beacon, presents a decoy "ArduPilot GCS"
  authentication prompt, and replies to client MAVLink messages with crafted
  telemetry (HEARTBEAT, GPS, battery, ACK). It is **not** a silent passive
  listener. See the manuscript Methods ("Interaction model" / "Listener behavior")
  for the full description.
- `protocol.py`: MAVLink v2 frame parser (start byte 0xFD, CRC-16/MCRF4XX with
  per-message CRC_EXTRA; v2 trailing-zero truncation handled), used to decode
  candidate frames.

Note: `source_id` in the released dataset is a keyed HMAC-SHA256 pseudonym; the
key is a secret and is **not** included in this release. Provide it via the
`MAVHONEY_HMAC_KEY` environment variable only if re-deriving ids from raw IPs.
