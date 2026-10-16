# classify/ — MAVHoney-D46 intent classifier

`classifier.py` implements the exact rule in Table 3 of the manuscript, using only
protocol-level observables (decoded MAVLink message name / NON_MAVLINK_PROBE):

| Priority | Label   | Condition |
|----------|---------|-----------|
| 0 | *(unlabeled)* | Session sent no application-layer bytes (no adaptive row) |
| 1 | CONTROL | valid MAVLink command message (COMMAND_LONG, SET_MODE, COMMAND_INT, MISSION_ITEM, PARAM_SET, SET_ACTUATOR_CONTROL_TARGET) |
| 2 | RECON   | valid MAVLink liveness/telemetry/param message (HEARTBEAT, PARAM_REQUEST_READ, SERVO_OUTPUT_RAW, ...) |
| 3 | UNKNOWN | MAVLink-framed but not a validatable command/telemetry message |
| 4 | SCANNER | application-layer bytes with no MAVLink frame (NON_MAVLINK_PROBE) |

ASN, GreyNoise membership, and geolocation are **not** inputs.

Verify it reproduces the released labels exactly:

    python classifier.py ../dataset      # -> mismatches: 0
