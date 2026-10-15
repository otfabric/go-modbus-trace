# Function coverage

Generated from `mbtcp`'s table by `TestCoverageDoc` (`make golden`); do not edit.

Every function below is decoded and validated as a request and as a response; exception responses are decoded for every function code. Any other code (the user-defined ranges 65-72 and 100-110, vendor and unknown codes) is kept opaque: its function code and data bytes. `Class` is what the function does to the device; `MBCAP` is its admission (`MBCAP-EXPORT.md` section 3; `sub`: it depends on the FC08 sub-function or the FC43 MEI type); `Serial` marks a function normally limited to serial lines, flagged `serial_function_over_tcp` when seen over TCP.

| FC | Name | Class | Serial | MBCAP | Request fields | Response fields |
|---|---|---|---|---|---|---|
| 1 | Read Coils | read |  | yes | address, quantity | byte_count, coil_status |
| 2 | Read Discrete Inputs | read |  | yes | address, quantity | byte_count, input_status |
| 3 | Read Holding Registers | read |  | yes | address, quantity | byte_count, registers |
| 4 | Read Input Registers | read |  | yes | address, quantity | byte_count, registers |
| 5 | Write Single Coil | write |  | no | address, value | address, value |
| 6 | Write Single Register | write |  | no | address, value | address, value |
| 7 | Read Exception Status | read | yes | yes |  | status |
| 8 | Diagnostics | other | yes | sub | sub_function, data | sub_function, data |
| 11 | Get Comm Event Counter | read | yes | yes |  | status, event_count |
| 12 | Get Comm Event Log | read | yes | yes |  | byte_count, status, event_count, message_count, events |
| 15 | Write Multiple Coils | write |  | no | address, quantity, byte_count, values | address, quantity |
| 16 | Write Multiple Registers | write |  | no | address, quantity, byte_count, values | address, quantity |
| 17 | Report Server ID | read | yes | yes |  | byte_count, server_id |
| 20 | Read File Record | read |  | yes | byte_count, …_reference_type, …_file, …_record, …_length | byte_count, …_length, …_reference_type, …_data |
| 21 | Write File Record | write |  | no | byte_count, …_reference_type, …_file, …_record, …_length, …_data | byte_count, …_reference_type, …_file, …_record, …_length, …_data |
| 22 | Mask Write Register | write |  | no | address, and_mask, or_mask | address, and_mask, or_mask |
| 23 | Read/Write Multiple Registers | write |  | no | read_address, read_quantity, write_address, write_quantity, byte_count, write_values | byte_count, registers |
| 24 | Read FIFO Queue | read |  | yes | fifo_address | byte_count, fifo_count, values |
| 43 | Encapsulated Interface Transport | other |  | sub | mei_type, read_device_id_code, …_id | mei_type, read_device_id_code, conformity_level, more_follows, next_object_id, number_of_objects, …_id, …_length, …_value |

FC08 sub-functions decoded by name: 0 Return Query Data, read; 1 Restart Communications Option; 2 Return Diagnostic Register, read; 3 Change ASCII Input Delimiter; 4 Force Listen Only Mode; 10 Clear Counters and Diagnostic Register; 11 Return Bus Message Count, read; 12 Return Bus Communication Error Count, read; 13 Return Bus Exception Error Count, read; 14 Return Server Message Count, read; 15 Return Server No Response Count, read; 16 Return Server NAK Count, read; 17 Return Server Busy Count, read; 18 Return Bus Character Overrun Count, read; 20 Clear Overrun Counter and Flag. FC43: MEI type 14 (Read Device Identification) is decoded; type 13 (CANopen) is opaque.
