# Security Events

Security event identifiers are stable API values. Increment the trailing
version only when the event's semantic meaning changes.

| Event ID | Type | Category | Description |
| --- | --- | --- | --- |
| `prism.security.process_exec.v1` | `process_exec` | `process` | Process execution observed from the kernel audit stream. |
| `prism.security.file_access.v1` | `file_access` | `file` | File path access observed from configured kernel probes. |
| `prism.security.network_connection.v1` | `network_connection` | `network` | Network destination connection observed from kernel network hooks. |

Policy match context must contain only policy metadata such as action, rule
family, and rule index. It must not include the matched command line, file
path, destination, SQL text, labels, annotations, headers, bodies, secrets, or
other payload values.
