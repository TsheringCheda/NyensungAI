# Windows real-telemetry collection

The agent passively reads selected local Windows Event Log channels and observes established TCP sockets. It does not scan remote hosts, inject packets, change firewall rules, or block traffic.

## Event sources

- **Security**: 4624/4625 logons, 4740 lockouts, 4720/4722 account creation/enabling, 4724 password reset attempts, 4728/4732 group membership changes, 4697 service installation, 1102 audit-log clearing.
- **System**: 7045 service installation.
- **Microsoft-Windows-Windows Defender/Operational**: 1116 detection and 1117 remediation/action.
- **Optional**: 4688 process creation, disabled by default because it can be high-volume. The agent stores only the executable basename and never stores command-line arguments.
- **Network**: newly observed established TCP connections (passive socket snapshot).

These are event observations and indicators, not automatic proof of compromise. For example, a successful login or a newly installed service may be legitimate. The severity values are triage priorities.

## Windows configuration

Run PowerShell as Administrator for fuller Security log and socket visibility. Some event types will only exist when the corresponding Windows audit policy is enabled. Defender events require the Defender Operational channel to exist and be readable. Missing or inaccessible channels are logged as warnings; other channels continue.

Copy `.env.example` to `.env` and set `NYENSUNG_AGENT_API_KEY` to exactly the same secret configured as `AGENT_API_KEY` in the backend `.env`. Never commit either `.env` file.

`NYENSUNG_INITIAL_BACKFILL_HOURS=24` bounds the first-run history query. The agent stores a separate record checkpoint per channel in `agent_checkpoint.json`; it retries delivery failures before advancing that channel's checkpoint. Stable event request IDs allow backend deduplication on retries.

Enable 4688 only after enabling **Audit Process Creation** in Windows Advanced Audit Policy. Process auditing may produce many records. Full command lines and PowerShell script contents are deliberately not collected.

## Validation

Parser unit tests run on non-Windows systems. Actual channel availability, audit policy, administrator permissions, and event delivery must be verified on the target Windows machine.
