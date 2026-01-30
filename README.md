# BPMN Security Rule Generator

This repository provides a CLI-based toolset for parsing, validating, and generating Suricata rules from BPMN process models.

---

## Overview

### Subcommands & Files
| File | Purpose |
|------|----------|
| `cli.py` | Main entry point (parser, validator, generator) |
| `core.py` | Core logic (parser, validator, rule generator) |
| `attributes.json` | Attribute schema (types/enums/min/max) - **extensible** |
| `mappings.json` | Rule mappings - **extensible** (scopes, templates) |

**Directional logic:**  
Rules are only generated in the direction **`sourceRef → targetRef`**.  
A reverse rule is created **only if an explicit reverse `messageFlow`** exists.

---

## 1) Parse - Extract Model Structure as JSON

Extracts participants (including BI), controls, and message flows from a BPMN model.

```bash
python cli.py parse -i model.bpmn -o parsed.json
```

**Output (`parsed.json`):**
- Participants (with BI/controls)
- Nodes (with controls)
- MessageFlows

---

## 2) Validate - Check Attributes Against Schema

Validates attributes in a BPMN file against a defined schema.

```bash
python cli.py validate -i model.bpmn -o validation.json
```

**Optional custom schema:**
```bash
python cli.py validate -i model.bpmn -a attributes.json -o validation.json
```

**Output (`validation.json`):**
- `unknown_attributes`
- `type_mismatch`
- `enum_violation`
- `range_violation`

---

## 3) Generate - Create Suricata Rules

Generates Suricata rules either as `.rules` text files or as JSON for pipelines/SOCs.

### 3.1 Text-Based Rules
```bash
python cli.py generate -i model.bpmn -o out.rules
```

### 3.2 JSON Rules
```bash
python cli.py generate -i model.bpmn -o out.json --json-out
```

### 3.3 Extended Options
```bash
python cli.py generate   -i model.bpmn   -m mappings.json   -a attributes.json   --sid-start 5000000   -o out.rules
```

---

### What Gets Generated

**Communication Scope**
- Rules defined in `mappings.json` (e.g., MQTT/1883, TLS policy, HTTP/HTTPS, OPC UA, Modbus, etc.)
- Direction: only `sourceRef → targetRef`
- Reverse rules: only if an explicit reverse messageFlow exists
- BI IPs are used as `{src_ip}` / `{dst_ip}`
- Port/protocol overrides via BI/controls (`src_port`, `dst_port`, `proto`)

**Task Scope**
- Meta-alerts (e.g., `is_human`, `password_length`)

**Resource Scope**
- Host-related policy alerts (e.g., `audit_log`, `tls_used`)

**Positive Compliance Examples**
- `encryption=true` → `pass tls ...`
- `cryptography_used=true` → `pass tls ...`

---

## Examples

| Action | Command |
|---------|----------|
| View structure | `python cli.py parse -i model.bpmn -o parsed.json` |
| Validate syntax | `python cli.py validate -i model.bpmn -o validation.json` |
| Generate text rules | `python cli.py generate -i model.bpmn -o out.rules` |
| Generate JSON rules | `python cli.py generate -i model.bpmn -o out.json --json-out` |
| Use custom SID start | `python cli.py generate -i model.bpmn --sid-start 5500000 -o out.rules` |

---

## Extending Mappings & Attributes

### New Attribute (`attributes.json`)
```json
{
  "schema": {
    "my_flag": { "type": "boolean" },
    "my_list": { "type": "list", "enum": ["A", "B"] },
    "dst_port": { "type": "integer", "min": 1, "max": 65535 }
  }
}
```

### New Rule (`mappings.json`)
```json
{
  "name": "my_policy_violation",
  "scope": "communication",
  "when_all": [
    { "attribute": "my_flag", "equals": true }
  ],
  "template": "alert tcp {src_ip} any -> {dst_ip} 12345 (msg:\"My policy violation {src_name}->{dst_name}\"; sid:{sid}; rev:1;)"
}
```

### Condition Notes
- Use `when_all` / `when_any`
- Supported operators: `equals`, `in` (for lists/enums), `gte`, `lte` (for integers)
- Template placeholders: `{src_ip}`, `{dst_ip}`, `{src_name}`, `{dst_name}`, `{sid}`, `{proto}`, `{src_port}`, `{dst_port}`

---

## Troubleshooting Tips

| Issue | Possible Cause / Fix |
|--------|-----------------------|
| **No reverse rules generated** | Ensure a reverse BPMN `messageFlow` exists. |
| **Missing IPs** | Attach BI objects properly to participants/processes (e.g., BI DataObject + associations). |
| **Validation errors (e.g., `protocol_type` as string)** | Follow schema syntax (e.g., lists: `protocol_type: [MQTT]`). |
| **Suricata import fails** | Include `.rules` in your Suricata config and reload with `suricata-update`. |

---

## License

This project is released under the **Apache License 2.0**, unless stated otherwise.

---

**Developed for research and open-source security automation.**
