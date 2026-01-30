
import re, json, xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

def _nsmap(root):
    ns = {}
    for k,v in root.attrib.items():
        if k.startswith("xmlns"):
            parts = k.split(":")
            if len(parts)==1:
                ns["bpmn"] = v
            else:
                ns[parts[1]] = v
    ns.setdefault("bpmn","http://www.omg.org/spec/BPMN/20100524/MODEL")
    return ns

def snake(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("_").lower()

_CONTROL_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_\-]*)\s*:\s*(.+?)\s*;\s*$")

def parse_control_block(text: str) -> Dict[str, Any]:
    controls: Dict[str, Any] = {}
    if not text:
        return controls
    lines = [ln for ln in (text or '').splitlines() if ln.strip()]
    cleaned = []
    for ln in lines:
        if ln.strip().upper() in {"BI","FR1","FR2","FR3","FR4","FR5","FR6","FR7"}:
            continue
        cleaned.append(ln)
    buf = "\n".join(cleaned)
    raw_lines = [s+";" for s in buf.split(";") if s.strip()]
    for raw in raw_lines:
        m = _CONTROL_LINE.match(raw)
        if not m:
            continue
        key_raw, val = m.group(1), m.group(2).strip()
        key = snake(key_raw)
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            items = []
            if inner:
                for item in inner.split(","):
                    items.append(_coerce_literal(item.strip()))
            controls[key] = items
        else:
            controls[key] = _coerce_literal(val)
    return controls

def _coerce_literal(tok: str):
    low = tok.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"\d+", tok):
        return int(tok)
    # normalize common protocols
    proto_norm = {"mqtt":"MQTT","opcua":"OPCUA","modbus":"MODBUS","https":"HTTPS","tls":"TLS",
                  "http":"HTTP","ssh":"SSH","smb":"SMB","bacnet":"BACNET","dns":"DNS","ntp":"NTP"}
    if low in proto_norm:
        return proto_norm[low]
    return tok

@dataclass
class Annotation:
    id: str
    text: str
    controls: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ParticipantInfo:
    id: str
    name: str = ""
    processRef: Optional[str]=None
    annotations: List[Annotation]=field(default_factory=list)
    controls: Dict[str, Any]=field(default_factory=dict)
    bi: Dict[str, Any]=field(default_factory=dict)

@dataclass
class FlowNode:
    id: str
    name: str = ""
    process_id: Optional[str]=None
    participant_id: Optional[str]=None
    annotations: List[Annotation]=field(default_factory=list)
    controls: Dict[str, Any]=field(default_factory=dict)

@dataclass
class MessageFlow:
    id: str
    name: str=""
    sourceRef: str=""
    targetRef: str=""
    annotations: List[Annotation]=field(default_factory=list)
    controls: Dict[str, Any]=field(default_factory=dict)

@dataclass
class Model:
    participants: Dict[str,ParticipantInfo]=field(default_factory=dict)
    nodes: Dict[str,FlowNode]=field(default_factory=dict)
    msg_flows: List[MessageFlow]=field(default_factory=list)
    participants_by_process: Dict[str,str]=field(default_factory=dict)

def parse_bpmn(path: str) -> Model:
    tree = ET.parse(path)
    root = tree.getroot()
    ns = _nsmap(root)
    q = lambda x: f"{{{ns['bpmn']}}}{x}"
    model = Model()

    # participants
    for p in root.findall(".//"+q("participant")):
        pid = p.attrib.get("id")
        name = p.attrib.get("name","")
        proc = p.attrib.get("processRef")
        if pid:
            model.participants[pid] = ParticipantInfo(id=pid, name=name, processRef=proc)
        if proc and pid:
            model.participants_by_process[proc] = pid

    # process -> element ids
    process_of: Dict[str,str] = {}
    for proc in root.findall(".//"+q("process")):
        pr_id = proc.attrib.get("id")
        if not pr_id: 
            continue
        for el in proc.iter():
            eid = el.attrib.get("id")
            if eid:
                process_of[eid] = pr_id

    # nodes (tasks + events minimal)
    node_tags = ["task","userTask","serviceTask","scriptTask","sendTask","receiveTask",
                 "startEvent","endEvent","intermediateThrowEvent","intermediateCatchEvent"]
    for tag in node_tags:
        for n in root.findall(".//"+q(tag)):
            nid = n.attrib["id"]
            name = n.attrib.get("name","")
            proc_id = process_of.get(nid)
            participant_id = model.participants_by_process.get(proc_id) if proc_id else None
            model.nodes[nid] = FlowNode(id=nid, name=name, process_id=proc_id, participant_id=participant_id)

    # text annotations
    ann_by_id: Dict[str,Annotation] = {}
    for ta in root.findall(".//"+q("textAnnotation")):
        aid = ta.attrib["id"]
        text_el = ta.find(q("text"))
        text = text_el.text if text_el is not None and text_el.text else ""
        ann_by_id[aid] = Annotation(id=aid, text=text, controls=parse_control_block(text))

    # associations (node/participant direct)
    for assoc in root.findall(".//"+q("association")):
        src = assoc.attrib.get("sourceRef")
        trg = assoc.attrib.get("targetRef")
        if src in ann_by_id:
            ann = ann_by_id[src]
            if trg in model.nodes:
                model.nodes[trg].annotations.append(ann)
            elif trg in model.participants:
                model.participants[trg].annotations.append(ann)

    # dataObjectReference blocks (FR*, BI) and their attached annotations
    data_objs = list(root.findall(".//"+q("dataObjectReference")))
    ann_controls = {a_id: a.controls for a_id,a in ann_by_id.items()}
    dataobj_controls: Dict[str,Dict[str,Any]] = {}
    for assoc in root.findall(".//"+q("association")):
        src = assoc.attrib.get("sourceRef"); trg = assoc.attrib.get("targetRef")
        if src in ann_controls and any(d.attrib.get("id")==trg for d in data_objs):
            dataobj_controls.setdefault(trg, {}).update(ann_controls[src])
        if trg in ann_controls and any(d.attrib.get("id")==src for d in data_objs):
            dataobj_controls.setdefault(src, {}).update(ann_controls[trg])

    # assign BI and FR controls to participants by process
    for d in data_objs:
        did = d.attrib.get("id")
        name = (d.attrib.get("name") or "").strip().upper()
        proc_id = None
        for proc in root.findall(".//"+q("process")):
            for desc in proc.iter():
                if desc is d:
                    proc_id = proc.attrib.get("id"); break
            if proc_id: break
        part_id = model.participants_by_process.get(proc_id) if proc_id else None
        if not part_id: 
            continue
        if name == "BI":
            model.participants[part_id].bi.update(dataobj_controls.get(did, {}))
        else:
            model.participants[part_id].controls.update(dataobj_controls.get(did, {}))

    # merge direct annotations
    for node in model.nodes.values():
        merged = {}
        for ann in node.annotations:
            merged.update(ann.controls)
        node.controls = merged
    for p in model.participants.values():
        m = {}
        for ann in p.annotations:
            m.update(ann.controls)
        p.controls.update(m)

    # message flows
    for mf in root.findall(".//"+q("messageFlow")):
        mid = mf.attrib["id"]
        model.msg_flows.append(MessageFlow(
            id=mid,
            name=mf.attrib.get("name",""),
            sourceRef=mf.attrib.get("sourceRef",""),
            targetRef=mf.attrib.get("targetRef","")
        ))
    return model

# ---- Validation against attributes.json ----
def validate_model(model: Model, attributes_path: str) -> Dict[str, Any]:
    schema = json.load(open(attributes_path))["schema"]
    issues = {"unknown_attributes": [], "type_mismatch": [], "enum_violation": [], "range_violation": []}
    def check_map(obj_id: str, where: str, kv: Dict[str, Any]):
        for k,v in kv.items():
            if k not in schema:
                issues["unknown_attributes"].append({"where":where, "id":obj_id, "attribute":k})
                continue
            typ = schema[k]["type"]
            if typ=="boolean" and not isinstance(v, bool):
                issues["type_mismatch"].append({"where":where,"id":obj_id,"attribute":k,"expected":"boolean","got":type(v).__name__})
            elif typ=="integer" and not isinstance(v, int):
                issues["type_mismatch"].append({"where":where,"id":obj_id,"attribute":k,"expected":"integer","got":type(v).__name__})
            elif typ=="string" and not isinstance(v, str):
                issues["type_mismatch"].append({"where":where,"id":obj_id,"attribute":k,"expected":"string","got":type(v).__name__})
            elif typ=="list" and not isinstance(v, list):
                issues["type_mismatch"].append({"where":where,"id":obj_id,"attribute":k,"expected":"list","got":type(v).__name__})
            # enum check
            if "enum" in schema[k]:
                enum = schema[k]["enum"]
                vals = v if isinstance(v, list) else [v]
                bad = [x for x in vals if x not in enum]
                if bad:
                    issues["enum_violation"].append({"where":where,"id":obj_id,"attribute":k,"invalid":bad,"allowed":enum})
            # range checks
            if isinstance(v, int):
                if "min" in schema[k] and v < schema[k]["min"]:
                    issues["range_violation"].append({"where":where,"id":obj_id,"attribute":k,"min":schema[k]["min"],"value":v})
                if "max" in schema[k] and v > schema[k]["max"]:
                    issues["range_violation"].append({"where":where,"id":obj_id,"attribute":k,"max":schema[k]["max"],"value":v})
    for pid,p in model.participants.items():
        check_map(pid, "participant.controls", p.controls)
        check_map(pid, "participant.bi", p.bi)
    for nid,n in model.nodes.items():
        check_map(nid, "node.controls", n.controls)
    return issues

# --- Rule generator with scopes + ports/proto placeholders ---
@dataclass
class Rule:
    text: str
    meta: Dict[str, Any]

def _load_json(path: str): 
    with open(path,"r") as f: return json.load(f)

def _ip_from_part(p) -> str:
    if not p: return "any"
    for k in ("ip","ipv4"):
        v = p.bi.get(k)
        if v: return v
    return "any"

def _port_from_ctrls(ctrls: Dict[str,Any], key: str, default: str) -> str:
    val = ctrls.get(key)
    if isinstance(val, int):
        return str(val)
    return default

def _proto_from_ctrls(ctrls: Dict[str,Any]) -> str:
    val = ctrls.get("proto")
    if isinstance(val, str) and val.lower() in ("tcp","udp","any"):
        return val.lower()
    return "tcp"

def _match_mapping(ctrls: Dict[str, Any], mapping: Dict[str, Any]) -> bool:
    def cond_ok(cond):
        attr = cond.get("attribute")
        if attr not in ctrls: 
            return False
        val = ctrls[attr]
        if "equals" in cond:
            return val == cond["equals"]
        if "in" in cond:
            arr = cond["in"]
            if isinstance(val, list):
                return any(v in arr for v in val)
            return val in arr
        if "gte" in cond and isinstance(val, int):
            return val >= cond["gte"]
        if "lte" in cond and isinstance(val, int):
            return val <= cond["lte"]
        return False
    ok_all = all(cond_ok(c) for c in mapping.get("when_all", [])) if mapping.get("when_all") else True
    ok_any = any(cond_ok(c) for c in mapping.get("when_any", [])) if mapping.get("when_any") else True
    return ok_all and ok_any

def generate_suricata_rules(model: Model, attributes_path: str, mappings_path: str, sid_start: int = 4000000, json_out: bool=False) -> List[Rule]:
    mappings = _load_json(mappings_path)
    sid = sid_start
    rules: List[Rule] = []


    # --- Communication scope ---
    # Build set of participant direction pairs present in the BPMN (to decide reverse generation)
    flow_pairs = set()
    for mf in model.msg_flows:
        # resolve endpoints (node -> participant)
        def to_part(ref):
            part = model.participants.get(ref)
            if part:
                return part
            node = model.nodes.get(ref)
            return model.participants.get(node.participant_id) if node and node.participant_id else None
        sp = to_part(mf.sourceRef)
        dp = to_part(mf.targetRef)
        if sp and dp:
            flow_pairs.add((sp.id, dp.id))

    for mf in model.msg_flows:
        # resolve endpoints (node -> participant), keep IDs for pair lookup
        def to_part(ref):
            part = model.participants.get(ref)
            if part:
                return part
            node = model.nodes.get(ref)
            return model.participants.get(node.participant_id) if node and node.participant_id else None

        src_part = to_part(mf.sourceRef)
        dst_part = to_part(mf.targetRef)
        if not src_part or not dst_part: 
            continue

        src_name, dst_name = (src_part.name or "src"), (dst_part.name or "dst")
        src_ip, dst_ip = _ip_from_part(src_part), _ip_from_part(dst_part)

        # merge controls from both sides (direction-aware: still combine for policy intent)
        comm_ctrls = {}
        comm_ctrls.update(src_part.controls); comm_ctrls.update(dst_part.controls)
        # allow BI overrides for ports/proto
        comm_ctrls.update({k:v for k,v in src_part.bi.items() if k in ("src_port","proto")})
        comm_ctrls.update({k:v for k,v in dst_part.bi.items() if k in ("dst_port","proto")})

        for mp in mappings:
            if mp.get("scope") != "communication": 
                continue
            if _match_mapping(comm_ctrls, mp):
                # defaults
                proto = mp.get("defaults",{}).get("proto") or _proto_from_ctrls(comm_ctrls)
                src_port = mp.get("defaults",{}).get("src_port") or _port_from_ctrls(comm_ctrls, "src_port", "any")
                dst_port = mp.get("defaults",{}).get("dst_port") or _port_from_ctrls(comm_ctrls, "dst_port", "any")
                # FORWARD only (respect BPMN direction)
                rule_text = mp["template"].format(
                    src_ip=src_ip, dst_ip=dst_ip, src_name=src_name, dst_name=dst_name, sid=sid,
                    src_port=src_port, dst_port=dst_port, proto=proto,
                    password_length=comm_ctrls.get("password_length","")
                )
                rules.append(Rule(text=rule_text, meta={"scope":"communication","mapping": mp["name"], "message_flow": mf.id, "dir":"forward"}))
                sid += 1
                # REVERSE only if an explicit reverse flow exists
                reverse_exists = (dst_part.id, src_part.id) in flow_pairs
                if mp.get("bidirectional") and reverse_exists:
                    rule_text_rev = mp["template"].format(
                        src_ip=dst_ip, dst_ip=src_ip, src_name=dst_name, dst_name=src_name, sid=sid,
                        src_port=src_port, dst_port=dst_port, proto=proto,
                        password_length=comm_ctrls.get("password_length","")
                    )
                    rules.append(Rule(text=rule_text_rev, meta={"scope":"communication","mapping": mp["name"], "message_flow": mf.id, "dir":"reverse"}))
                    sid += 1
    # --- Task scope --- (emit meta alerts)
    for nid, node in model.nodes.items():
        if not node.name:
            continue
        part = model.participants.get(node.participant_id) if node.participant_id else None
        participant_name = part.name if part else "Participant"
        task_ctrls = node.controls.copy()
        for mp in mappings:
            if mp.get("scope") != "task": 
                continue
            if _match_mapping(task_ctrls, mp):
                rule_text = mp["template"].format(
                    task_name=node.name, participant_name=participant_name, sid=sid,
                    password_length=task_ctrls.get("password_length","")
                )
                rules.append(Rule(text=rule_text, meta={"scope":"task","mapping": mp["name"], "node": nid}))
                sid += 1

    # --- Resource scope --- (per participant)
    for pid, p in model.participants.items():
        res_ctrls = p.controls.copy()
        for mp in mappings:
            if mp.get("scope") != "resource":
                continue
            if _match_mapping(res_ctrls, mp):
                rule_text = mp["template"].format(
                    dst_ip=_ip_from_part(p), participant_name=p.name, sid=sid
                )
                rules.append(Rule(text=rule_text, meta={"scope":"resource","mapping": mp["name"], "participant": pid}))
                sid += 1

    return rules

# helper for CLI JSON rules output
def rules_to_json(rules: List[Rule]) -> List[Dict[str, Any]]:
    return [{"text": r.text, "meta": r.meta} for r in rules]
