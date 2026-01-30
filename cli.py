
import argparse, json, os
from core import parse_bpmn, generate_suricata_rules, validate_model, rules_to_json

def cmd_parse(args):
    model = parse_bpmn(args.input)
    out = {
        "participants": {pid: {
            "name": p.name, "processRef": p.processRef, "bi": p.bi, "controls": p.controls
        } for pid,p in model.participants.items()},
        "nodes": {nid: {
            "name": n.name, "process_id": n.process_id, "participant_id": n.participant_id, "controls": n.controls
        } for nid,n in model.nodes.items()},
        "message_flows": [{"id": m.id, "name": m.name, "sourceRef": m.sourceRef, "targetRef": m.targetRef} for m in model.msg_flows]
    }
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Wrote parsed model to {args.output}")

def cmd_generate(args):
    model = parse_bpmn(args.input)
    rules = generate_suricata_rules(model, args.attributes, args.mappings, sid_start=args.sid_start)
    if args.json_out:
        with open(args.output, "w") as f:
            json.dump(rules_to_json(rules), f, indent=2)
        print(f"Wrote {len(rules)} rules (JSON) to {args.output}")
    else:
        with open(args.output, "w") as f:
            for r in rules:
                f.write(r.text.strip() + "\n")
        print(f"Wrote {len(rules)} Suricata rules to {args.output}")

def cmd_validate(args):
    model = parse_bpmn(args.input)
    report = validate_model(model, args.attributes)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote validation report to {args.output}")

def main():
    p = argparse.ArgumentParser(prog="siren", description="BPMN → Suricata rule generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("parse", help="Parse BPMN and dump extracted controls/BI")
    pp.add_argument("--input","-i", required=True, help="Path to BPMN XML file")
    pp.add_argument("--output","-o", required=True, help="Path to write parsed JSON")
    pp.set_defaults(func=cmd_parse)

    pg = sub.add_parser("generate", help="Generate Suricata rules from BPMN")
    pg.add_argument("--input","-i", required=True, help="Path to BPMN XML file")
    pg.add_argument("--attributes","-a", required=False, default=os.path.join(os.path.dirname(__file__),"attributes.json"), help="Path to attributes JSON")
    pg.add_argument("--mappings","-m", required=False, default=os.path.join(os.path.dirname(__file__),"mappings.json"), help="Path to mappings JSON")
    pg.add_argument("--sid-start", type=int, default=4000000, help="Starting SID for generated rules")
    pg.add_argument("--output","-o", required=True, help="Path to write .rules file or JSON")
    pg.add_argument("--json-out", action="store_true", help="Write rules as JSON instead of .rules text")
    pg.set_defaults(func=cmd_generate)

    pv = sub.add_parser("validate", help="Validate attributes against schema")
    pv.add_argument("--input","-i", required=True, help="Path to BPMN XML file")
    pv.add_argument("--attributes","-a", required=False, default=os.path.join(os.path.dirname(__file__),"attributes.json"), help="Path to attributes JSON")
    pv.add_argument("--output","-o", required=True, help="Path to write validation report (JSON)")
    pv.set_defaults(func=cmd_validate)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
