import os
import sys
import json
import csv
import argparse
from synthesizer.core import load_seed_manifest, build_trace
from synthesizer.decoys import export_decoy_registry

def cmd_generate(args):
    """Executes the trace generation loop."""
    print(f"Loading manifest from {args.input}...")
    try:
        rows = load_seed_manifest(args.input)
    except Exception as e:
        print(f"Error loading manifest: {e}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Exporting decoy registry...")
    export_decoy_registry()
    
    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        
    traces = []
    print(f"Writing traces incrementally to {args.output}...")
    with open(args.output, "w", encoding="utf-8") as f:
        for row in rows:
            trace = build_trace(row, force_mock=args.force_mock)
            traces.append(trace)
            f.write(json.dumps(trace) + "\n")
            f.flush()
            
    print(f"\nGeneration completed successfully! Traces written to: {args.output}")
    
    # Summary of generated traces
    benign_count = sum(1 for t in traces if not t["ground_truth"]["is_malicious"])
    malicious_count = sum(1 for t in traces if t["ground_truth"]["is_malicious"])
    hp_fired_count = sum(1 for t in traces if t["detector_results"]["honeypot"]["fired"])
    monitor_suspicious_count = sum(1 for t in traces if t["detector_results"]["llm_monitor"]["verdict"] == "SUSPICIOUS")
    
    print(f"Rollup stats:")
    print(f"  Total traces generated: {len(traces)}")
    print(f"  Benign traces: {benign_count}")
    print(f"  Malicious traces: {malicious_count}")
    print(f"  Honeypots Fired: {hp_fired_count} / {malicious_count} malicious runs")
    print(f"  LLM Monitor Suspicious: {monitor_suspicious_count} / {malicious_count} malicious runs")

def cmd_show(args):
    """Searches for a trace ID or prefix and prints its formatted content."""
    trace_file = args.output_file
    if not os.path.exists(trace_file):
        print(f"Traces file not found at {trace_file}. Run generation first.", file=sys.stderr)
        sys.exit(1)
        
    target_id = args.trace_id
    found = False
    
    with open(trace_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            trace = json.loads(line)
            # Match by trace_id or sample_id prefix (e.g. s01 matches s01_...)
            trace_id = trace.get("trace_id", "")
            if trace_id == target_id or trace_id.startswith(f"{target_id}_") or target_id == trace_id.split("_")[0]:
                print(json.dumps(trace, indent=2))
                found = True
                break
                
    if not found:
        print(f"Trace with ID or prefix '{target_id}' not found in {trace_file}.", file=sys.stderr)
        sys.exit(1)

def cmd_summary(args):
    """Aggregates and outputs the detection rollup table to stdout and CSV."""
    trace_file = args.input_file
    output_csv = args.output_csv
    
    if not os.path.exists(trace_file):
        print(f"Traces file not found at {trace_file}. Run generation first.", file=sys.stderr)
        sys.exit(1)
        
    rows_summary = []
    
    with open(trace_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            trace = json.loads(line)
            # Extract sample_id from trace_id (e.g. s01_github-review -> s01)
            trace_id = trace.get("trace_id", "")
            sample_id = trace_id.split("_")[0]
            
            tactic = trace["ground_truth"]["attack_method"].split(" (")[0] if trace["ground_truth"]["attack_method"] else "Legitimate Helper"
            scope_behavior = trace_id.replace(f"{sample_id}_{trace['skill']['name']}_", "")
            
            # Count decoys touched based on assets rather than raw strings
            hp = trace["detector_results"]["honeypot"]
            matched_values = hp["matched_values"]
            
            num_decoys_touched = len(hp["matched_values"])
            honeypot_fired = "Yes" if hp["fired"] else "No"
            
            monitor_verdict = trace["detector_results"]["llm_monitor"]["verdict"]
            notes = trace["ground_truth"]["security_impact_dimension"]
            
            rows_summary.append({
                "sample_id": sample_id,
                "tactic": tactic,
                "scope_behavior": scope_behavior,
                "num_decoys_touched": str(num_decoys_touched),
                "honeypot_fired": honeypot_fired,
                "monitor_verdict_MOCKED": monitor_verdict,
                "notes": notes
            })
            
    # Write to CSV
    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        
    fields = ["sample_id", "tactic", "scope_behavior", "num_decoys_touched", "honeypot_fired", "monitor_verdict_MOCKED", "notes"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows_summary)
        
    # Print markdown table
    print("\n# Detection Rollup Summary Table")
    print("> [!NOTE]")
    print("> The monitor verdict column represents MOCKED detector results and not actual real-time LLM monitor decisions.\n")
    
    # Format markdown headers
    headers = ["Sample ID", "Tactic", "Scope/Stealthiness", "Decoys Touched", "Honeypot Fired", "Monitor Verdict (MOCKED)", "Notes"]
    col_widths = [10, 25, 25, 15, 15, 25, 30]
    
    header_line = "| " + " | ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths)) + " |"
    separator_line = "| " + " | ".join("-" * w for w in col_widths) + " |"
    print(header_line)
    print(separator_line)
    
    for row in rows_summary:
        vals = [
            row["sample_id"],
            row["tactic"],
            row["scope_behavior"],
            row["num_decoys_touched"],
            row["honeypot_fired"],
            row["monitor_verdict_MOCKED"],
            row["notes"]
        ]
        row_line = "| " + " | ".join(f"{v:<{w}}" for v, w in zip(vals, col_widths)) + " |"
        print(row_line)
        
    print(f"\nRollup table successfully saved to: {output_csv}\n")

def main():
    parser = argparse.ArgumentParser(description="Insider Honeypots Synthetic Trace Generator CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    # Subcommand: generate
    parser_generate = subparsers.add_parser("generate", help="Generate synthetic agent traces from manifest")
    parser_generate.add_argument("--input", default="data/seed_manifest.csv", help="Path to input seed manifest CSV")
    parser_generate.add_argument("--output", default="output/traces.jsonl", help="Path to write synthetic traces JSONL")
    parser_generate.add_argument("--force-mock", action="store_true", help="Force mock offline trace generation (no LLM calls)")
    
    # Subcommand: show
    parser_show = subparsers.add_parser("show", help="Show full generated trace details by ID or prefix")
    parser_show.add_argument("--trace-id", required=True, help="Trace ID (e.g., s01_github-code-review_broad) or ID prefix (e.g. s01)")
    parser_show.add_argument("--output-file", default="output/traces.jsonl", help="Path to output traces JSONL file")
    
    # Subcommand: summary
    parser_summary = subparsers.add_parser("summary", help="Show rollup summary table of generated traces")
    parser_summary.add_argument("--input-file", default="output/traces.jsonl", help="Path to read generated traces JSONL")
    parser_summary.add_argument("--output-csv", default="output/summary_table.csv", help="Path to write CSV rollup summary")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "summary":
        cmd_summary(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
