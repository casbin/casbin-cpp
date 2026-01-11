import json
import sys
import math
import re
import platform
import subprocess

# Force UTF-8 output for Windows
sys.stdout.reconfigure(encoding="utf-8")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}", file=sys.stderr)
        return None


def format_val(val_ns):
    if val_ns is None:
        return "N/A"
    # val_ns is in nanoseconds (Google Benchmark time_unit usually ns)
    if val_ns < 1000:
        return f"{val_ns:.2f}ns"
    if val_ns < 1e6:
        return f"{val_ns/1e3:.2f}us"
    if val_ns < 1e9:
        return f"{val_ns/1e6:.2f}ms"
    return f"{val_ns/1e9:.2f}s"


def normalize_name(name):
    # Google Benchmark names: "Suite/Test/..."
    # Clean up common prefixes or suffixes if needed
    return name


def parse_google_benchmark(data):
    """Parses Google Benchmark JSON data."""
    benchmarks = data.get("benchmarks", [])
    parsed = {}
    
    # Group by name (handle repetitions if present)
    grouped = {}
    
    for b in benchmarks:
        name = b.get("name")
        # If using aggregates (mean, median, stddev), the name might have suffix
        if name.endswith("_mean") or name.endswith("_median") or name.endswith("_stddev"):
            real_name = name.rsplit("_", 1)[0]
            metric = name.rsplit("_", 1)[1]
            if real_name not in grouped:
                grouped[real_name] = {"samples": []}
            grouped[real_name][metric] = b.get("real_time") # Use real_time or cpu_time
            continue
            
        if name not in grouped:
            grouped[name] = {"samples": []}
        
        # Collect raw samples if available
        grouped[name]["samples"].append(b.get("real_time"))
        grouped[name]["unit"] = b.get("time_unit", "ns")

    for name, data in grouped.items():
        # Google Benchmark output is usually in time_unit (default ns)
        # We want to normalize to ns for internal consistency with format_val
        unit = data.get("unit", "ns")
        mult = 1.0
        if unit == "us": mult = 1e3
        elif unit == "ms": mult = 1e6
        elif unit == "s": mult = 1e9
        
        mean = 0.0
        stddev = 0.0
        rounds = len(data["samples"])
        
        if "mean" in data:
            mean = data["mean"] * mult
            if "stddev" in data:
                stddev = data["stddev"] * mult
            else:
                stddev = 0.0
            # Estimate rounds if aggregates only
            if rounds == 0: rounds = 1 # We don't know exact rounds if only aggregate provided
        elif rounds > 0:
            # Calculate from samples
            samples = [s * mult for s in data["samples"]]
            mean = sum(samples) / rounds
            if rounds > 1:
                variance = sum((x - mean) ** 2 for x in samples) / (rounds - 1)
                stddev = math.sqrt(variance)
            else:
                stddev = 0.0
        
        parsed[name] = {
            "mean": mean,
            "stddev": stddev,
            "rounds": rounds
        }
            
    return parsed

def main():
    if len(sys.argv) < 3:
        print("Usage: python pytest_benchstat.py base.json pr.json")
        sys.exit(1)

    base_data = load_json(sys.argv[1])
    pr_data = load_json(sys.argv[2])

    if not base_data or not pr_data:
        sys.exit(1)

    # Detect format and parse
    # Try Google Benchmark first (has "benchmarks" list with "real_time")
    # Fallback to Pytest-benchmark (has "benchmarks" list with "stats")
    
    def parse_any(data):
        if "benchmarks" in data and len(data["benchmarks"]) > 0:
            first = data["benchmarks"][0]
            if "stats" in first:
                # Pytest-benchmark
                return {b["name"]: b["stats"] for b in data["benchmarks"]}
            elif "real_time" in first or "cpu_time" in first:
                # Google Benchmark
                return parse_google_benchmark(data)
        return {}

    base_map = parse_any(base_data)
    pr_map = parse_any(pr_data)

    all_names = sorted(set(base_map.keys()) | set(pr_map.keys()))

    # Print Header
    print("goos: linux")
    print("goarch: amd64")
    print("pkg: github.com/casbin/casbin-cpp")
    
    cpu_info = "GitHub Actions Runner"
    # Try to get CPU info from JSON context if available
    if "context" in base_data and "cpu_model" in base_data["context"]:
        cpu_info = base_data["context"]["cpu_model"]
        
    print(f"cpu: {cpu_info}")
    print("")

    w_name = 50
    w_val = 20

    # Header
    print(f"{'':<{w_name}}│   old base.json    │   new pr.json      │")
    print(f"{'':<{w_name}}│    sec/op          │    sec/op          │")

    base_means = []
    pr_means = []

    # Footnote tracking
    need_low_sample_note = False
    need_insignificant_note = False

    for name in all_names:
        base = base_map.get(name)
        pr = pr_map.get(name)

        base_mean = base["mean"] if base else 0
        pr_mean = pr["mean"] if pr else 0

        base_std = base["stddev"] if base else 0
        pr_std = pr["stddev"] if pr else 0

        base_rounds = base["rounds"] if base else 0
        pr_rounds = pr["rounds"] if pr else 0

        if base_mean > 0:
            base_means.append(base_mean)
        if pr_mean > 0:
            pr_means.append(pr_mean)

        # Format Value with StdDev and Superscript
        def format_cell(val, std, rounds):
            if val == 0:
                return "N/A"

            # StdDev formatting
            if rounds < 2 or std == 0:
                std_str = "± ∞"
            else:
                pct = (std / val) * 100
                std_str = f"± {pct:.0f}%"

            # Superscript for low sample size
            note = ""
            if rounds < 6:
                note = "¹"
                nonlocal need_low_sample_note
                need_low_sample_note = True

            return f"{format_val(val)} {std_str} {note}"

        base_str = format_cell(base_mean, base_std, base_rounds) if base else "N/A"
        pr_str = format_cell(pr_mean, pr_std, pr_rounds) if pr else "N/A"

        display_name = normalize_name(name)

        print(f"{display_name:<{w_name}} {base_str:<{w_val}} {pr_str:<{w_val}}")

    if base_means and pr_means:
        # Filter out zero values for geomean calculation
        base_geo_input = [x for x in base_means if x > 0]
        pr_geo_input = [x for x in pr_means if x > 0]

        g_base_str = "N/A"
        g_pr_str = "N/A"

        if base_geo_input:
            g_base = math.exp(sum(math.log(x) for x in base_geo_input) / len(base_geo_input))
            g_base_str = f"{format_val(g_base)}"

        if pr_geo_input:
            g_pr = math.exp(sum(math.log(x) for x in pr_geo_input) / len(pr_geo_input))
            g_pr_str = f"{format_val(g_pr)}"

        print(f"{'geomean':<{w_name}} {g_base_str:<{w_val}} {g_pr_str:<{w_val}}")

    # Print Footnotes
    if need_low_sample_note:
        print("¹ need >= 6 samples for confidence interval at level 0.95")
    if need_insignificant_note:
        print("² need >= 4 samples to detect a difference at alpha level 0.05")


if __name__ == "__main__":
    main()
