"""End-to-end demo: synthetic traffic -> features (both versions) -> detect.

Run:  python demo.py
Shows that v1_hybrid (with the ownership-mismatch signal) separates attackers
better than v0_edge (behavioral only).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bola_detection.registry import DetectorRegistry
from bola_detection.detectors import BolaDetector, ExfilDetector
from tools.synthetic_logs import generate


def main():
    logs, ownership, attacker_ids = generate()
    print(f"generated {len(logs)} access logs; attackers={sorted(attacker_ids)}")

    # Sibling detectors over one shared pass. BOLA is the live one; Exfil is
    # wired in to show the per-detector attribution the registry produces.
    registry = DetectorRegistry(
        detectors=[BolaDetector(), ExfilDetector()],
        ownership=ownership,
        contamination=0.02,
    )
    results = registry.fit_score(logs)

    n_attack = sum(1 for r in results if r.user_id in attacker_ids)
    ranked = sorted(results, key=lambda r: -r.combined)

    # precision@k on the combined score (k = true attacker windows).
    topk = ranked[:n_attack]
    prec_at_k = sum(1 for r in topk if r.user_id in attacker_ids) / n_attack if n_attack else 0.0
    # attribution: of the correctly-flagged attacker windows, how many -> "bola"
    attributed = sum(1 for r in topk if r.user_id in attacker_ids and r.top_detector == "bola")

    print(f"\n=== sibling-detector registry ({[d.name for d in registry.detectors]}) ===")
    print(f"windows: {len(results)}  attacker-windows: {n_attack}")
    print(f"precision@{n_attack} (combined score) = {prec_at_k:.2f}")
    print(f"attribution: {attributed}/{len(topk)} top windows attributed to 'bola'")

    print("\nTop-8 by combined score (z = std-devs above that detector's norm):")
    for r in ranked[:8]:
        tag = "ATTACKER" if r.user_id in attacker_ids else "normal"
        print(f"  combined={r.combined:+.2f}  {r.user_id:<7} {tag:<9} "
              f"-> {r.top_detector:<6} "
              f"| bola_z={r.z.get('bola', 0):+.2f} exfil_z={r.z.get('exfil', 0):+.2f}")


if __name__ == "__main__":
    main()
