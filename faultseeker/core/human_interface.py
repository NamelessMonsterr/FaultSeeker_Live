"""
Human-in-the-Loop Interface for FaultSeeker++
Research Gap 2: Lack of Human-in-the-Loop Interaction

Provides CLI-based analyst interaction at strategic checkpoints:
  1. Post-Forensics (after Stage 1) — review addresses, patterns
  2. Vulnerability Review (after Stage 2) — confirm/reject findings
  3. Final Review — edit descriptions, add annotations

Phase 1 is CLI-only. Phase 2 (DOCX §4.4) would add FastAPI + React.
"""

from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class AnalystFeedback:
    """Structured feedback from an analyst interaction."""
    checkpoint: str                         # 'post_forensics', 'vulnerability_review', 'final_review'
    action: str                             # 'approve', 'modify', 'reject', 'skip'
    modifications: Dict[str, Any] = field(default_factory=dict)
    notes: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'checkpoint': self.checkpoint,
            'action': self.action,
            'modifications': self.modifications,
            'notes': self.notes,
        }


# Analyst guidance types (from PDF §3.2.5)
GUIDANCE_TYPES = {
    '1': ('address_label', 'Label an address as attacker/victim/neutral'),
    '2': ('function_focus', 'Mark a function for priority analysis'),
    '3': ('evidence_add', 'Add external evidence or context'),
    '4': ('vuln_confirm', 'Confirm/reject an identified vulnerability'),
    '5': ('attack_hypothesis', 'Suggest an attack vector hypothesis'),
}


class HumanInterface:
    """
    CLI-based human-in-the-loop interface.

    Pauses the pipeline at strategic checkpoints and solicits
    analyst input via stdin/stdout.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.feedback_log: List[AnalystFeedback] = []

    def checkpoint_post_forensics(
        self,
        forensics_result: Dict[str, Any],
    ) -> AnalystFeedback:
        """
        Checkpoint 1: After Stage 1 forensics completes.

        Allows analyst to review:
        - Identified attacker/victim addresses
        - Suspicious patterns
        - Function call prioritization
        """
        if not self.enabled:
            return AnalystFeedback(checkpoint='post_forensics', action='skip')

        print("\n" + "=" * 60)
        print("🔍 CHECKPOINT: Post-Forensics Review")
        print("=" * 60)

        # Display key forensics findings
        if hasattr(forensics_result, 'potential_attacker'):
            print(f"\n📌 Potential Attackers: {forensics_result.potential_attacker}")
        if hasattr(forensics_result, 'potential_victim'):
            print(f"📌 Potential Victims: {forensics_result.potential_victim}")
        if hasattr(forensics_result, 'repeated_patterns'):
            patterns = forensics_result.repeated_patterns
            print(f"📌 Repeated Patterns: {len(patterns) if patterns else 0} found")

        print("\nOptions:")
        print("  [a] Approve and continue")
        print("  [m] Modify (add context or corrections)")
        print("  [s] Skip (continue without review)")

        choice = self._prompt("Your choice [a/m/s]: ", default='a')

        if choice == 'm':
            modifications = self._collect_modifications()
            notes = self._prompt("Any additional notes: ", default='')
            feedback = AnalystFeedback(
                checkpoint='post_forensics',
                action='modify',
                modifications=modifications,
                notes=notes,
            )
        elif choice == 's':
            feedback = AnalystFeedback(checkpoint='post_forensics', action='skip')
        else:
            feedback = AnalystFeedback(checkpoint='post_forensics', action='approve')

        self.feedback_log.append(feedback)
        return feedback

    def checkpoint_vulnerability_review(
        self,
        scored_functions: List[Dict[str, Any]],
    ) -> AnalystFeedback:
        """
        Checkpoint 2: After vulnerability scoring.

        Allows analyst to confirm/reject findings and adjust confidence.
        """
        if not self.enabled:
            return AnalystFeedback(checkpoint='vulnerability_review', action='skip')

        print("\n" + "=" * 60)
        print("🔍 CHECKPOINT: Vulnerability Review")
        print("=" * 60)

        if scored_functions:
            for i, sf in enumerate(scored_functions, 1):
                conf = sf.get('confidence', {})
                print(f"\n  [{i}] {sf.get('function', '?')} @ {sf.get('address', '?')[:12]}...")
                print(f"      Confidence: {conf.get('overall', 0):.1%} ({conf.get('level', '?')})")
                evidence = sf.get('evidence', [])
                if evidence:
                    print(f"      Evidence: {str(evidence[0])[:60]}...")

        print("\nOptions:")
        print("  [a] Approve all findings")
        print("  [c] Confirm/reject individual findings")
        print("  [n] Add analyst notes")
        print("  [s] Skip")

        choice = self._prompt("Your choice [a/c/n/s]: ", default='a')

        modifications = {}
        if choice == 'c' and scored_functions:
            modifications = self._review_individual(scored_functions)
        elif choice == 'n':
            notes = self._prompt("Notes: ", default='')
            modifications = {'analyst_notes': notes}

        feedback = AnalystFeedback(
            checkpoint='vulnerability_review',
            action=choice if choice != 'c' else 'modify',
            modifications=modifications,
        )
        self.feedback_log.append(feedback)
        return feedback

    def get_feedback_log(self) -> List[Dict[str, Any]]:
        """Get all feedback as serializable dicts."""
        return [f.to_dict() for f in self.feedback_log]

    # ─── Private ───────────────────────────────────────────────────

    def _prompt(self, message: str, default: str = '') -> str:
        """Prompt user for input with a default value."""
        try:
            response = input(message).strip()
            return response if response else default
        except (EOFError, KeyboardInterrupt):
            print("\n(skipped)")
            return default

    def _collect_modifications(self) -> Dict[str, Any]:
        """Collect modifications from the analyst."""
        mods = {}
        print("\nGuidance types:")
        for key, (gtype, desc) in GUIDANCE_TYPES.items():
            print(f"  [{key}] {desc}")
        print("  [d] Done")

        while True:
            choice = self._prompt("\nSelect guidance type [1-5/d]: ", default='d')
            if choice == 'd':
                break
            if choice in GUIDANCE_TYPES:
                gtype, desc = GUIDANCE_TYPES[choice]
                value = self._prompt(f"  {desc}: ")
                if value:
                    if gtype not in mods:
                        mods[gtype] = []
                    mods[gtype].append(value)
            else:
                print("  Invalid choice")

        return mods

    def _review_individual(self, scored_functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Review individual findings."""
        confirmations = {}
        for i, sf in enumerate(scored_functions, 1):
            func_name = sf.get('function', f'func_{i}')
            choice = self._prompt(
                f"  [{i}] {func_name} — [c]onfirm / [r]eject / [s]kip: ",
                default='s'
            )
            if choice in ('c', 'r'):
                confirmations[func_name] = {
                    'confirmed': choice == 'c',
                    'note': self._prompt("    Note (optional): ", default=''),
                }
        return {'confirmations': confirmations}
