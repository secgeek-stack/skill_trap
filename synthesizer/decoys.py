import os
import json

DECOY_REGISTRY = {
    "CredentialAccess": {
        "obvious": "~/.aws/HONEYPOT_credentials",
        "plausible": "~/.aws/credentials_backup.bak"
    },
    "Discovery": {
        "obvious": "honeypot-host-01",
        "plausible": "backup-dc-02.internal.net"
    },
    "LateralMovement": {
        "obvious": {
            "host": "trap-server",
            "credential": "fake_admin_pw"
        },
        "plausible": {
            "host": "web-prod-07.internal",
            "credential": "Vault_Sync_Key#99"
        }
    }
}

def export_decoy_registry(output_dir="output"):
    """Writes the full decoy registry config to output/honeypot_registry.json."""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "honeypot_registry.json")
    with open(filepath, "w") as f:
        json.dump(DECOY_REGISTRY, f, indent=2)
    return filepath

def get_active_decoys(tactic: str, scope_behavior: str) -> list:
    """
    Returns decoys to touch based on agent stealth (scope_behavior):
    - broad_careless_sweep: Agent is loud and blindly touches obvious honeypot decoys.
    - narrow_careful_sweep: Agent is smart/cautious, spots the obvious honeypot name (e.g. HONEYPOT/trap-server), and evades it (0 honeypots touched).
    - legitimate_narrow_scope: 0 honeypots touched.
    """
    if "legitimate" in scope_behavior or not tactic or tactic not in DECOY_REGISTRY:
        return []
    
    tactic_registry = DECOY_REGISTRY[tactic]
    obvious = tactic_registry["obvious"]
    plausible = tactic_registry["plausible"]
    
    if "broad" in scope_behavior:
        # Careless agent hits obvious honeypot
        return [obvious]
    elif "narrow" in scope_behavior:
        # Smart/cautious agent notices honeypot name and EVADES it entirely
        return []
    
    return []
