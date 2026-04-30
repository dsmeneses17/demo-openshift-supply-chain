#!/usr/bin/env python3
"""
Supply chain security test script.
Signs, attests, and validates container images using cosign and Enterprise Contract.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

def run_command(cmd, shell=False, capture=True):
    """Run a command and return stdout."""
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, shell=shell)
        else:
            # Run without capturing - for interactive commands
            result = subprocess.run(cmd, text=True, shell=shell)
            return "", result.returncode
        
        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        print(f"Failed to run command: {e}", file=sys.stderr)
        return "", 1

def get_digests(repo):
    """Get all image digests from docker inspect and manifest inspect."""
    digests = []
    
    # 1. Main digest via docker inspect
    cmd = f'docker inspect --format="{{{{range .RepoDigests}}}}{{{{println .}}}}{{{{end}}}}" {repo}'
    stdout, _ = run_command(cmd, shell=True, capture=True)
    main_digests = [d.strip() for d in stdout.split('\n') if d.strip()]
    for d in main_digests:
        if d not in digests:
            digests.append(d)
            
    # 2. Sub-digests via docker manifest inspect
    print(f"DEBUG - Checking for sub-components in {repo}...")
    env = os.environ.copy()
    env["DOCKER_CLI_EXPERIMENTAL"] = "enabled"
    
    try:
        result = subprocess.run(
            f'docker manifest inspect {repo}', 
            capture_output=True, text=True, shell=True, env=env
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if "manifests" in data:
                base_repo = repo.split(':')[0].split('@')[0]
                for m in data["manifests"]:
                    digest = m.get("digest")
                    if digest:
                        full_ref = f"{base_repo}@{digest}"
                        if full_ref not in digests:
                            print(f"DEBUG - Found sub-component: {full_ref}")
                            digests.append(full_ref)
    except Exception as e:
        print(f"DEBUG - Failed to inspect manifest: {e}", file=sys.stderr)
        
    return digests

def sign_image(image_ref):
    """Sign image with cosign (keyless)."""
    print(f"\n=== Signing {image_ref} ===")
    cmd = ["cosign", "sign", "--yes", image_ref]
    _, code = run_command(cmd, capture=False)  # Interactive
    return code == 0

def create_predicate(work_dir):
    """Create predicate YAML file."""
    predicate = {
        "builder": {"id": "https://github.com/dsmeneses17"},
        "buildType": "github-actions",
        "invocation": {},
        "buildConfig": {},
        "metadata": {
            "completeness": {
                "parameters": False,
                "environment": False,
                "materials": False
            },
            "reproducible": False
        },
        "materials": []
    }
    
    pred_file = work_dir / "predicate.json"
    
    # Delete if exists (to avoid stale data)
    if pred_file.exists():
        pred_file.unlink()
    
    with open(pred_file, 'w', encoding='utf-8') as f:
        json.dump(predicate, f, separators=(',', ':'))
    
    print(f"DEBUG - Predicate created: {pred_file}")
    with open(pred_file, 'r') as f:
        content = f.read()
        print(f"DEBUG - Content: {content}")
        print(f"DEBUG - Bytes (first 50): {' '.join(f'{ord(c):02x}' for c in content[:50])}")
    
    return str(pred_file.absolute())

def attest_image(image_ref, predicate_file):
    """Attest image with predicate."""
    print(f"\nGenerando atestación...")
    cmd = [
        "cosign", "attest",
        "--yes",
        "--predicate", predicate_file,
        "--type", "slsaprovenance",
        image_ref
    ]
    _, code = run_command(cmd, capture=False)  # Interactive
    return code == 0

def verify_attestation(image_ref):
    """Verify what was attested."""
    print(f"\nDEBUG - Verificando qué se atestigó:")
    cmd = [
        "cosign", "verify-attestation",
        "--type", "slsaprovenance",
        "--certificate-identity-regexp", ".*",
        "--certificate-oidc-issuer-regexp", ".*",
        image_ref
    ]
    stdout, code = run_command(cmd, capture=True)  # Non-interactive
    
    if code == 0:
        try:
            # cosign may output multiple JSON objects separated by newlines
            lines = stdout.strip().split('\n')
            if not lines or not lines[0].strip().startswith('{'):
                print(f"DEBUG - No valid JSON output: {stdout}", file=sys.stderr)
                return {}
            
            # Find the LAST valid JSON line (most recent attestation)
            valid_json_lines = [line for line in lines if line.strip().startswith('{')]
            if not valid_json_lines:
                return {}
                
            data = json.loads(valid_json_lines[-1])
            payload_b64 = data.get("payload", "")
            
            import base64
            decoded = base64.b64decode(payload_b64).decode('utf-8')
            statement = json.loads(decoded)
            print(f"DEBUG - Full statement parsed: {json.dumps(statement, indent=2)}")
            predicate = statement.get("predicate", {})
            print(f"DEBUG - Predicate parsed successfully: {json.dumps(predicate, indent=2)}")
            return predicate
        except Exception as e:
            print(f"Error decoding attestation: {e}", file=sys.stderr)
            print(f"Raw stdout was: {stdout}", file=sys.stderr)
            return {}
    return {}

def create_policy(work_dir):
    """Create minimal policy file."""
    policy = {"sources": []}
    policy_file = work_dir / "policy.json"
    
    # Delete if exists (to avoid stale data)
    if policy_file.exists():
        policy_file.unlink()
    
    with open(policy_file, 'w', encoding='utf-8') as f:
        json.dump(policy, f)
    return str(policy_file.absolute())

def validate_image(image_ref, policy_file):
    """Validate image with Enterprise Contract."""
    print(f"\nEjecutando validación EC...")
    cmd = [
        "ec", "validate", "image",
        "--image", image_ref,
        "--policy", policy_file,
        "--certificate-identity-regexp", ".*",
        "--certificate-oidc-issuer-regexp", ".*",
        "--rekor-url", "https://rekor.sigstore.dev"
    ]
    stdout, code = run_command(cmd, capture=True)  # Non-interactive
    print(stdout)
    return code == 0

def main():
    """Main entry point."""
    repo = "ghcr.io/dsmeneses17/demo-openshift-supply-chain:latest"
    work_dir = Path.cwd()
    
    # Get all digests
    digests = get_digests(repo)
    if not digests:
        print(f"No digests found for {repo}", file=sys.stderr)
        return 1
    
    print(f"Found {len(digests)} digest(es): {digests}")
    
    # Create policy once
    policy_file = create_policy(work_dir)
    
    # Process each digest
    for image_ref in digests:
        print(f"\n{'='*60}")
        print(f"Firmando y Atestando: {image_ref}")
        print(f"{'='*60}")
        
        # 1. Sign
        if not sign_image(image_ref):
            print(f"Failed to sign {image_ref}", file=sys.stderr)
            continue
        
        # 2. Create predicate
        predicate_file = create_predicate(work_dir)
        
        # 3. Attest
        if not attest_image(image_ref, predicate_file):
            print(f"Failed to attest {image_ref}", file=sys.stderr)
            continue
        
        # 4. Verify attestation
        predicate = verify_attestation(image_ref)
        if not predicate:
            print(f"WARNING: Predicate is empty for {image_ref}")
            
    # 5. Validate with EC on the main manifest list
    print(f"\n{'='*60}")
    print(f"Validando imagen principal y sus componentes: {digests[0]}")
    print(f"{'='*60}")
    validate_image(digests[0], policy_file)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
