"""
Uniplex CLI - Command-line interface for the Uniplex protocol.

Commands:
    uniplex init       Generate a new passport
    uniplex gate       Start a local gate server
    uniplex verify     Verify a passport
    uniplex info       Show passport information
"""

import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    print("CLI dependencies not installed. Run: pip install uniplex[cli]")
    sys.exit(1)

from . import __version__
from .passport import Passport
from .gate import Gate, GateRequest, TrustProfile
from .attestation import Attestation


DEFAULT_PASSPORT_FILE = "passport.json"
DEFAULT_KEY_FILE = "passport.key"


@click.group()
@click.version_option(version=__version__, prog_name="uniplex")
def main():
    """Uniplex - AI Agent Trust Infrastructure.
    
    Generate passports, run gates, and verify authorization.
    """
    pass


@main.command()
@click.option("--self-signed", is_flag=True, required=True, help="Create a self-signed (L1) passport")
@click.option("--agent-id", required=True, help="Unique identifier for the agent")
@click.option("--permissions", default="*", help="Permission pattern (default: '*' for all)")
@click.option("--expires", default="7d", help="Expiration time (e.g., '7d', '24h', '30d')")
@click.option("--output", "-o", default=DEFAULT_PASSPORT_FILE, help="Output file path")
@click.option("--key-file", default=DEFAULT_KEY_FILE, help="Private key output file")
@click.option("--json-output", is_flag=True, help="Output passport as JSON to stdout")
def init(self_signed: bool, agent_id: str, permissions: str, expires: str, 
         output: str, key_file: str, json_output: bool):
    """Generate a new Uniplex passport.
    
    Example:
        uniplex init --self-signed --agent-id "my-agent" --permissions "*"
    """
    # Parse expiration
    expires_td = parse_duration(expires)
    if expires_td is None:
        click.echo(f"Error: Invalid expiration format '{expires}'. Use format like '7d', '24h', '30d'", err=True)
        sys.exit(1)
    
    # Parse permissions
    perm_list = [p.strip() for p in permissions.split(",")]
    
    # Create passport
    passport = Passport.create_self_issued(
        agent_id=agent_id,
        permissions=perm_list,
        expires_in=expires_td,
    )
    
    if json_output:
        # Output JSON to stdout (for piping)
        click.echo(passport.to_json(indent=None))
    else:
        # Save to files
        passport.save(output)
        
        # Save private key if we have it
        if passport._private_key:
            with open(key_file, "wb") as f:
                f.write(passport._private_key)
            os.chmod(key_file, 0o600)  # Restrict permissions
        
        click.echo(f"✓ Created passport: {output}")
        click.echo(f"  Agent ID:    {agent_id}")
        click.echo(f"  Passport ID: {passport.passport_id}")
        click.echo(f"  Permissions: {permissions}")
        click.echo(f"  Expires:     {passport.provenance.expires_at}")
        click.echo(f"  Private key: {key_file}")
        click.echo()
        click.echo("Set environment variable for SDK usage:")
        click.echo(f"  export UNIPLEX_PASSPORT=\"$(cat {output})\"")


@main.command()
@click.option("--profile", type=click.Choice(["L1", "L2", "L3"]), default="L1", help="Trust profile level")
@click.option("--port", default=8080, help="Port to listen on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--require-pop", is_flag=True, help="Require Proof of Possession")
@click.option("--gate-id", default=None, help="Gate identifier")
def gate(profile: str, port: int, host: str, require_pop: bool, gate_id: str):
    """Start a local Uniplex gate server.
    
    Example:
        uniplex gate --profile L1 --port 8080
        uniplex gate --profile L2 --require-pop --port 8080
    """
    try:
        import uvicorn
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import JSONResponse
    except ImportError:
        click.echo("Gate server dependencies not installed. Run: pip install uniplex[cli]", err=True)
        sys.exit(1)
    
    # Create FastAPI app
    app = FastAPI(
        title="Uniplex Gate",
        description="Authorization gate for AI agents",
        version=__version__,
    )
    
    # Create gate with specified profile
    trust_profile = TrustProfile(profile)
    
    # For L2+, require PoP by default
    if trust_profile in (TrustProfile.L2, TrustProfile.L3):
        require_pop = True
    
    gate_instance = Gate(
        profile=trust_profile,
        require_pop=require_pop,
        gate_id=gate_id or f"gate_{host}:{port}",
    )
    
    @app.post("/authorize")
    async def authorize(request_data: dict):
        """Process an authorization request."""
        try:
            request = GateRequest.model_validate(request_data)
            decision = gate_instance.authorize(request)
            return JSONResponse(content=decision.model_dump(exclude_none=True))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "profile": profile,
            "version": __version__,
            "require_pop": require_pop,
        }
    
    @app.get("/")
    async def root():
        """Root endpoint with gate info."""
        return {
            "name": "Uniplex Gate",
            "version": __version__,
            "profile": profile,
            "require_pop": require_pop,
            "endpoints": {
                "authorize": "POST /authorize",
                "health": "GET /health",
            }
        }
    
    click.echo(f"Starting Uniplex Gate (Profile: {profile})")
    click.echo(f"Listening on http://{host}:{port}")
    if require_pop:
        click.echo("Proof of Possession: REQUIRED")
    click.echo()
    click.echo("Endpoints:")
    click.echo(f"  POST http://{host}:{port}/authorize")
    click.echo(f"  GET  http://{host}:{port}/health")
    click.echo()
    
    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command()
@click.argument("input_file")
@click.option("--output", "-o", default=None, help="Output file (default: secured-<input>)")
@click.option("--profile", type=click.Choice(["L1", "L2", "L3"]), default="L2", help="Trust profile")
@click.option("--server-id", default=None, help="Server ID for the wrapper")
def wrap(input_file: str, output: str, profile: str, server_id: str):
    """Wrap an MCP server with Uniplex authorization.
    
    Example:
        uniplex wrap ./my-mcp-server.py --profile L2 --output ./secured-server.py
    """
    from .mcp import generate_wrapper_code
    
    if not os.path.exists(input_file):
        click.echo(f"Error: Input file not found: {input_file}", err=True)
        sys.exit(1)
    
    # Default output filename
    if output is None:
        base = os.path.basename(input_file)
        name, ext = os.path.splitext(base)
        output = f"secured-{name}{ext}"
    
    # Default server ID
    if server_id is None:
        base = os.path.basename(input_file).replace(".py", "")
        server_id = f"mcp://{base}.local"
    
    trust_profile = TrustProfile(profile)
    
    # Generate wrapper code
    wrapper_code = generate_wrapper_code(
        input_file=input_file,
        output_file=output,
        server_id=server_id,
        profile=trust_profile,
    )
    
    with open(output, "w") as f:
        f.write(wrapper_code)
    
    click.echo(f"✓ Created wrapped server: {output}")
    click.echo(f"  Server ID: {server_id}")
    click.echo(f"  Profile:   {profile}")
    click.echo()
    click.echo("Run with:")
    click.echo(f"  python {output}")


@main.command()
@click.argument("passport_file", default=DEFAULT_PASSPORT_FILE)
def verify(passport_file: str):
    """Verify a passport's signature and validity.
    
    Example:
        uniplex verify passport.json
    """
    try:
        passport = Passport.load(passport_file)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {passport_file}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON: {e}", err=True)
        sys.exit(1)
    
    # Check signature
    sig_valid = passport.verify_signature()
    expired = passport.is_expired()
    
    click.echo(f"Passport: {passport_file}")
    click.echo(f"  ID:         {passport.passport_id}")
    click.echo(f"  Agent:      {passport.identity.agent_id}")
    click.echo(f"  Issuer:     {passport.provenance.issuer.id} ({passport.provenance.issuer.type})")
    click.echo(f"  Issued:     {passport.provenance.issued_at}")
    click.echo(f"  Expires:    {passport.provenance.expires_at}")
    click.echo(f"  Signature:  {'✓ Valid' if sig_valid else '✗ INVALID'}")
    click.echo(f"  Expired:    {'✗ YES' if expired else '✓ No'}")
    
    if not sig_valid or expired:
        sys.exit(1)


@main.command()
@click.argument("passport_file", default=DEFAULT_PASSPORT_FILE)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def info(passport_file: str, as_json: bool):
    """Show passport information.
    
    Example:
        uniplex info passport.json
    """
    try:
        passport = Passport.load(passport_file)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {passport_file}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON: {e}", err=True)
        sys.exit(1)
    
    if as_json:
        click.echo(passport.to_json())
    else:
        click.echo(f"Passport ID:  {passport.passport_id}")
        click.echo(f"Agent ID:     {passport.identity.agent_id}")
        click.echo(f"Issuer:       {passport.provenance.issuer.id}")
        click.echo(f"Issuer Type:  {passport.provenance.issuer.type}")
        click.echo(f"Issued At:    {passport.provenance.issued_at}")
        click.echo(f"Expires At:   {passport.provenance.expires_at}")
        click.echo(f"Permissions:")
        for perm in passport.permissions:
            target = f" (target: {perm.target})" if perm.target else ""
            click.echo(f"  - {perm.action}{target}")


@main.command()
@click.argument("passport_file", default=DEFAULT_PASSPORT_FILE)
@click.argument("action")
@click.option("--target", help="Optional target identifier")
@click.option("--profile", type=click.Choice(["L1", "L2", "L3"]), default="L1", help="Trust profile")
def check(passport_file: str, action: str, target: Optional[str], profile: str):
    """Check if a passport can perform an action.
    
    Example:
        uniplex check passport.json "tools:search" --target "mcp://server"
    """
    try:
        passport = Passport.load(passport_file)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {passport_file}", err=True)
        sys.exit(1)
    
    trust_profile = TrustProfile(profile)
    gate_instance = Gate(profile=trust_profile)
    decision = gate_instance.authorize_simple(passport, action, target)
    
    if decision.allowed:
        click.echo(f"✓ ALLOWED: {action}")
        click.echo(f"  Agent: {decision.agent_id}")
    else:
        click.echo(f"✗ DENIED: {action}")
        click.echo(f"  Reason: {decision.reason}")
        click.echo(f"  Code:   {decision.reason_code}")
        sys.exit(1)


def parse_duration(s: str) -> Optional[timedelta]:
    """Parse a duration string like '7d', '24h', '30m' into timedelta."""
    s = s.strip().lower()
    
    if s.endswith("d"):
        try:
            return timedelta(days=int(s[:-1]))
        except ValueError:
            return None
    elif s.endswith("h"):
        try:
            return timedelta(hours=int(s[:-1]))
        except ValueError:
            return None
    elif s.endswith("m"):
        try:
            return timedelta(minutes=int(s[:-1]))
        except ValueError:
            return None
    elif s.endswith("s"):
        try:
            return timedelta(seconds=int(s[:-1]))
        except ValueError:
            return None
    else:
        # Try as days
        try:
            return timedelta(days=int(s))
        except ValueError:
            return None


if __name__ == "__main__":
    main()
