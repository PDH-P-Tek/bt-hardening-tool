"""Setup routes — Phase 2.1.

Server-rendered, no client-side framework, no external assets. The tool runs offline
on team kit and a page that needs a CDN is a page that does not load.

Every field here is typed by the operator. Configuration import fills interfaces in
*for confirmation* and never applies anything silently: a mis-parse the operator did
not see is the failure mode this whole flow is designed against.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from btht.app.data import ESTATES, ISA_CHECKS
from btht.app.generate.diff import Gate, diff_rulesets, gate_for
from btht.app.generate.emit import checklist
from btht.app.generate.order import GenerationRefused, generate
from btht.app.ingest.annex import looks_out_of_bounds, parse_rows, split_kinds
from btht.app.ingest.isa import load_catalogue
from btht.app.ingest.pfsense import ParseError, parse_string
from btht.app.ingest.roles import derive_interfaces, derive_side
from btht.app.model.estate import Estate, Firewall, Host, Node, Platform, SourceOfTruth
from btht.app.model.policy import (
    EgressPolicy,
    EstateFileError,
    FirewallPolicy,
    Policy,
    Selector,
    ServiceRule,
    convention_of,
    load_estate,
    load_policy,
    parse_address,
    save_estate,
    save_policy,
    side_rules_of,
    validate_policy,
)
from btht.app.validate.rules import Context, Severity, run_all
from btht.app.web.topology import details_json, layout, render_svg

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()


def estate_path(slug: str) -> Path:
    """Estates live in a gitignored directory. Slugs never leave it."""
    safe = "".join(c for c in slug if c.isalnum() or c in "-_")
    if not safe:
        raise EstateFileError("estate name must contain a letter or a digit")
    return ESTATES / f"{safe}.yaml"


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def render(request: Request, template: str, **context: Any) -> HTMLResponse:
    context.setdefault("messages", [])
    return TEMPLATES.TemplateResponse(request, template, context)


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    estates = []
    if ESTATES.is_dir():
        for path in sorted(ESTATES.glob("*.yaml")):
            try:
                estate = load_estate(path)
            except (EstateFileError, ValueError):
                continue
            estates.append(
                {
                    "slug": path.stem,
                    "team": estate.team,
                    "enclaves": len(estate.firewalls),
                    "nodes": len(estate.all_nodes()),
                }
            )
    return render(request, "index.html", estates=estates)


@router.post("/estates")
def create_estate(
    slug: str = Form(...),
    team: int = Form(0),
    team_padded: str = Form(""),
    vocabulary: str = Form(""),
    tokens: str = Form(""),
) -> RedirectResponse:
    path = estate_path(slug)
    estate = Estate(
        team=team,
        team_padded=team_padded.strip() or str(team),
        role_vocabulary=_split(vocabulary),
    )
    save_estate(estate, path, enclave_tokens=_split(tokens))
    return RedirectResponse(f"/estates/{path.stem}", status_code=303)


@router.get("/estates/{slug}", response_class=HTMLResponse)
def show_estate(request: Request, slug: str) -> HTMLResponse:
    path = estate_path(slug)
    if not path.exists():
        return render(
            request,
            "index.html",
            estates=[],
            messages=[("err", f"no estate called {slug}")],
        )
    estate = load_estate(path)
    return render(
        request,
        "estate.html",
        slug=path.stem,
        estate=estate,
        platforms=[p.value for p in Platform],
        messages=request.query_params.getlist("m") and [("ok", request.query_params["m"])] or [],
    )


@router.post("/estates/{slug}/enclaves")
def add_enclave(
    slug: str,
    name: str = Form(...),
    fqdn: str = Form(""),
    platform: str = Form("pfsense"),
    mgmt_address: str = Form(...),
    credential_ref: str = Form(""),
) -> RedirectResponse:
    path = estate_path(slug)
    estate = load_estate(path)
    node = Node(
        name=fqdn.strip() or name.strip(),
        platform=Platform(platform),
        mgmt_address=parse_address(mgmt_address),
        credential_ref=credential_ref.strip(),
        enclave=name.strip(),
    )
    firewall = Firewall(enclave=name.strip(), fqdn=fqdn.strip(), node=node)
    estate = replace(estate, firewalls=(*estate.firewalls, firewall))
    save_estate(estate, path, convention_of(path).enclave_tokens, side_rules_of(path))
    return RedirectResponse(f"/estates/{slug}", status_code=303)


@router.post("/estates/{slug}/enclaves/{enclave}/interfaces")
def add_interface(
    slug: str,
    enclave: str,
    ifname: str = Form(...),
    role: str = Form(...),
    v4: str = Form(""),
    v6: str = Form(""),
    descr: str = Form(""),
) -> RedirectResponse:
    from btht.app.model.estate import Interface

    path = estate_path(slug)
    estate = load_estate(path)
    interface = Interface(
        ifname=ifname.strip(),
        role=role.strip(),
        descr=descr.strip(),
        v4=parse_address(v4),
        v6=parse_address(v6),
        is_lan=ifname.strip() == "lan",
    )
    firewalls = tuple(
        replace(fw, interfaces=(*fw.interfaces, interface)) if fw.enclave == enclave else fw
        for fw in estate.firewalls
    )
    save_estate(
        replace(estate, firewalls=firewalls),
        path,
        convention_of(path).enclave_tokens,
        side_rules_of(path),
    )
    return RedirectResponse(f"/estates/{slug}", status_code=303)


@router.post("/estates/{slug}/enclaves/{enclave}/import")
async def import_config(
    request: Request, slug: str, enclave: str, config: UploadFile = File(...)
) -> Any:
    """Fill interfaces in from a configuration, for the operator to confirm."""
    path = estate_path(slug)
    estate = load_estate(path)
    convention = convention_of(path)

    try:
        parsed = parse_string((await config.read()).decode("utf-8", errors="replace"))
    except (ParseError, UnicodeDecodeError) as exc:
        return render(
            request,
            "estate.html",
            slug=path.stem,
            estate=estate,
            platforms=[p.value for p in Platform],
            messages=[("err", f"could not read that file: {exc}")],
        )

    interfaces = derive_interfaces(parsed.interfaces, convention)
    side = derive_side(interfaces, side_rules_of(path))

    firewalls = tuple(
        replace(
            fw,
            interfaces=interfaces,
            side=side or fw.side,
            config_version=parsed.facts.config_version or fw.config_version,
        )
        if fw.enclave == enclave
        else fw
        for fw in estate.firewalls
    )
    estate = replace(estate, firewalls=firewalls)
    save_estate(estate, path, convention.enclave_tokens, side_rules_of(path))

    unresolved = sum(1 for i in interfaces if i.role.startswith("other:"))
    note = (
        f"read {len(interfaces)} interface(s) — check them against the box before continuing"
        if not unresolved
        else f"read {len(interfaces)} interface(s); {unresolved} could not be placed from "
        "your declared vocabulary and need a role"
    )
    return render(
        request,
        "estate.html",
        slug=path.stem,
        estate=estate,
        platforms=[p.value for p in Platform],
        messages=[("warn" if unresolved else "ok", note)],
    )


@router.get("/estates/{slug}/topology", response_class=HTMLResponse)
def show_topology(request: Request, slug: str) -> HTMLResponse:
    """The declared estate, drawn. Read-only by design — see `topology.py`."""
    path = estate_path(slug)
    if not path.exists():
        return render(
            request, "index.html", estates=[], messages=[("err", f"no estate called {slug}")]
        )
    diagram = layout(load_estate(path))
    return render(
        request,
        "topology.html",
        slug=path.stem,
        svg=render_svg(diagram),
        details=details_json(diagram),
    )


def _selector_text(selector: Selector) -> str:
    """One line describing who a rule applies to. The operator reads this, not YAML."""
    if selector.any:
        return "anywhere"
    parts: list[str] = []
    if selector.segments:
        parts.append("segments " + ", ".join(selector.segments))
    if selector.enclaves:
        parts.append("enclaves " + ", ".join(selector.enclaves))
    if selector.alias:
        parts.append(f"alias {selector.alias}")
    if selector.host:
        parts.append(selector.host)
    return " · ".join(parts) or "not declared"


def _with_firewall(policy: Policy, enclave: str, **changes: Any) -> Policy:
    """Update one firewall's policy, creating it if the operator has not started it."""
    existing = policy.for_enclave(enclave) or FirewallPolicy(enclave=enclave)
    updated = replace(existing, **changes)
    others = tuple(f for f in policy.firewalls if f.enclave != enclave)
    return replace(policy, firewalls=(*others, updated))


@router.get("/estates/{slug}/policy/{enclave}", response_class=HTMLResponse)
def wizard(request: Request, slug: str, enclave: str, step: str = "0") -> HTMLResponse:
    """Walk one firewall segment by segment — `SPEC.md` §5.1."""
    path = estate_path(slug)
    estate = load_estate(path)
    policy = load_policy(path)
    firewall = estate.firewall(enclave)
    if firewall is None:
        return render(
            request, "index.html", estates=[], messages=[("err", f"no enclave {enclave}")]
        )

    segments = [i for i in firewall.interfaces if i.role != "wan"]
    entry = policy.for_enclave(enclave) or FirewallPolicy(enclave=enclave)

    on_egress = step == "egress"
    index = 0 if on_egress else max(0, min(int(step or 0), max(len(segments) - 1, 0)))
    segment = None if on_egress or not segments else segments[index]

    services = []
    if segment is not None:
        for service in entry.services:
            if service.segment == segment.role:
                services.append(
                    {
                        "name": service.name,
                        "protocol": service.protocol,
                        "ports": list(service.ports),
                        "source_text": _selector_text(service.source),
                    }
                )

    return render(
        request,
        "wizard.html",
        slug=path.stem,
        enclave=enclave,
        steps=segments,
        step="egress" if on_egress else index,
        total=len(segments),
        segment=segment,
        hosts=[h for h in firewall.hosts if segment and h.segment_role == segment.role],
        services=services,
        egress=entry.egress,
        problems=validate_policy(policy, estate),
    )


@router.post("/estates/{slug}/policy/{enclave}/services")
def add_service(
    slug: str,
    enclave: str,
    step: str = Form("0"),
    segment: str = Form(...),
    name: str = Form(...),
    protocol: str = Form("tcp"),
    ports: str = Form(""),
    host: str = Form(""),
    from_segments: str = Form(""),
    from_enclaves: str = Form(""),
    from_alias: str = Form(""),
    from_any: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    path = estate_path(slug)
    policy = load_policy(path)
    entry = policy.for_enclave(enclave) or FirewallPolicy(enclave=enclave)

    service = ServiceRule(
        name=name.strip(),
        segment=segment.strip(),
        host=host.strip(),
        protocol=protocol.strip(),
        ports=tuple(int(p) for p in _split(ports) if p.isdigit()),
        source=Selector(
            any=from_any == "yes",
            alias=from_alias.strip(),
            segments=_split(from_segments),
            enclaves=_split(from_enclaves),
        ),
        notes=notes.strip(),
    )
    save_policy(
        _with_firewall(policy, enclave, services=(*entry.services, service)),
        path,
    )
    return RedirectResponse(f"/estates/{slug}/policy/{enclave}?step={step}", status_code=303)


@router.post("/estates/{slug}/policy/{enclave}/egress")
def set_egress(
    slug: str,
    enclave: str,
    default: str = Form("deny_and_log"),
    notes: str = Form(""),
) -> RedirectResponse:
    path = estate_path(slug)
    policy = load_policy(path)
    entry = policy.for_enclave(enclave) or FirewallPolicy(enclave=enclave)
    save_policy(
        _with_firewall(
            policy,
            enclave,
            egress=EgressPolicy(
                default=default.strip(), allow=entry.egress.allow, notes=notes.strip()
            ),
        ),
        path,
    )
    return RedirectResponse(f"/estates/{slug}/policy/{enclave}?step=egress", status_code=303)


def _paste_context(estate: Estate, enclave: str, text: str) -> dict[str, Any]:
    """Everything the preview needs. Nothing here touches the estate."""
    rows = parse_rows(text) if text.strip() else ()
    networks, hosts = split_kinds(rows)
    firewall = estate.firewall(enclave)
    declared = firewall.interfaces if firewall else ()

    subnets = []
    for row in networks:
        matched = ""
        for iface in declared:
            if iface.v4 and str(iface.v4.network) == row.v4:
                matched = iface.role
                break
        subnets.append({"name": row.name, "v4": row.v4, "matched": matched})

    return {
        "text": text,
        "parsed": [
            {
                "name": row.name,
                "v4": row.v4,
                "v6": row.v6,
                "description": row.description,
                "source_line": row.source_line,
                "looks_complete": row.looks_complete,
                "out_of_bounds": looks_out_of_bounds(row),
            }
            for row in hosts
        ],
        "subnets": subnets,
        "unreadable": sum(1 for row in hosts if not row.looks_complete),
    }


@router.get("/estates/{slug}/enclaves/{enclave}/paste", response_class=HTMLResponse)
def paste_form(request: Request, slug: str, enclave: str) -> HTMLResponse:
    return render(request, "paste.html", slug=estate_path(slug).stem, enclave=enclave, text="")


@router.post("/estates/{slug}/enclaves/{enclave}/paste", response_class=HTMLResponse)
def paste_preview(request: Request, slug: str, enclave: str, text: str = Form("")) -> HTMLResponse:
    """Render the parse back. **Nothing is applied here** — `SPEC.md` §5.2."""
    path = estate_path(slug)
    estate = load_estate(path)
    return render(
        request,
        "paste.html",
        slug=path.stem,
        enclave=enclave,
        **_paste_context(estate, enclave, text),
    )


@router.post("/estates/{slug}/enclaves/{enclave}/paste/confirm")
def paste_confirm(
    slug: str, enclave: str, text: str = Form(""), keep: list[int] = Form(default=[])
) -> RedirectResponse:
    """Apply only the rows the operator ticked.

    The paste is parsed again here rather than trusting values round-tripped through
    the form: what gets saved is then provably what was previewed, from the same input
    through the same code.
    """
    path = estate_path(slug)
    estate = load_estate(path)
    _, rows = split_kinds(parse_rows(text))
    chosen = [rows[i] for i in keep if 0 <= i < len(rows)]

    new_hosts = tuple(
        Host(
            hostname=row.name,
            v4=parse_address(row.v4) if row.v4 else None,
            v6=parse_address(row.v6) if row.v6 else None,
            out_of_bounds=looks_out_of_bounds(row),
            source_of_truth=SourceOfTruth.ANNEX,
        )
        for row in chosen
        if row.looks_complete
    )
    firewalls = tuple(
        replace(fw, hosts=(*fw.hosts, *new_hosts)) if fw.enclave == enclave else fw
        for fw in estate.firewalls
    )
    save_estate(
        replace(estate, firewalls=firewalls),
        path,
        convention_of(path).enclave_tokens,
        side_rules_of(path),
    )
    return RedirectResponse(f"/estates/{slug}", status_code=303)


#: Acknowledgements are per estate, per enclave, and last only as long as the process.
#: They are a decision about *this* generated ruleset; regenerating must re-ask.
_ACKNOWLEDGED: dict[tuple[str, str], set[str]] = {}


def _review(slug: str, enclave: str):  # type: ignore[no-untyped-def]
    """Generate, validate and gate. Everything the review page needs, in one place."""
    path = estate_path(slug)
    estate = load_estate(path)
    policy = load_policy(path)
    firewall = estate.firewall(enclave)
    if firewall is None:
        return None

    catalogue = load_catalogue(ISA_CHECKS if ISA_CHECKS.exists() else None)
    ruleset = generate(
        firewall,
        policy,
        catalogue,
        scoring_source=Selector(alias="Scoring_Sources"),
        essential={"dns": Selector(alias="DNS_Servers"), "ntp": Selector(alias="NTP_Servers")},
    )
    findings = run_all(
        Context(firewall=firewall, ruleset=ruleset, policy=policy, catalogue=catalogue)
    )
    acknowledged = frozenset(_ACKNOWLEDGED.get((slug, enclave), set()))
    return (
        firewall,
        ruleset,
        findings,
        gate_for(findings, acknowledged),
        diff_rulesets(firewall.rules, ruleset),
    )


@router.get("/estates/{slug}/review/{enclave}", response_class=HTMLResponse)
def review(request: Request, slug: str, enclave: str) -> HTMLResponse:
    """The diff gate — `SPEC.md` §9. The last thing before anything reaches a firewall."""
    try:
        result = _review(slug, enclave)
    except GenerationRefused as exc:
        return render(
            request,
            "estate.html",
            slug=estate_path(slug).stem,
            estate=load_estate(estate_path(slug)),
            platforms=[p.value for p in Platform],
            messages=[("err", f"Refusing to generate: {exc}")],
        )
    if result is None:
        return render(
            request, "index.html", estates=[], messages=[("err", f"no enclave {enclave}")]
        )
    _firewall, _ruleset, findings, gate, diff = result
    return render(
        request,
        "review.html",
        slug=estate_path(slug).stem,
        enclave=enclave,
        gate=gate,
        keys=[Gate.key(f) for f in gate.warnings],
        info=[f for f in findings if f.severity is Severity.INFO],
        diff=diff,
    )


@router.post("/estates/{slug}/review/{enclave}/acknowledge")
def acknowledge(slug: str, enclave: str, key: str = Form(...)) -> RedirectResponse:
    """One finding, one decision. There is no accept-all endpoint, deliberately."""
    _ACKNOWLEDGED.setdefault((slug, enclave), set()).add(key)
    return RedirectResponse(f"/estates/{slug}/review/{enclave}", status_code=303)


@router.post("/estates/{slug}/review/{enclave}/export")
def export(slug: str, enclave: str) -> Any:
    """Export is refused unless the gate opens. Checked here, not only in the template."""
    from fastapi.responses import PlainTextResponse

    try:
        result = _review(slug, enclave)
    except GenerationRefused as exc:
        # A refusal is a decision, not a crash. It must read as one at every entry
        # point, or an operator sees a 500 and assumes the tool is broken rather than
        # that their policy is incomplete.
        return PlainTextResponse(f"Refusing to generate: {exc}", status_code=409)
    if result is None:
        return RedirectResponse(f"/estates/{slug}", status_code=303)
    _firewall, ruleset, _findings, gate, _diff = result
    if not gate.may_export:
        return PlainTextResponse(f"Export refused. {gate.reason}", status_code=409)
    return PlainTextResponse(checklist(ruleset, team=str(load_estate(estate_path(slug)).team)))


@router.get("/estates/{slug}/monitor", response_class=HTMLResponse)
def monitor_dashboard(request: Request, slug: str) -> HTMLResponse:
    """The topology with live status on it — `BUILD-PLAN.md` 5.4.

    Not a second dashboard. The operator already reads this picture, and a host that
    stops answering should change on the picture they are already looking at.
    """
    from btht.app.monitor.store import Store

    path = estate_path(slug)
    estate = load_estate(path)
    database = ESTATES / f"{path.stem}-monitor.sqlite"

    status: dict[str, str] = {}
    worklist: list[dict[str, str]] = []
    if database.exists():
        store = Store(database)
        try:
            for beat in store.heartbeats():
                status[str(beat["host"])] = (
                    "reachable" if beat["reachable"] else f"unreachable — {beat['error']}"
                )
            for row in store.worklist():
                worklist.append(
                    {
                        "host": str(row["host"]),
                        "label": str(row["label"]),
                        "note": str(row["note"]),
                        "collector": str(row["collector"]),
                    }
                )
        finally:
            store.close()

    diagram = layout(estate, status)
    return render(
        request,
        "monitor.html",
        slug=path.stem,
        svg=render_svg(diagram),
        details=details_json(diagram),
        polled=bool(status),
        worklist=worklist,
    )
