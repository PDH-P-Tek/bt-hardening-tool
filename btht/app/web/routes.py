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

from btht.app.data import ESTATES, ISA_CHECKS, SERVICE_CATALOGUE
from btht.app.generate.diff import Gate, diff_rulesets, gate_for
from btht.app.generate.emit import checklist
from btht.app.generate.order import GenerationRefused, generate
from btht.app.ingest.annex import looks_out_of_bounds, parse_rows, split_kinds
from btht.app.ingest.isa import load_catalogue
from btht.app.ingest.pfsense import ParseError, parse_string
from btht.app.ingest.roles import derive_interfaces, derive_side
from btht.app.model.edit import (
    InUse,
    remove_firewall,
    remove_host,
    remove_host_group,
    remove_host_type,
    remove_interface,
    remove_service,
    rename_service,
    update_firewall,
    update_host,
    update_host_group,
    update_host_type,
    update_interface,
    update_service,
)
from btht.app.model.estate import (
    Estate,
    Firewall,
    Host,
    HostGroup,
    Node,
    Platform,
    SourceOfTruth,
)
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
from btht.app.model.services import (
    Catalogue,
    Confidence,
    HostType,
    Service,
)
from btht.app.model.services import (
    load_catalogue as load_services,
)
from btht.app.model.services import (
    save_catalogue as save_services,
)
from btht.app.validate.rules import Context, Severity, run_all
from btht.app.web.topology import View, layout, render_svg

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()


#: A team has one range. There is no list to choose from, no second estate to confuse
#: it with, and no slug in any URL — the front page *is* the range.
RANGE_FILE = "range.yaml"


def estate_path(_slug: str = "") -> Path:
    """The one range file. The argument is ignored and kept only so callers read the same."""
    return ESTATES / RANGE_FILE


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def render(request: Request, template: str, **context: Any) -> HTMLResponse:
    context.setdefault("messages", [])
    return TEMPLATES.TemplateResponse(request, template, context)


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """The front page is the range. A team has one, so there is nothing to pick from."""
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    return _range_page(request, path)


def _range_page(
    request: Request, path: Path, messages: list[tuple[str, str]] | None = None
) -> HTMLResponse:
    """The range, one level at a time.

    Enclaves, then the interfaces of the one selected, then the hosts on the interface
    selected. The form for adding to the level you are looking at appears beside it,
    so adding an interface is never offered while you are looking at hosts.
    """
    estate = load_estate(path)
    catalogue = load_services(SERVICE_CATALOGUE)
    params = request.query_params
    enclave = params.get("enclave", "")
    ifname = params.get("interface", "")
    showing_devices = params.get("devices") == "1"

    firewall = estate.firewall(enclave) if enclave else None
    interface = None
    hosts: tuple[Host, ...] = ()
    groups: tuple[HostGroup, ...] = ()
    if firewall is not None and ifname:
        interface = next((i for i in firewall.interfaces if i.ifname == ifname), None)
        if interface is not None:
            hosts = tuple(h for h in firewall.hosts if h.segment_role == interface.role)
            groups = tuple(g for g in firewall.host_groups if g.segment_role == interface.role)

    return render(
        request,
        "range.html",
        declared=True,
        estate=estate,
        catalogue=catalogue,
        platforms=[p.value for p in Platform],
        host_count=sum(len(f.all_hosts(catalogue)) for f in estate.firewalls),
        selected_enclave=enclave,
        selected_interface=ifname,
        showing_devices=showing_devices,
        devices=sorted(estate.nodes, key=lambda n: n.name),
        firewall=firewall,
        interface=interface,
        hosts=hosts,
        groups=groups,
        host_types=sorted(catalogue.host_types),
        enclave_tokens=convention_of(path).enclave_tokens,
        messages=messages
        or (
            [(request.query_params.get("k", "ok"), request.query_params["m"])]
            if request.query_params.get("m")
            else []
        ),
    )


@router.post("/range/create")
def create_estate(
    team: int = Form(0),
    team_name: str = Form(""),
    team_padded: str = Form(""),
    vocabulary: str = Form(""),
    tokens: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
    estate = Estate(
        team=team,
        team_name=team_name.strip(),
        team_padded=team_padded.strip(),
        role_vocabulary=_split(vocabulary),
    )
    save_estate(estate, path, enclave_tokens=_split(tokens))
    return RedirectResponse("/range", status_code=303)


@router.get("/range", response_class=HTMLResponse)
def show_range(request: Request) -> HTMLResponse:
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    return _range_page(request, path)


@router.post("/range/enclaves")
def add_enclave(
    name: str = Form(...),
    fqdn: str = Form(""),
    platform: str = Form("pfsense"),
    mgmt_address: str = Form(...),
    credential_ref: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
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
    return RedirectResponse("/range", status_code=303)


@router.post("/range/enclaves/{enclave}/interfaces")
def add_interface(
    enclave: str,
    ifname: str = Form(...),
    role: str = Form(...),
    v4: str = Form(""),
    v6: str = Form(""),
    descr: str = Form(""),
    upstreams: list[str] = Form(default=[]),
) -> RedirectResponse:
    from btht.app.model.estate import Interface

    path = estate_path()
    estate = load_estate(path)
    interface = Interface(
        ifname=ifname.strip(),
        role=role.strip(),
        descr=descr.strip(),
        v4=parse_address(v4),
        v6=parse_address(v6),
        is_lan=ifname.strip() == "lan",
        upstreams=tuple(u for u in upstreams if u),
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
    return RedirectResponse("/range", status_code=303)


@router.post("/range/enclaves/{enclave}/import")
async def import_config(request: Request, enclave: str, config: UploadFile = File(...)) -> Any:
    """Fill interfaces in from a configuration, for the operator to confirm."""
    path = estate_path()
    estate = load_estate(path)
    convention = convention_of(path)

    try:
        parsed = parse_string((await config.read()).decode("utf-8", errors="replace"))
    except (ParseError, UnicodeDecodeError) as exc:
        return _range_page(request, path, [("err", f"could not read that file: {exc}")])

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
    return _range_page(request, path, [("warn" if unresolved else "ok", note)])


@router.get("/range/topology", response_class=HTMLResponse)
def show_topology(request: Request) -> HTMLResponse:
    """The declared estate, drawn. Read-only by design — see `topology.py`.

    What is open and what is filtered come from the query string, so the picture is a
    pure function of them and any particular view is a link.
    """
    path = estate_path()
    if not path.exists():
        return render(
            request, "index.html", declared=False, messages=[("err", "no range declared yet")]
        )
    estate = load_estate(path)
    catalogue = load_services(SERVICE_CATALOGUE)
    params = request.query_params
    view = View(
        open_ids=frozenset(params.getlist("open")),
        focus_id=params.get("focus", ""),
        host_type=params.get("host_type", ""),
        service=params.get("service", ""),
        only_scored=params.get("scored") == "1",
        only_out_of_bounds=params.get("oob") == "1",
    )
    diagram = layout(estate, view, slug=path.stem, catalogue=catalogue)
    return render(
        request,
        "topology.html",
        slug=path.stem,
        estate=estate,
        view=view,
        diagram=diagram,
        svg=render_svg(diagram),
        open_ids=sorted(view.open_ids),
        host_types=sorted(catalogue.host_types),
        services=sorted(catalogue.services),
        open_all_links={f.enclave: view.open_all_link(f, path.stem) for f in estate.firewalls},
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


@router.get("/range/policy/{enclave}", response_class=HTMLResponse)
def wizard(request: Request, enclave: str, step: str = "0") -> HTMLResponse:
    """Walk one firewall segment by segment — `SPEC.md` §5.1."""
    path = estate_path()
    estate = load_estate(path)
    policy = load_policy(path)
    firewall = estate.firewall(enclave)
    if firewall is None:
        return render(
            request, "index.html", declared=False, messages=[("err", f"no enclave {enclave}")]
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


@router.post("/range/policy/{enclave}/services")
def add_service(
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
    path = estate_path()
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
    return RedirectResponse(f"/range/policy/{enclave}?step={step}", status_code=303)


@router.post("/range/policy/{enclave}/egress")
def set_egress(
    enclave: str,
    default: str = Form("deny_and_log"),
    notes: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
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
    return RedirectResponse(f"/range/policy/{enclave}?step=egress", status_code=303)


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


@router.get("/range/enclaves/{enclave}/paste", response_class=HTMLResponse)
def paste_form(request: Request, enclave: str) -> HTMLResponse:
    return render(request, "paste.html", slug=estate_path().stem, enclave=enclave, text="")


@router.post("/range/enclaves/{enclave}/paste", response_class=HTMLResponse)
def paste_preview(request: Request, enclave: str, text: str = Form("")) -> HTMLResponse:
    """Render the parse back. **Nothing is applied here** — `SPEC.md` §5.2."""
    path = estate_path()
    estate = load_estate(path)
    return render(
        request,
        "paste.html",
        slug=path.stem,
        enclave=enclave,
        **_paste_context(estate, enclave, text),
    )


@router.post("/range/enclaves/{enclave}/paste/confirm")
def paste_confirm(
    enclave: str, text: str = Form(""), keep: list[int] = Form(default=[])
) -> RedirectResponse:
    """Apply only the rows the operator ticked.

    The paste is parsed again here rather than trusting values round-tripped through
    the form: what gets saved is then provably what was previewed, from the same input
    through the same code.
    """
    path = estate_path()
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
    return RedirectResponse("/range", status_code=303)


#: Acknowledgements are per estate, per enclave, and last only as long as the process.
#: They are a decision about *this* generated ruleset; regenerating must re-ask.
_ACKNOWLEDGED: dict[str, set[str]] = {}


def _review(enclave: str):  # type: ignore[no-untyped-def]
    """Generate, validate and gate. Everything the review page needs, in one place."""
    path = estate_path()
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
    acknowledged = frozenset(_ACKNOWLEDGED.get(enclave, set()))
    return (
        firewall,
        ruleset,
        findings,
        gate_for(findings, acknowledged),
        diff_rulesets(firewall.rules, ruleset),
    )


@router.get("/range/review/{enclave}", response_class=HTMLResponse)
def review(request: Request, enclave: str) -> HTMLResponse:
    """The diff gate — `SPEC.md` §9. The last thing before anything reaches a firewall."""
    try:
        result = _review(enclave)
    except GenerationRefused as exc:
        return _range_page(request, estate_path(), [("err", f"Refusing to generate: {exc}")])
    if result is None:
        return render(
            request, "index.html", declared=False, messages=[("err", f"no enclave {enclave}")]
        )
    _firewall, _ruleset, findings, gate, diff = result
    return render(
        request,
        "review.html",
        slug=estate_path().stem,
        enclave=enclave,
        gate=gate,
        keys=[Gate.key(f) for f in gate.warnings],
        info=[f for f in findings if f.severity is Severity.INFO],
        diff=diff,
    )


@router.post("/range/review/{enclave}/acknowledge")
def acknowledge(enclave: str, key: str = Form(...)) -> RedirectResponse:
    """One finding, one decision. There is no accept-all endpoint, deliberately."""
    _ACKNOWLEDGED.setdefault(enclave, set()).add(key)
    return RedirectResponse(f"/range/review/{enclave}", status_code=303)


@router.post("/range/review/{enclave}/export")
def export(enclave: str) -> Any:
    """Export is refused unless the gate opens. Checked here, not only in the template."""
    from fastapi.responses import PlainTextResponse

    try:
        result = _review(enclave)
    except GenerationRefused as exc:
        # A refusal is a decision, not a crash. It must read as one at every entry
        # point, or an operator sees a 500 and assumes the tool is broken rather than
        # that their policy is incomplete.
        return PlainTextResponse(f"Refusing to generate: {exc}", status_code=409)
    if result is None:
        return RedirectResponse("/range", status_code=303)
    _firewall, ruleset, _findings, gate, _diff = result
    if not gate.may_export:
        return PlainTextResponse(f"Export refused. {gate.reason}", status_code=409)
    return PlainTextResponse(checklist(ruleset, team=str(load_estate(estate_path()).team)))


@router.get("/range/monitor", response_class=HTMLResponse)
def monitor_dashboard(request: Request) -> HTMLResponse:
    """The topology with status painted on it — `BUILD-PLAN.md` 5.4.

    Not a second dashboard. The operator already reads this picture, and a host that
    stops answering should change on the picture they are already looking at.
    """
    from btht.app.monitor.store import Store

    path = estate_path()
    estate = load_estate(path)
    catalogue = load_services(SERVICE_CATALOGUE)
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

    params = request.query_params
    view = View(open_ids=frozenset(params.getlist("open")), focus_id=params.get("focus", ""))
    diagram = layout(estate, view, slug=path.stem, catalogue=catalogue, status=status)
    return render(
        request,
        "monitor.html",
        slug=path.stem,
        estate=estate,
        view=view,
        diagram=diagram,
        svg=render_svg(diagram),
        open_ids=sorted(view.open_ids),
        host_types=sorted(catalogue.host_types),
        services=sorted(catalogue.services),
        open_all_links={f.enclave: view.open_all_link(f, path.stem) for f in estate.firewalls},
        polled=bool(status),
        worklist=worklist,
    )


# ===========================================================================
#  Editing what has already been declared — Phase 9.6
# ===========================================================================
#
# Every add form has a matching edit and delete. The tool is used the night before a
# range opens, and an add-only interface means a typo is fixed by hand-editing YAML
# under time pressure — which is how the second mistake gets made.


def _ports_from(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in _split(text) if p.isdigit())


def _save(estate: Estate, path: Path) -> None:
    save_estate(estate, path, convention_of(path).enclave_tokens, side_rules_of(path))


def _back(message: str = "", kind: str = "ok", where: str = "") -> RedirectResponse:
    parts = [where] if where else []
    if message:
        parts.append(f"m={message}&k={kind}")
    suffix = "?" + "&".join(parts) if parts else ""
    return RedirectResponse(f"/range{suffix}", status_code=303)


@router.get("/range/edit/interface/{enclave}/{ifname}", response_class=HTMLResponse)
def edit_interface_form(request: Request, enclave: str, ifname: str) -> HTMLResponse:
    path = estate_path()
    estate = load_estate(path)
    firewall = estate.firewall(enclave)
    interface = (
        next((i for i in firewall.interfaces if i.ifname == ifname), None) if firewall else None
    )
    if interface is None:
        return _range_page(request, path, [("err", f"no interface {ifname}")])
    return render(
        request,
        "edit.html",
        slug=path.stem,
        title=f"{enclave} · interface {ifname}",
        action=f"/range/edit/interface/{enclave}/{ifname}",
        delete_action=f"/range/delete/interface/{enclave}/{ifname}",
        delete_warning="Refused while hosts still sit on this segment.",
        fields=[
            {
                "name": "ifname",
                "label": "ifname (what pfSense calls it)",
                "value": interface.ifname,
            },
            {"name": "role", "label": "segment role (what you call it)", "value": interface.role},
            {"name": "v4", "label": "IPv4 with prefix", "value": str(interface.v4 or "")},
            {"name": "v6", "label": "IPv6 with prefix", "value": str(interface.v6 or "")},
            {"name": "descr", "label": "description", "value": interface.descr},
            {
                "name": "upstreams",
                "label": "connects to, comma separated",
                "value": ", ".join(interface.upstreams),
                "hint": "Declared devices this interface peers with — usually the "
                "routers a WAN talks to. Declared: "
                + (", ".join(sorted(n.name for n in load_estate(path).nodes)) or "none yet"),
            },
        ],
    )


@router.post("/range/edit/interface/{enclave}/{ifname}")
def edit_interface(
    enclave: str,
    ifname: str,
    new_ifname: str = Form("", alias="ifname"),
    role: str = Form(""),
    v4: str = Form(""),
    v6: str = Form(""),
    descr: str = Form(""),
    upstreams: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
    renamed = new_ifname.strip() or ifname
    changes: dict[str, object] = {
        "role": role.strip(),
        "v4": parse_address(v4),
        "v6": parse_address(v6),
        "descr": descr.strip(),
        "is_lan": renamed == "lan",
        "upstreams": _split(upstreams),
    }
    if renamed != ifname:
        changes["ifname"] = renamed
    estate = update_interface(load_estate(path), enclave, ifname, **changes)
    _save(estate, path)
    return _back(f"interface {ifname} updated")


@router.post("/range/delete/interface/{enclave}/{ifname}")
def delete_interface(enclave: str, ifname: str) -> RedirectResponse:
    path = estate_path()
    try:
        _save(remove_interface(load_estate(path), enclave, ifname), path)
    except InUse as exc:
        return _back(str(exc), "err")
    return _back(f"interface {ifname} removed")


@router.get("/range/edit/host/{enclave}/{hostname}", response_class=HTMLResponse)
def edit_host_form(request: Request, enclave: str, hostname: str) -> HTMLResponse:
    path = estate_path()
    estate = load_estate(path)
    firewall = estate.firewall(enclave)
    host = next((h for h in firewall.hosts if h.hostname == hostname), None) if firewall else None
    if host is None:
        return _range_page(request, path, [("err", f"no host {hostname}")])
    catalogue = load_services(SERVICE_CATALOGUE)
    return render(
        request,
        "edit.html",
        slug=path.stem,
        title=f"{enclave} · host {hostname}",
        action=f"/range/edit/host/{enclave}/{hostname}",
        delete_action=f"/range/delete/host/{enclave}/{hostname}",
        fields=[
            {"name": "hostname", "label": "hostname", "value": host.hostname},
            {"name": "os", "label": "operating system", "value": host.os},
            {"name": "v4", "label": "IPv4", "value": str(host.v4 or "")},
            {"name": "v6", "label": "IPv6", "value": str(host.v6 or "")},
            {"name": "segment_role", "label": "segment", "value": host.segment_role},
            {
                "name": "service_role",
                "label": "host type",
                "value": host.service_role,
                "options": sorted(catalogue.host_types),
            },
            {
                "name": "services",
                "label": "services it runs, comma separated",
                "value": ", ".join(host.services),
                "hint": "known: " + ", ".join(sorted(catalogue.services)[:12]) + "…",
            },
            {
                "name": "out_of_bounds",
                "label": "out of bounds",
                "value": "yes" if host.out_of_bounds else "",
                "options": ["", "yes"],
                "hint": "Out-of-bounds hosts must keep working and are never policy targets.",
            },
        ],
    )


@router.post("/range/edit/host/{enclave}/{hostname}")
def edit_host(
    enclave: str,
    hostname: str,
    new_hostname: str = Form("", alias="hostname"),
    os: str = Form(""),
    v4: str = Form(""),
    v6: str = Form(""),
    segment_role: str = Form(""),
    service_role: str = Form(""),
    services: str = Form(""),
    out_of_bounds: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
    renamed = new_hostname.strip() or hostname
    changes: dict[str, object] = {
        "os": os.strip(),
        "v4": parse_address(v4),
        "v6": parse_address(v6),
        "segment_role": segment_role.strip(),
        "service_role": service_role.strip(),
        "services": _split(services),
        "out_of_bounds": out_of_bounds == "yes",
    }
    if renamed != hostname:
        changes["hostname"] = renamed
    estate = update_host(load_estate(path), enclave, hostname, **changes)
    _save(estate, path)
    return _back(f"host {hostname} updated")


@router.post("/range/delete/host/{enclave}/{hostname}")
def delete_host(enclave: str, hostname: str) -> RedirectResponse:
    path = estate_path()
    _save(remove_host(load_estate(path), enclave, hostname), path)
    return _back(f"host {hostname} removed")


@router.get("/range/edit/group/{enclave}/{prefix}", response_class=HTMLResponse)
def edit_group_form(request: Request, enclave: str, prefix: str) -> HTMLResponse:
    path = estate_path()
    estate = load_estate(path)
    firewall = estate.firewall(enclave)
    group = (
        next((g for g in firewall.host_groups if g.name_prefix == prefix), None)
        if firewall
        else None
    )
    if group is None:
        return _range_page(request, path, [("err", f"no group {prefix}")])
    catalogue = load_services(SERVICE_CATALOGUE)
    return render(
        request,
        "edit.html",
        slug=path.stem,
        title=f"{enclave} · group {prefix} ({group.count} hosts)",
        action=f"/range/edit/group/{enclave}/{prefix}",
        delete_action=f"/range/delete/group/{enclave}/{prefix}",
        delete_warning=f"This removes all {group.count} machines in the group.",
        fields=[
            {"name": "name_prefix", "label": "name prefix", "value": group.name_prefix},
            {"name": "count", "label": "how many", "value": str(group.count)},
            {"name": "first_index", "label": "first number", "value": str(group.first_index)},
            {
                "name": "index_width",
                "label": "digits in the number",
                "value": str(group.index_width),
            },
            {"name": "os", "label": "operating system", "value": group.os},
            {
                "name": "host_type",
                "label": "host type",
                "value": group.host_type,
                "options": sorted(catalogue.host_types),
            },
            {"name": "segment_role", "label": "segment", "value": group.segment_role},
            {"name": "v4_start", "label": "first IPv4", "value": str(group.v4_start or "")},
            {"name": "v6_start", "label": "first IPv6", "value": str(group.v6_start or "")},
            {
                "name": "services",
                "label": "services (blank uses the host type's)",
                "value": ", ".join(group.services),
            },
        ],
    )


@router.post("/range/edit/group/{enclave}/{prefix}")
def edit_group(
    enclave: str,
    prefix: str,
    name_prefix: str = Form(""),
    count: int = Form(1),
    first_index: int = Form(1),
    index_width: int = Form(2),
    os: str = Form(""),
    host_type: str = Form(""),
    segment_role: str = Form(""),
    v4_start: str = Form(""),
    v6_start: str = Form(""),
    services: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
    try:
        estate = update_host_group(
            load_estate(path),
            enclave,
            prefix,
            name_prefix=name_prefix.strip() or prefix,
            count=count,
            first_index=first_index,
            index_width=index_width,
            os=os.strip(),
            host_type=host_type.strip(),
            segment_role=segment_role.strip(),
            v4_start=parse_address(v4_start),
            v6_start=parse_address(v6_start),
            services=_split(services),
        )
    except ValueError as exc:
        return _back(str(exc), "err")
    _save(estate, path)
    return _back(f"group {prefix} updated")


@router.post("/range/delete/group/{enclave}/{prefix}")
def delete_group(enclave: str, prefix: str) -> RedirectResponse:
    path = estate_path()
    _save(remove_host_group(load_estate(path), enclave, prefix), path)
    return _back(f"group {prefix} and its machines removed")


@router.get("/range/edit/enclave/{enclave}", response_class=HTMLResponse)
def edit_enclave_form(request: Request, enclave: str) -> HTMLResponse:
    path = estate_path()
    firewall = load_estate(path).firewall(enclave)
    if firewall is None:
        return _range_page(request, path, [("err", f"no enclave {enclave}")])
    return render(
        request,
        "edit.html",
        slug=path.stem,
        title=f"enclave {enclave}",
        action=f"/range/edit/enclave/{enclave}",
        delete_action=f"/range/delete/enclave/{enclave}",
        delete_warning="Refused while a declared path still names this enclave.",
        fields=[
            {"name": "enclave", "label": "enclave name", "value": firewall.enclave},
            {"name": "fqdn", "label": "firewall FQDN", "value": firewall.fqdn},
            {"name": "side", "label": "side label", "value": firewall.side},
            {
                "name": "mgmt_address",
                "label": "management address",
                "value": str(firewall.node.mgmt_address),
            },
            {
                "name": "gui_url",
                "label": "management GUI URL",
                "value": firewall.node.gui_url,
                "hint": "Blank means no GUI link is offered. A link that does not answer is "
                "worse than none.",
            },
            {"name": "ssh_user", "label": "your SSH username", "value": firewall.node.ssh_user},
            {
                "name": "credential_ref",
                "label": "credential name (never the credential)",
                "value": firewall.node.credential_ref,
            },
        ],
    )


@router.post("/range/edit/enclave/{enclave}")
def edit_enclave(
    enclave: str,
    new_enclave: str = Form("", alias="enclave"),
    fqdn: str = Form(""),
    side: str = Form(""),
    mgmt_address: str = Form(""),
    gui_url: str = Form(""),
    ssh_user: str = Form(""),
    credential_ref: str = Form(""),
) -> RedirectResponse:
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    firewall = estate.firewall(enclave)
    if firewall is None:
        return _back(f"no enclave {enclave}", "err")
    node = dc_replace(
        firewall.node,
        mgmt_address=parse_address(mgmt_address) or firewall.node.mgmt_address,
        gui_url=gui_url.strip(),
        ssh_user=ssh_user.strip(),
        credential_ref=credential_ref.strip(),
        enclave=new_enclave.strip() or enclave,
    )
    changes: dict[str, object] = {
        "fqdn": fqdn.strip(),
        "side": side.strip(),
        "node": node,
    }
    renamed = new_enclave.strip()
    if renamed and renamed != enclave:
        changes["enclave"] = renamed
    estate = update_firewall(estate, enclave, **changes)
    _save(estate, path)
    return _back(f"enclave {enclave} updated")


@router.post("/range/delete/enclave/{enclave}")
def delete_enclave(enclave: str) -> RedirectResponse:
    path = estate_path()
    try:
        _save(remove_firewall(load_estate(path), enclave, load_policy(path)), path)
    except InUse as exc:
        return _back(str(exc), "err")
    return _back(f"enclave {enclave} removed")


# ===========================================================================
#  The catalogue — Phase 9.5
# ===========================================================================


def _any_estate() -> Estate:
    """Reference checking needs an estate; use whichever ones exist.

    Removing a service is refused when something uses it, and "something" spans every
    estate on this install rather than only the one being looked at.
    """
    from dataclasses import replace as dc_replace

    combined = Estate(team=0)
    if not ESTATES.is_dir():
        return combined
    firewalls: list[Firewall] = []
    for path in sorted(ESTATES.glob("*.yaml")):
        try:
            firewalls.extend(load_estate(path).firewalls)
        except (EstateFileError, ValueError):
            continue
    return dc_replace(combined, firewalls=tuple(firewalls))


@router.get("/services", response_class=HTMLResponse)
def services_page(request: Request) -> HTMLResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    return render(
        request,
        "services.html",
        services=[catalogue.services[n] for n in sorted(catalogue.services)],
        host_types=[catalogue.host_types[n] for n in sorted(catalogue.host_types)],
        service_names=sorted(catalogue.services),
        messages=(
            [(request.query_params.get("k", "ok"), request.query_params["m"])]
            if request.query_params.get("m")
            else []
        ),
    )


def _services_back(message: str = "", kind: str = "ok") -> RedirectResponse:
    suffix = f"?m={message}&k={kind}" if message else ""
    return RedirectResponse(f"/services{suffix}", status_code=303)


@router.post("/services/new")
def add_catalogue_service(
    name: str = Form(...),
    tcp: str = Form(""),
    udp: str = Form(""),
    confidence: str = Form("standard"),
    descr: str = Form(""),
    note: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    service = Service(
        name=name.strip(),
        tcp=_ports_from(tcp),
        udp=_ports_from(udp),
        descr=descr.strip(),
        confidence=Confidence(confidence),
        note=note.strip(),
        custom=True,
    )
    save_services(update_service(catalogue, service), SERVICE_CATALOGUE)
    return _services_back(f"{service.name} added")


@router.get("/services/edit/{name}", response_class=HTMLResponse)
def edit_service_form(request: Request, name: str) -> HTMLResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    service = catalogue.services.get(name)
    if service is None:
        return _services_page_error(request, f"no service {name}")
    return render(
        request,
        "edit.html",
        slug="",
        title=f"service {name}",
        action=f"/services/edit/{name}",
        delete_action=f"/services/delete/{name}",
        delete_warning="Refused while any host or host type still runs it.",
        fields=[
            {
                "name": "name",
                "label": "name",
                "value": service.name,
                "hint": "Renaming carries every host and host type that runs it.",
            },
            {"name": "tcp", "label": "tcp ports", "value": ", ".join(str(p) for p in service.tcp)},
            {"name": "udp", "label": "udp ports", "value": ", ".join(str(p) for p in service.udp)},
            {"name": "tcp_dynamic", "label": "tcp range", "value": service.tcp_dynamic},
            {
                "name": "confidence",
                "label": "confidence",
                "value": service.confidence.value,
                "options": ["standard", "assumed", "unverified"],
            },
            {"name": "descr", "label": "description", "value": service.descr},
            {"name": "note", "label": "note", "value": service.note},
        ],
    )


def _services_page_error(request: Request, message: str) -> HTMLResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    return render(
        request,
        "services.html",
        services=[catalogue.services[n] for n in sorted(catalogue.services)],
        host_types=[catalogue.host_types[n] for n in sorted(catalogue.host_types)],
        service_names=sorted(catalogue.services),
        messages=[("err", message)],
    )


@router.post("/services/edit/{name}")
def edit_service(
    name: str,
    new_name: str = Form("", alias="name"),
    tcp: str = Form(""),
    udp: str = Form(""),
    tcp_dynamic: str = Form(""),
    confidence: str = Form("standard"),
    descr: str = Form(""),
    note: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    estate = _any_estate()
    renamed = new_name.strip() or name

    if renamed != name:
        catalogue, _estate, outcome = rename_service(catalogue, estate, name, renamed)
        message = outcome.summary
    else:
        message = f"{name} updated"

    service = catalogue.services[renamed]
    updated = Service(
        name=renamed,
        tcp=_ports_from(tcp),
        udp=_ports_from(udp),
        tcp_dynamic=tcp_dynamic.strip(),
        descr=descr.strip(),
        confidence=Confidence(confidence),
        note=note.strip(),
        custom=service.custom,
    )
    save_services(update_service(catalogue, updated), SERVICE_CATALOGUE)
    return _services_back(message)


@router.post("/services/delete/{name}")
def delete_service(name: str) -> RedirectResponse:
    try:
        reduced = remove_service(load_services(SERVICE_CATALOGUE), _any_estate(), name)
    except InUse as exc:
        return _services_back(str(exc), "err")
    save_services(reduced, SERVICE_CATALOGUE)
    return _services_back(f"{name} removed")


@router.post("/services/types/new")
def add_host_type(
    name: str = Form(...),
    default_os: str = Form(""),
    services: str = Form(""),
    descr: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    host_type = HostType(
        name=name.strip(),
        services=_split(services),
        default_os=default_os.strip(),
        descr=descr.strip(),
        custom=True,
    )
    unknown = [s for s in host_type.services if s not in catalogue.services]
    if unknown:
        return _services_back(
            "these services are not defined yet: "
            + ", ".join(unknown)
            + ". Add them first, or the type promises ports the tool cannot open.",
            "err",
        )
    save_services(update_host_type(catalogue, host_type), SERVICE_CATALOGUE)
    return _services_back(f"{host_type.name} added")


@router.get("/services/types/edit/{name}", response_class=HTMLResponse)
def edit_host_type_form(request: Request, name: str) -> HTMLResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    host_type = catalogue.host_types.get(name)
    if host_type is None:
        return _services_page_error(request, f"no host type {name}")
    return render(
        request,
        "edit.html",
        slug="",
        title=f"host type {name}",
        action=f"/services/types/edit/{name}",
        delete_action=f"/services/types/delete/{name}",
        delete_warning="Refused while any host or group still uses it.",
        fields=[
            {"name": "name", "label": "name", "value": host_type.name},
            {
                "name": "default_os",
                "label": "default operating system",
                "value": host_type.default_os,
            },
            {
                "name": "services",
                "label": "services",
                "value": ", ".join(host_type.services),
                "hint": "known: " + ", ".join(sorted(catalogue.services)),
            },
            {"name": "descr", "label": "description", "value": host_type.descr},
        ],
    )


@router.post("/services/types/edit/{name}")
def edit_host_type(
    name: str,
    new_name: str = Form("", alias="name"),
    default_os: str = Form(""),
    services: str = Form(""),
    descr: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    existing = catalogue.host_types.get(name)
    host_type = HostType(
        name=new_name.strip() or name,
        services=_split(services),
        default_os=default_os.strip(),
        descr=descr.strip(),
        custom=existing.custom if existing else True,
    )
    updated = update_host_type(catalogue, host_type)
    if host_type.name != name:
        updated = Catalogue(
            services=updated.services,
            host_types={k: v for k, v in updated.host_types.items() if k != name},
            hostname_patterns=updated.hostname_patterns,
        )
    save_services(updated, SERVICE_CATALOGUE)
    return _services_back(f"{name} updated")


@router.post("/services/types/delete/{name}")
def delete_host_type(name: str) -> RedirectResponse:
    try:
        reduced = remove_host_type(load_services(SERVICE_CATALOGUE), _any_estate(), name)
    except InUse as exc:
        return _services_back(str(exc), "err")
    save_services(reduced, SERVICE_CATALOGUE)
    return _services_back(f"{name} removed")


@router.get("/range/settings", response_class=HTMLResponse)
def range_settings_form(request: Request) -> HTMLResponse:
    path = estate_path()
    return render(
        request,
        "settings.html",
        estate=load_estate(path),
        enclave_tokens=convention_of(path).enclave_tokens,
    )


@router.post("/range/settings")
def save_range_settings(
    team: int = Form(0),
    team_name: str = Form(""),
    team_padded: str = Form(""),
    vocabulary: str = Form(""),
    tokens: str = Form(""),
) -> RedirectResponse:
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = dc_replace(
        load_estate(path),
        team=team,
        team_name=team_name.strip(),
        team_padded=team_padded.strip(),
        role_vocabulary=_split(vocabulary),
    )
    save_estate(estate, path, enclave_tokens=_split(tokens), sides=side_rules_of(path))
    return _back("range settings saved")


@router.post("/range/enclaves/{enclave}/hosts")
def add_host(
    enclave: str,
    hostname: str = Form(...),
    os: str = Form(""),
    v4: str = Form(""),
    v6: str = Form(""),
    segment_role: str = Form(""),
    host_type: str = Form(""),
    services: str = Form(""),
    out_of_bounds: str = Form(""),
    ifname: str = Form(""),
) -> RedirectResponse:
    """One machine, typed in. The paste accelerator is not the only way to add a host."""
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    catalogue = load_services(SERVICE_CATALOGUE)
    chosen = _split(services)
    if not chosen and host_type:
        host_type_entry = catalogue.host_types.get(host_type)
        chosen = tuple(host_type_entry.services) if host_type_entry else ()

    host = Host(
        hostname=hostname.strip(),
        os=os.strip(),
        v4=parse_address(v4),
        v6=parse_address(v6),
        segment_role=segment_role.strip(),
        service_role=host_type.strip(),
        services=chosen,
        out_of_bounds=out_of_bounds == "yes",
        source_of_truth=SourceOfTruth.WIZARD,
    )
    estate = dc_replace(
        estate,
        firewalls=tuple(
            dc_replace(f, hosts=(*f.hosts, host)) if f.enclave == enclave else f
            for f in estate.firewalls
        ),
    )
    _save(estate, path)
    return _back(f"{host.hostname} added", where=f"enclave={enclave}&interface={ifname}")


@router.post("/range/enclaves/{enclave}/groups")
def add_group(
    enclave: str,
    name_prefix: str = Form(...),
    count: int = Form(1),
    first_index: int = Form(1),
    index_width: int = Form(2),
    os: str = Form(""),
    host_type: str = Form(""),
    segment_role: str = Form(""),
    v4_start: str = Form(""),
    v6_prefix: str = Form(""),
    ifname: str = Form(""),
) -> RedirectResponse:
    """Many machines of one kind. Ten workstations is one declaration, not ten."""
    from dataclasses import replace as dc_replace

    path = estate_path()
    try:
        group = HostGroup(
            name_prefix=name_prefix.strip(),
            count=count,
            first_index=first_index,
            index_width=index_width,
            os=os.strip(),
            host_type=host_type.strip(),
            segment_role=segment_role.strip(),
            v4_start=parse_address(v4_start),
            v6_prefix=v6_prefix.strip(),
        )
    except ValueError as exc:
        return _back(str(exc), "err", where=f"enclave={enclave}&interface={ifname}")

    estate = load_estate(path)
    estate = dc_replace(
        estate,
        firewalls=tuple(
            dc_replace(f, host_groups=(*f.host_groups, group)) if f.enclave == enclave else f
            for f in estate.firewalls
        ),
    )
    _save(estate, path)
    return _back(
        f"{group.count} × {group.name_prefix} added",
        where=f"enclave={enclave}&interface={ifname}",
    )


@router.post("/range/devices")
def add_device(
    name: str = Form(...),
    platform: str = Form("frr"),
    mgmt_address: str = Form(...),
    ssh_user: str = Form(""),
    gui_url: str = Form(""),
    credential_ref: str = Form(""),
    poll_seconds: int = Form(60),
) -> RedirectResponse:
    """A router, or anything else on the range that is not a firewall.

    They exist in their own right: the monitor polls them, and an interface can say it
    peers with them.
    """
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    try:
        node = Node(
            name=name.strip(),
            platform=Platform(platform),
            mgmt_address=parse_address(mgmt_address),
            ssh_user=ssh_user.strip(),
            gui_url=gui_url.strip(),
            credential_ref=credential_ref.strip(),
            poll_seconds=poll_seconds,
        )
    except ValueError as exc:
        return _back(str(exc), "err", where="devices=1")
    _save(dc_replace(estate, nodes=(*estate.nodes, node)), path)
    return _back(f"{node.name} added", where="devices=1")


@router.post("/range/devices/{name}/delete")
def delete_device(name: str) -> RedirectResponse:
    """Refused while an interface still says it peers with this device."""
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    peers = [
        f"{f.enclave}/{i.ifname}"
        for f in estate.firewalls
        for i in f.interfaces
        if name in i.upstreams
    ]
    if peers:
        return _back(
            f"{name} is still connected to " + ", ".join(peers) + ". Clear those first.",
            "err",
            where="devices=1",
        )
    _save(dc_replace(estate, nodes=tuple(n for n in estate.nodes if n.name != name)), path)
    return _back(f"{name} removed", where="devices=1")
