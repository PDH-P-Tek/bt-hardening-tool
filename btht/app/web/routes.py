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

from btht.app.data import ESTATES, ISA_CHECKS, SEGMENT_TYPES, SERVICE_CATALOGUE
from btht.app.generate.diff import Gate, diff_rulesets, gate_for
from btht.app.generate.emit import checklist, rule_row
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
    BadAddress,
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
from btht.app.model.segments import (
    SegmentType,
    load_segment_types,
    save_segment_types,
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
from btht.app.web import forms, guide, progress
from btht.app.web.topology import View, layout, render_svg

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()


#: A team has one range. There is no list to choose from, no second estate to confuse
#: it with, and no slug in any URL — the front page *is* the range.
RANGE_FILE = "range.yaml"

#: The monitor's collected state. Working data — gitignored, rebuildable from the boxes.
MONITOR_DB = ESTATES / "monitor.db"


def estate_path(_slug: str = "") -> Path:
    """The one range file. The argument is ignored and kept only so callers read the same."""
    return ESTATES / RANGE_FILE


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def render(request: Request, template: str, **context: Any) -> HTMLResponse:
    context.setdefault("messages", [])
    # Named `journey` rather than `steps`: the policy wizard puts its own per-segment
    # steps in the context, and a collision there silently fed interfaces to the guide.
    journey = _guide_steps()
    context["journey"] = journey
    context["next_step"] = guide.next_step(journey)
    context.setdefault("unreviewed", _unreviewed_count())
    return TEMPLATES.TemplateResponse(request, template, context)


def _guide_steps() -> tuple[guide.Step, ...]:
    """Where the operator is, worked out from the estate rather than remembered.

    Deliberately tolerant: this decorates every page, so a half-written estate or an
    absent monitor database must degrade to "you are near the start", never to a 500
    on a page that would otherwise have rendered.
    """
    path = estate_path()
    if not path.exists():
        return guide.plan(None)
    try:
        estate = load_estate(path)
        policy = load_policy(path)
    except (EstateFileError, OSError):
        return guide.plan(None)
    state = progress.load(path)
    return guide.plan(
        estate,
        policy,
        reviewed=frozenset(state.signed_off),
        baselined=_baselined_nodes(),
        unreviewed_items=_unreviewed_count(),
    )


def _baselined_nodes() -> frozenset[str]:
    """Which boxes the monitor already holds a baseline for."""
    from btht.app.monitor.store import Store

    if not MONITOR_DB.exists():
        return frozenset()
    try:
        store = Store(MONITOR_DB)
    except Exception:  # pragma: no cover - a corrupt scratch DB must not break the UI
        return frozenset()
    try:
        return frozenset(str(row["host"]) for row in store.heartbeats())
    finally:
        store.close()


def _unreviewed_count() -> int:
    from btht.app.monitor.store import Store

    if not MONITOR_DB.exists():
        return 0
    try:
        store = Store(MONITOR_DB)
    except Exception:  # pragma: no cover
        return 0
    try:
        return sum(1 for row in store.worklist())
    finally:
        store.close()


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
    showing_routers = params.get("routers") == "1"

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
        showing_routers=showing_routers,
        routers=sorted(estate.nodes, key=lambda n: n.name),
        firewall=firewall,
        interface=interface,
        hosts=hosts,
        groups=groups,
        host_types=sorted(catalogue.host_types),
        service_names=sorted(catalogue.services),
        enclave_tokens=convention_of(path).enclave_tokens,
        # Field lists come from one place, so the pop-out that adds a thing and the
        # pop-out that edits it can never drift apart.
        new_enclave_fields=forms.enclave_fields([p.value for p in Platform]),
        new_router_fields=forms.router_fields(),
        new_interface_fields=forms.interface_fields(estate),
        new_host_fields=forms.host_fields(catalogue, segment=interface.role if interface else ""),
        new_group_fields=forms.group_fields(catalogue, segment=interface.role if interface else ""),
        edit_interface_fields={
            i.ifname: forms.interface_fields(estate, i)
            for i in (firewall.interfaces if firewall else ())
        },
        edit_host_fields={h.hostname: forms.host_fields(catalogue, h) for h in hosts},
        edit_group_fields={g.name_prefix: forms.group_fields(catalogue, g) for g in groups},
        edit_router_fields={n.name: forms.router_fields(n) for n in estate.nodes},
        edit_enclave_fields=forms.enclave_fields([], firewall) if firewall else [],
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
    declared = _split(vocabulary) or tuple(sorted(load_segment_types(SEGMENT_TYPES)))
    estate = Estate(
        team=team,
        team_name=team_name.strip(),
        team_padded=team_padded.strip(),
        role_vocabulary=declared,
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
    display_name: str = Form(""),
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
    firewall = Firewall(
        enclave=name.strip(),
        display_name=display_name.strip(),
        fqdn=fqdn.strip(),
        node=node,
    )
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
    estate = load_estate(path)
    if role.strip() and not estate.knows_role(role.strip()):
        return _back(
            f"{role.strip()!r} is not one of this range's segment types. Add it in "
            "range settings first, so the same segment is not spelled two ways.",
            "err",
            where=f"enclave={enclave}&interface=__new",
        )
    try:
        addresses = _addresses(v4=v4, v6=v6)
    except BadAddress as exc:
        return _back(str(exc), "err", where=f"enclave={enclave}&interface=__new")

    interface = Interface(
        ifname=ifname.strip(),
        role=role.strip(),
        descr=descr.strip(),
        v4=addresses["v4"],
        v6=addresses["v6"],
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


#: Acknowledgements are per estate, per enclave, and now persist — see `web/progress.py`.
#: Holding them in memory meant a restart threw away every decision a person had made
#: and re-closed the export gate, which during an exercise is a real loss of work.


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
    acknowledged = progress.load(path).keys_for(enclave)
    return (
        firewall,
        ruleset,
        findings,
        gate_for(findings, acknowledged),
        diff_rulesets(firewall.rules, ruleset),
    )


@router.get("/rules", response_class=HTMLResponse)
def rules_hub(request: Request) -> HTMLResponse:
    """Where the ruleset gets read and agreed, enclave by enclave.

    One card per firewall saying the only three things that decide what to do next:
    whether a policy has been declared, whether it generates, and whether a person has
    signed the result off.
    """
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    estate = load_estate(path)
    policy = load_policy(path)
    state = progress.load(path)

    cards = []
    for firewall in estate.firewalls:
        entry = policy.for_enclave(firewall.enclave)
        card: dict[str, Any] = {
            "enclave": firewall.enclave,
            "display_name": firewall.display_name or firewall.enclave,
            "has_policy": entry is not None,
            "services": len(entry.services) if entry else 0,
            "signed_off": firewall.enclave in state.signed_off,
            "refused": "",
            "blocking": 0,
            "outstanding": 0,
            "rules": 0,
        }
        if entry is not None:
            try:
                result = _review(firewall.enclave)
            except GenerationRefused as exc:
                card["refused"] = str(exc)
            else:
                if result is not None:
                    _fw, ruleset, _findings, gate, _diff = result
                    card["rules"] = len(ruleset.all_rules())
                    card["blocking"] = len(gate.blocking)
                    card["outstanding"] = len(gate.unacknowledged)
        cards.append(card)
    return render(request, "rules.html", estate=estate, cards=cards)


@router.get("/rules/{enclave}", response_class=HTMLResponse)
def review(request: Request, enclave: str) -> HTMLResponse:
    """The ruleset, as a person reads it — `SPEC.md` §9, `CLAUDE.md`.

    The rules are the page. Someone has to be able to look down this list and say "yes,
    that looks correct", so it is rendered in entry order, tab by tab, one line of plain
    English per rule, with the findings that argue against it in front of them. The
    gate and the export come after, because they are the consequence of that reading
    rather than the point of the page.
    """
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    try:
        result = _review(enclave)
    except GenerationRefused as exc:
        return render(
            request,
            "rules_review.html",
            enclave=enclave,
            refused=str(exc),
            estate=load_estate(path),
        )
    if result is None:
        return _range_page(request, path, [("err", f"no enclave {enclave}")])
    firewall, ruleset, findings, gate, diff = result
    state = progress.load(path)

    # Entry order is part of the ruleset — the same rule in a different place is a
    # different ruleset — so the page is built as the tabs are typed, not regrouped.
    tabs: list[dict[str, Any]] = []
    if ruleset.floating:
        tabs.append({"name": "Floating", "blocks": _blocks(ruleset.floating)})
    if ruleset.wan:
        tabs.append({"name": "WAN", "blocks": _blocks(ruleset.wan)})
    for ifname, rules in ruleset.per_interface:
        tabs.append({"name": ifname, "blocks": _blocks(rules)})

    return render(
        request,
        "rules_review.html",
        enclave=enclave,
        refused="",
        estate=load_estate(path),
        firewall=firewall,
        ruleset=ruleset,
        tabs=tabs,
        rule_count=len(ruleset.all_rules()),
        gate=gate,
        keys=[Gate.key(f) for f in gate.warnings],
        info=[f for f in findings if f.severity is Severity.INFO],
        diff=diff,
        signed_off=enclave in state.signed_off,
    )


def _blocks(rules: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Consecutive runs of one ordering block, kept in the order they are entered."""
    out: list[dict[str, Any]] = []
    for generated in rules:
        if not out or out[-1]["name"] != generated.block:
            out.append({"name": generated.block, "rules": []})
        out[-1]["rules"].append({"generated": generated, "row": rule_row(generated)})
    return out


@router.post("/rules/{enclave}/acknowledge")
def acknowledge(enclave: str, key: str = Form(...)) -> RedirectResponse:
    """One finding, one decision. There is no accept-all endpoint, deliberately."""
    path = estate_path()
    state = progress.load(path)
    state.acknowledge(enclave, key)
    progress.save(state, path)
    return RedirectResponse(f"/rules/{enclave}", status_code=303)


@router.post("/rules/{enclave}/sign-off")
def sign_off(enclave: str) -> RedirectResponse:
    """A person says these rules are right. Recorded, because the next step depends on it."""
    path = estate_path()
    state = progress.load(path)
    state.sign_off(enclave)
    progress.save(state, path)
    return RedirectResponse(f"/rules/{enclave}", status_code=303)


@router.post("/rules/{enclave}/export")
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


# ===========================================================================
#  The monitor — `MONITORING.md` §8.2
# ===========================================================================
#
# Three levels, and the shape of them is the product. **Estate**: one tile per host,
# coloured by the worst thing outstanding on it, with a single number dominating the
# page. **Host**: what is outstanding there, grouped, worst first. **Item**: the actual
# change in the platform's own syntax, who was on the box when it happened, and three
# decisions. Nothing here can write to a managed box.


def _store() -> Any:
    from btht.app.monitor.store import Store

    MONITOR_DB.parent.mkdir(parents=True, exist_ok=True)
    return Store(MONITOR_DB)


def _sessions_for(store: Any, host: str) -> tuple[Any, ...]:
    """Every login the collector has seen on one box, newest first."""
    import json

    from btht.app.monitor.sessions import Session

    out = []
    for row in store.items(host):
        if str(row["collector"]) != "M-SESS-01":
            continue
        try:
            out.append(Session(**json.loads(str(row["current_value"]))))
        except (json.JSONDecodeError, TypeError):
            continue
    return tuple(sorted(out, key=lambda s: s.started, reverse=True))


def _key_inventory(store: Any, host: str) -> frozenset[str]:
    """The key fingerprints `M-AUTH-01` has seen on this box."""
    prints = set()
    for row in store.items(host):
        if str(row["collector"]) != "M-AUTH-01":
            continue
        for word in str(row["current_value"]).split():
            if word.startswith("SHA256:"):
                prints.add(word)
    return frozenset(prints)


@router.get("/monitor", response_class=HTMLResponse)
def monitor_estate(request: Request) -> HTMLResponse:
    """The estate view. One number dominates it: total unreviewed. Zero means stop looking."""
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    estate = load_estate(path)

    store = _store()
    try:
        summary = [dict(row) for row in store.host_summary()]
        total = store.unreviewed_count()
        marker = store.last_look()
        since = [dict(row) for row in store.changed_since(marker)]
        flagged = [dict(row) for row in store.worklist()]
        taken = store.baselines_taken()
        store.mark_looked()
    finally:
        store.close()

    known = {row["host"] for row in summary}
    declared = estate.all_nodes()
    return render(
        request,
        "monitor_estate.html",
        estate=estate,
        summary=summary,
        total=total,
        since=since,
        marker=marker,
        flagged=flagged,
        never_polled=[n for n in declared if n.name not in known],
        no_baseline=[n for n in declared if not taken.get(n.name)],
        nodes={n.name: n for n in declared},
        running=_scheduler_running(request),
    )


@router.get("/monitor/host/{host}", response_class=HTMLResponse)
def monitor_host(request: Request, host: str) -> HTMLResponse:
    """One box: what is outstanding on it, grouped by collector, worst first."""
    estate = load_estate(estate_path())
    node = next((n for n in estate.all_nodes() if n.name == host), None)

    store = _store()
    try:
        outstanding = [dict(row) for row in store.outstanding(host)]
        everything = [dict(row) for row in store.items(host)]
        beat = next((dict(b) for b in store.heartbeats() if b["host"] == host), None)
        sessions = _sessions_for(store, host)
        unknown = _unknown_key_sessions(sessions, _key_inventory(store, host))
    finally:
        store.close()

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in outstanding:
        groups.setdefault(str(row["collector"]), []).append(row)

    return render(
        request,
        "monitor_host.html",
        host=host,
        node=node,
        beat=beat,
        groups=groups,
        outstanding=outstanding,
        sessions=sessions[:25],
        unknown_key_sessions=unknown,
        reviewed_count=len([r for r in everything if r["kind"] == "config"]) - len(outstanding),
        state_items=[r for r in everything if r["kind"] == "state"],
    )


def _unknown_key_sessions(sessions: tuple[Any, ...], inventory: frozenset[str]) -> tuple[Any, ...]:
    from btht.app.monitor.sessions import unknown_keys

    return unknown_keys(tuple(sessions), inventory)


@router.get("/monitor/item/{host}/{key:path}", response_class=HTMLResponse)
def monitor_item(request: Request, host: str, key: str) -> HTMLResponse:
    """One change, in the platform's own syntax, beside whoever was on the box."""
    from datetime import timedelta

    from btht.app.monitor.sessions import around
    from btht.app.monitor.store import BaselineKind

    store = _store()
    try:
        row = store.item(host, key)
        if row is None:
            return render(
                request,
                "monitor_item.html",
                host=host,
                key=key,
                item=None,
                sessions=(),
                unknown=(),
                as_received=None,
                hardened=None,
            )
        item = dict(row)
        sessions = around(_sessions_for(store, host), str(item["last_changed"]),
                          window=timedelta(minutes=15))
        unknown = _unknown_key_sessions(sessions, _key_inventory(store, host))
        as_received = store.snapshot_value(host, key, BaselineKind.AS_RECEIVED)
        hardened = store.snapshot_value(host, key, BaselineKind.HARDENED)
    finally:
        store.close()

    estate = load_estate(estate_path())
    node = next((n for n in estate.all_nodes() if n.name == host), None)
    return render(
        request,
        "monitor_item.html",
        host=host,
        key=key,
        item=item,
        node=node,
        sessions=sessions,
        unknown=unknown,
        as_received=as_received,
        hardened=hardened,
        diff_lines=_line_diff(str(item["baseline_value"] or ""), str(item["current_value"] or "")),
    )


def _line_diff(before: str, after: str) -> list[tuple[str, str]]:
    """A line diff in the platform's own syntax — never re-rendered into ours.

    An operator has to be able to take what they read here straight to the box, so the
    text is the text the box gave us.
    """
    import difflib

    out: list[tuple[str, str]] = []
    matcher = difflib.SequenceMatcher(None, before.splitlines(), after.splitlines())
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("delete", "replace"):
            out.extend(("removed", line) for line in before.splitlines()[i1:i2])
        if tag in ("insert", "replace"):
            out.extend(("added", line) for line in after.splitlines()[j1:j2])
        if tag == "equal":
            out.extend(("same", line) for line in before.splitlines()[i1:i2])
    return out


@router.post("/monitor/item/{host}/{key:path}/{decision}")
def monitor_decide(host: str, key: str, decision: str, note: str = Form("")) -> Any:
    """Accept, flag or suppress — one item at a time, deliberately.

    `MONITORING.md` §3.4: if accepting one change re-surfaces the other nine, the
    operator stops using accept and the tool is dead.
    """
    from fastapi.responses import PlainTextResponse

    store = _store()
    try:
        if decision == "accept":
            store.accept(host, key, note)
        elif decision == "flag":
            store.flag(host, key, note)
        elif decision == "suppress":
            if not note.strip():
                return PlainTextResponse(
                    "Suppressing needs a note. It is the only record of why this item "
                    "stopped being watched.",
                    status_code=400,
                )
            store.suppress(host, key, note)
        else:
            return PlainTextResponse(f"unknown decision {decision}", status_code=400)
    finally:
        store.close()
    return RedirectResponse(f"/monitor/host/{host}", status_code=303)


@router.get("/monitor/setup", response_class=HTMLResponse)
def monitor_setup(request: Request) -> HTMLResponse:
    """Prove the monitor can reach every box, then take the two baselines — S6 and S7."""
    path = estate_path()
    if not path.exists():
        return render(request, "index.html", declared=False)
    estate = load_estate(path)
    store = _store()
    try:
        taken = store.baselines_taken()
        beats = {str(b["host"]): dict(b) for b in store.heartbeats()}
    finally:
        store.close()
    return render(
        request,
        "monitor_setup.html",
        estate=estate,
        nodes=estate.all_nodes(),
        taken=taken,
        beats=beats,
        probes=request.app.state.__dict__.get("last_probes", {}),
        running=_scheduler_running(request),
    )


@router.post("/monitor/setup/test")
async def monitor_test(request: Request) -> RedirectResponse:
    """Try every declared box and say what specifically failed on each — never 'failed'."""
    import asyncio

    from btht.app.monitor.connect import probe

    estate = load_estate(estate_path())
    scheduler = getattr(request.app.state, "scheduler", None)
    credentials = scheduler.credentials if scheduler else None
    if credentials is None:
        from btht.app.monitor.scheduler import Credentials

        credentials = Credentials()
    nodes = estate.all_nodes()
    results = await asyncio.gather(
        *(asyncio.to_thread(probe, node, credentials) for node in nodes)
    )
    request.app.state.last_probes = {p.node: p for p in results}
    return RedirectResponse("/monitor/setup", status_code=303)


@router.post("/monitor/setup/baseline/{kind}")
async def monitor_baseline(request: Request, kind: str) -> Any:
    """Collect from every box and adopt the result as the named baseline."""
    import asyncio

    from fastapi.responses import PlainTextResponse

    from btht.app.monitor.scheduler import Credentials, collect_once, transport_for
    from btht.app.monitor.store import BaselineKind

    try:
        which = BaselineKind(kind)
    except ValueError:
        return PlainTextResponse(f"unknown baseline {kind}", status_code=400)

    estate = load_estate(estate_path())
    scheduler = getattr(request.app.state, "scheduler", None)
    credentials = scheduler.credentials if scheduler else Credentials()
    nodes = estate.all_nodes()

    store = _store()
    try:
        secret = store.secret
        collections = await asyncio.gather(
            *(
                asyncio.to_thread(collect_once, node, transport_for(node, credentials), secret)
                for node in nodes
            )
        )
        taken = 0
        for collection in collections:
            store.record_heartbeat(collection)
            if collection.reachable:
                store.adopt_baseline(collection, which)
                taken += 1
    finally:
        store.close()
    return RedirectResponse(f"/monitor/setup?m=baseline+taken+for+{taken}+box(es)", status_code=303)


def _scheduler_running(request: Request) -> bool:
    scheduler = getattr(request.app.state, "scheduler", None)
    return bool(scheduler and scheduler._task is not None)


@router.get("/metrics")
def metrics() -> Any:
    """Prometheus exposition — `MONITORING.md` §8.2.

    Grafana was rejected for the operator's own view; a scrapeable endpoint was not.
    """
    from fastapi.responses import PlainTextResponse

    from btht.app.monitor.report import metrics as render_metrics

    store = _store()
    try:
        body = render_metrics(store)
    finally:
        store.close()
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


@router.get("/monitor/handover")
def monitor_handover(shift: str = "") -> Any:
    """The shift report. `MONITORING.md` §9 — a non-zero unreviewed count *is* the handover."""
    from fastapi.responses import PlainTextResponse

    from btht.app.monitor.report import handover

    store = _store()
    try:
        return PlainTextResponse(handover(store, shift))
    finally:
        store.close()


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


def _addresses(**fields: str) -> dict[str, Any]:
    """Parse several address fields, or raise the first problem with its field named."""
    out: dict[str, Any] = {}
    for name, text in fields.items():
        try:
            out[name] = parse_address(text)
        except BadAddress as exc:
            raise BadAddress(f"{name}: {exc}") from exc
    return out


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
        fields=forms.interface_fields(estate, interface),
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
    upstreams: list[str] = Form(default=[]),
) -> RedirectResponse:
    path = estate_path()
    renamed = new_ifname.strip() or ifname
    estate = load_estate(path)
    if role.strip() and not estate.knows_role(role.strip()):
        return _back(
            f"{role.strip()!r} is not one of this range's segment types. Add it in "
            "range settings first.",
            "err",
        )
    try:
        addresses = _addresses(v4=v4, v6=v6)
    except BadAddress as exc:
        return _back(str(exc), "err")
    changes: dict[str, object] = {
        "role": role.strip(),
        "v4": addresses["v4"],
        "v6": addresses["v6"],
        "descr": descr.strip(),
        "is_lan": renamed == "lan",
        "upstreams": tuple(u for u in upstreams if u),
    }
    if renamed != ifname:
        changes["ifname"] = renamed
    estate = update_interface(estate, enclave, ifname, **changes)
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
        fields=forms.host_fields(catalogue, host),
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
    services: list[str] = Form(default=[]),
    out_of_bounds: str = Form(""),
) -> RedirectResponse:
    path = estate_path()
    renamed = new_hostname.strip() or hostname
    try:
        addresses = _addresses(v4=v4, v6=v6)
    except BadAddress as exc:
        return _back(str(exc), "err")
    changes: dict[str, object] = {
        "os": os.strip(),
        "v4": addresses["v4"],
        "v6": addresses["v6"],
        "segment_role": segment_role.strip(),
        "service_role": service_role.strip(),
        "services": tuple(s for s in services if s),
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
        fields=forms.group_fields(catalogue, group),
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
            v4_start=_addresses(v4_start=v4_start)["v4_start"],
            v6_start=_addresses(v6_start=v6_start)["v6_start"],
            services=_split(services),
        )
    except (ValueError, BadAddress) as exc:
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
        fields=forms.enclave_fields([], firewall),
    )


@router.post("/range/edit/enclave/{enclave}")
def edit_enclave(
    enclave: str,
    new_enclave: str = Form("", alias="enclave"),
    display_name: str = Form(""),
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
        mgmt_address=_addresses(mgmt_address=mgmt_address)["mgmt_address"]
        or firewall.node.mgmt_address,
        gui_url=gui_url.strip(),
        ssh_user=ssh_user.strip(),
        credential_ref=credential_ref.strip(),
        enclave=new_enclave.strip() or enclave,
    )
    changes: dict[str, object] = {
        "fqdn": fqdn.strip(),
        "display_name": display_name.strip(),
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


@router.get("/services/edit/{name:path}", response_class=HTMLResponse)
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
        fields=forms.service_fields(service),
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


@router.post("/services/edit/{name:path}")
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


@router.post("/services/delete/{name:path}")
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
    services: list[str] = Form(default=[]),
    descr: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    host_type = HostType(
        name=name.strip(),
        services=tuple(s for s in services if s),
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


@router.get("/services/types/edit/{name:path}", response_class=HTMLResponse)
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
        fields=forms.host_type_fields(catalogue, host_type),
    )


@router.post("/services/types/edit/{name:path}")
def edit_host_type(
    name: str,
    new_name: str = Form("", alias="name"),
    default_os: str = Form(""),
    services: list[str] = Form(default=[]),
    descr: str = Form(""),
) -> RedirectResponse:
    catalogue = load_services(SERVICE_CATALOGUE)
    existing = catalogue.host_types.get(name)
    host_type = HostType(
        name=new_name.strip() or name,
        services=tuple(s for s in services if s),
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


@router.post("/services/types/delete/{name:path}")
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
    services: list[str] = Form(default=[]),
    out_of_bounds: str = Form(""),
    ifname: str = Form(""),
) -> RedirectResponse:
    """One machine, typed in. The paste accelerator is not the only way to add a host."""
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    catalogue = load_services(SERVICE_CATALOGUE)
    chosen = tuple(s for s in services if s)
    if not chosen and host_type:
        host_type_entry = catalogue.host_types.get(host_type)
        chosen = tuple(host_type_entry.services) if host_type_entry else ()

    try:
        addresses = _addresses(v4=v4, v6=v6)
    except BadAddress as exc:
        return _back(str(exc), "err", where=f"enclave={enclave}&interface={ifname}")

    host = Host(
        hostname=hostname.strip(),
        os=os.strip(),
        v4=addresses["v4"],
        v6=addresses["v6"],
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
            v4_start=_addresses(v4_start=v4_start)["v4_start"],
            v6_prefix=v6_prefix.strip(),
        )
    except (ValueError, BadAddress) as exc:
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


@router.post("/range/routers")
def add_router(
    name: str = Form(...),
    mgmt_address: str = Form(...),
    ssh_user: str = Form(""),
    gui_url: str = Form(""),
    credential_ref: str = Form(""),
    poll_seconds: int = Form(60),
) -> RedirectResponse:
    """A router. Always FRR on Linux, so the platform is not a question worth asking.

    They exist in their own right: the monitor polls them, and a firewall interface
    says which of them it peers with.
    """
    from dataclasses import replace as dc_replace

    path = estate_path()
    estate = load_estate(path)
    try:
        node = Node(
            name=name.strip(),
            platform=Platform.FRR,
            mgmt_address=_addresses(mgmt_address=mgmt_address)["mgmt_address"],
            ssh_user=ssh_user.strip(),
            gui_url=gui_url.strip(),
            credential_ref=credential_ref.strip(),
            poll_seconds=poll_seconds,
        )
    except (ValueError, BadAddress) as exc:
        return _back(str(exc), "err", where="routers=1")
    _save(dc_replace(estate, nodes=(*estate.nodes, node)), path)
    return _back(f"{node.name} added", where="routers=1")


@router.post("/range/routers/{name}/delete")
def delete_router(name: str) -> RedirectResponse:
    """Refused while an interface still says it peers with this router."""
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
            where="routers=1",
        )
    _save(dc_replace(estate, nodes=tuple(n for n in estate.nodes if n.name != name)), path)
    return _back(f"{name} removed", where="routers=1")


# ===========================================================================
#  Segment types, services and host templates — each its own page
# ===========================================================================


@router.get("/segments", response_class=HTMLResponse)
def segments_page(request: Request) -> HTMLResponse:
    """The kinds of segment this range has. Shipped with defaults, edited here."""
    shipped = load_segment_types(SEGMENT_TYPES)
    path = estate_path()
    in_use: dict[str, list[str]] = {}
    declared: tuple[str, ...] = ()
    if path.exists():
        estate = load_estate(path)
        declared = estate.role_vocabulary
        for firewall in estate.firewalls:
            for interface in firewall.interfaces:
                in_use.setdefault(interface.role, []).append(
                    f"{firewall.enclave}/{interface.ifname}"
                )
    return render(
        request,
        "segments.html",
        page="segments",
        types=[shipped.get(n, SegmentType(name=n, custom=True)) for n in sorted(declared)]
        or sorted(shipped.values(), key=lambda t: t.name),
        in_use=in_use,
        has_range=path.exists(),
        messages=(
            [(request.query_params.get("k", "ok"), request.query_params["m"])]
            if request.query_params.get("m")
            else []
        ),
    )


@router.post("/segments")
def add_segment_type(name: str = Form(...), descr: str = Form("")) -> RedirectResponse:
    """Define a segment type, and add it to this range's list."""
    from dataclasses import replace as dc_replace

    clean = name.strip()
    if not clean:
        return RedirectResponse("/segments?m=a segment type needs a name&k=err", status_code=303)

    shipped = load_segment_types(SEGMENT_TYPES)
    if clean not in shipped:
        shipped[clean] = SegmentType(name=clean, descr=descr.strip(), custom=True)
        save_segment_types(shipped, SEGMENT_TYPES)

    path = estate_path()
    if path.exists():
        estate = load_estate(path)
        if clean not in estate.role_vocabulary:
            _save(dc_replace(estate, role_vocabulary=(*estate.role_vocabulary, clean)), path)
    return RedirectResponse(f"/segments?m={clean} added", status_code=303)


@router.post("/segments/{name}/delete")
def remove_segment_type(name: str) -> RedirectResponse:
    """Refused while an interface is still assigned to it."""
    from dataclasses import replace as dc_replace

    path = estate_path()
    if path.exists():
        estate = load_estate(path)
        used = [
            f"{f.enclave}/{i.ifname}"
            for f in estate.firewalls
            for i in f.interfaces
            if i.role == name
        ]
        if used:
            return RedirectResponse(
                f"/segments?m={name} is assigned to " + ", ".join(used) + "&k=err",
                status_code=303,
            )
        _save(
            dc_replace(
                estate,
                role_vocabulary=tuple(r for r in estate.role_vocabulary if r != name),
            ),
            path,
        )
    return RedirectResponse(f"/segments?m={name} removed from this range", status_code=303)


@router.get("/host-templates", response_class=HTMLResponse)
def host_templates_page(request: Request) -> HTMLResponse:
    """Host templates, on their own page rather than the bottom of another one."""
    catalogue = load_services(SERVICE_CATALOGUE)
    return render(
        request,
        "host_templates.html",
        page="types",
        host_types=[catalogue.host_types[n] for n in sorted(catalogue.host_types)],
        catalogue=catalogue,
        service_names=sorted(catalogue.services),
        messages=(
            [(request.query_params.get("k", "ok"), request.query_params["m"])]
            if request.query_params.get("m")
            else []
        ),
    )
