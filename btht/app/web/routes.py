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

from btht.app.data import ESTATES
from btht.app.ingest.pfsense import ParseError, parse_string
from btht.app.ingest.roles import derive_interfaces, derive_side
from btht.app.model.estate import Estate, Firewall, Node, Platform
from btht.app.model.policy import (
    EstateFileError,
    convention_of,
    load_estate,
    parse_address,
    save_estate,
    side_rules_of,
)
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
