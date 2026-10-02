"""Deterministic interoperability identities derived from verified S4 components."""

from __future__ import annotations

from dataclasses import dataclass

from packageurl import PackageURL

from securescan.advisories.osv.models import canonical_package_name, purl_package_name
from securescan.evidence import PackageComponentPayload, SecureScanComponent


class ComponentIdentityError(ValueError):
    def __init__(self) -> None:
        super().__init__("SecureScan component identity is invalid")


@dataclass(frozen=True, slots=True)
class InteroperablePackageIdentity:
    component_ref: str
    bom_ref: str
    name: str
    version: str | None
    package_type: str
    purl: str | None
    identity_source: str


_PURL_TYPES = {"go-module": "golang", "npm": "npm", "python": "pypi"}


def package_identity(component: SecureScanComponent) -> InteroperablePackageIdentity:
    payload = component.payload
    if not isinstance(payload, PackageComponentPayload):
        raise ComponentIdentityError

    purl = payload.purl or _derive_purl(payload)
    if purl is not None:
        _verify_coordinates(payload, PackageURL.from_string(purl))
    return InteroperablePackageIdentity(
        component_ref=component.component_ref,
        bom_ref=f"urn:securescan:component:{component.component_ref}",
        name=payload.package_name,
        version=payload.package_version,
        package_type=payload.package_type,
        purl=purl,
        identity_source=(
            "observed_purl"
            if payload.purl is not None
            else "derived_purl"
            if purl is not None
            else "securescan_package_key"
        ),
    )


def _derive_purl(payload: PackageComponentPayload) -> str | None:
    purl_type = _PURL_TYPES.get(payload.package_type)
    if purl_type is None or payload.package_version is None:
        return None
    namespace: str | None = None
    name = payload.package_name
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)
    elif purl_type == "golang" and "/" in name:
        namespace, name = name.rsplit("/", 1)
    try:
        return PackageURL(
            type=purl_type,
            namespace=namespace,
            name=name,
            version=payload.package_version,
        ).to_string()
    except (TypeError, ValueError):
        raise ComponentIdentityError from None


def _verify_coordinates(payload: PackageComponentPayload, purl: PackageURL) -> None:
    expected_type = _PURL_TYPES.get(payload.package_type)
    try:
        names_match = (
            expected_type is None
            or canonical_package_name(purl.type, payload.package_name)
            == purl_package_name(purl)
        )
    except ValueError:
        raise ComponentIdentityError from None
    if (
        (expected_type is not None and purl.type != expected_type)
        or purl.version != payload.package_version
        or not names_match
    ):
        raise ComponentIdentityError
