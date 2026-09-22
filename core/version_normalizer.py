def format_portal_version(
    portal_self_version=None,
    portal_admin_version=None,
    full_version=None,
) -> str:
    """Use the Portal product version, without calendar-version guessing.

    `/sharing/rest/portals/self` is preferred because it reports the ArcGIS
    Enterprise product version, for example 11.5. A Portal Admin value such as
    2025.1 is retained in metadata but is not converted through a hard-coded
    lookup table.
    """
    for candidate in (portal_self_version, full_version, portal_admin_version):
        if candidate not in (None, ""):
            return str(candidate).strip()
    return "Unknown"
