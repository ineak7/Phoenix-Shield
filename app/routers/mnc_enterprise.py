from fastapi import APIRouter, Header, HTTPException, status

router = APIRouter()

VALID_MNC_LICENSES = ["MNC-SECURE-KEY-2026-X99", "ENTERPRISE-PRO-KEY"]

@router.get("/software-upgrade")
def get_software_upgrade(x_license_key: str = Header(...)):
    if x_license_key not in VALID_MNC_LICENSES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Invalid or missing MNC enterprise license key."
        )
    return {
        "status": "authorized",
        "upgrade_version": "v2.4.0-enterprise",
        "patch_notes": "Advanced threat detection rules deployed via codebase sync."
    }