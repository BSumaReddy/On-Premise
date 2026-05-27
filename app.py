"""
On-Premise API Application Entry Point.

__author__: BanyanCloud Engineering
__email__: engineering@banyancloud.io
__status__: Development
__copyright__: Banyan Cloud Inc @2024
__version__: 1.0.0
"""

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# On-Premise routers (no shift_left dependency)
# ---------------------------------------------------------------------------
from on_premise.routers.recs_onprem_asset_master_details import router as master_router
from on_premise.routers.recs_onprem_asset_details import router as details_router
from on_premise.routers.recs_onprem_asset_final_compliance import router as compliance_router

app = FastAPI(
    title="BanyanCloud On-Premise API",
    description=(
        "Centralized, comprehensive solution for identifying and managing "
        "security vulnerabilities in your application's dependencies and "
        "infrastructure code."
    ),
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Configuration for CORS
_cors_raw = os.getenv("CORS_ORIGIN_IP_LIST", "*")
ALLOWED_ORIGINS = [o.strip() for o in _cors_raw.split(",")]


# Middleware to handle path prefix for reverse proxy deployment
@app.middleware("http")
async def set_script_name_from_header(request: Request, call_next):
    """
    Middleware to set root_path from headers for reverse proxy deployments.

    This allows Swagger UI to work correctly when the app is deployed behind
    a reverse proxy with a path prefix (e.g., /sl in QA environment).

    Checks headers in order:
    1. X-Script-Name (common in reverse proxies)
    2. X-Forwarded-Prefix (common in Istio/Envoy)
    3. ISTIO_PREFIX environment variable (fallback)
    """
    # Get header value
    prefix = (
        request.headers.get("X-Script-Name")
        or request.headers.get("X-Forwarded-Prefix")
        or os.getenv("ISTIO_PREFIX", "")
    )

    # Normalize to "/sl" style
    prefix = f"/{prefix.strip('/')}" if prefix else ""

    # Modify request scope to set root_path
    # This ensures FastAPI generates correct URLs for Swagger UI
    request.scope["root_path"] = prefix
    return await call_next(request)


# Add middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    # Allow all methods
    allow_methods=["*"],
    # Allow all headers
    allow_headers=["*"],
)

app.include_router(master_router)
app.include_router(details_router)
app.include_router(compliance_router)


# Custom OpenAPI at /apidocs/apispec.json
@app.get("/apidocs/apispec.json", include_in_schema=False)
async def custom_openapi_schema(request: Request):
    root_path = request.scope.get("root_path", "")

    servers = [{"url": root_path or "/", "description": "Deployment prefix"}]

    from on_premise.models.common_responses import (COMMON_ERROR_RESPONSES,
                                                    ErrorResponse,
                                                    SuccessResponse)

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        servers=servers,
    )

    # Required by Swagger UI
    openapi_schema["openapi"] = "3.0.2"

    # Ensure components exist
    components = openapi_schema.setdefault("components", {})
    components.setdefault("securitySchemes", {})
    components.setdefault("schemas", {})
    components.setdefault("responses", {})

    # Add response schemas (required by COMMON_ERROR_RESPONSES and endpoint responses)
    try:
        # Pydantic v2
        components["schemas"]["ErrorResponse"] = ErrorResponse.model_json_schema()
        components["schemas"]["SuccessResponse"] = SuccessResponse.model_json_schema()
    except AttributeError:
        # Fallback for Pydantic v1
        components["schemas"]["ErrorResponse"] = ErrorResponse.schema()
        components["schemas"]["SuccessResponse"] = SuccessResponse.schema()

    # Add common error responses (reusable via $ref in endpoint responses)
    components["responses"].update(COMMON_ERROR_RESPONSES)

    # Add security schemes for Swagger UI authentication
    components["securitySchemes"] = {
        "AccessToken": {
            "type": "apiKey",
            "in": "header",
            "name": "access-token",
            "description": "Cognito access token",
        },
        "IdToken": {
            "type": "apiKey",
            "in": "header",
            "name": "id-token",
            "description": "Cognito ID token",
        },
        "CookieAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "Cookie",
            "description": "Cookie header containing both access-token and id-token",
        },
    }

    # Add global security requirements
    openapi_schema["security"] = [
        {"AccessToken": [], "IdToken": []},
        {"CookieAuth": []},
    ]

    return JSONResponse(content=openapi_schema)


# Custom Swagger UI (works for /apidocs and /sl/apidocs)
@app.get("/apidocs", include_in_schema=False)
async def custom_swagger_ui(request: Request):
    root_path = request.scope.get("root_path", "")
    openapi_url = f"{root_path}/apidocs/apispec.json"

    return get_swagger_ui_html(
        openapi_url=openapi_url, title="BanyanCloud ShiftLeft API Docs"
    )


# Optional ReDoc
@app.get("/redoc", include_in_schema=False)
async def custom_redoc(request: Request):
    root_path = request.scope.get("root_path", "")
    return get_redoc_html(
        openapi_url=f"{root_path}/apidocs/apispec.json",
        title="BanyanCloud ShiftLeft API ReDoc",
    )


@app.get("/healthz")
def health_check():
    """Check the health status of the API service.

    Returns:
        dict: A dictionary containing the service status
    """
    return {"status": "ok"}
if __name__ == "__main__":
    import subprocess
    import uvicorn
    from dotenv import load_dotenv

    # Load environment variables from file
    load_dotenv("environment.env")

    PORT = int(os.getenv("APP_PORT", 8001))



    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=PORT,
        reload=False,   # reload=True causes double-bind errors when run as __main__
        workers=1,
    )
