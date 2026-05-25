"""Common Pydantic response models and OpenAPI error definitions."""

from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

APPLICATION_JSON = "application/json"
ERROR_RESPONSE_SCHEMA_REF = "#/components/schemas/ErrorResponse"


class ErrorResponse(BaseModel):
    """Standard error response."""
    status_code: int = Field(..., example=400)
    message: str     = Field(..., example="An error occurred")
    data: List[Any]  = Field(default_factory=list, example=[])


class SuccessResponse(BaseModel, Generic[T]):
    """Standard success response (paginated or flat)."""
    status_code: int           = Field(default=200, example=200)
    message: str               = Field(..., example="Data retrieved successfully")
    data: List[T]              = Field(..., example=[])
    totalPages: Optional[int]  = Field(None, example=5)
    totalData: Optional[int]   = Field(None, example=48)


COMMON_ERROR_RESPONSES = {
    "BadRequest": {
        "description": "Bad Request",
        "content": {APPLICATION_JSON: {"schema": {"$ref": ERROR_RESPONSE_SCHEMA_REF},
                                       "example": {"status_code": 400, "message": "Invalid request", "data": []}}},
    },
    "Unauthorized": {
        "description": "Unauthorized",
        "content": {APPLICATION_JSON: {"schema": {"$ref": ERROR_RESPONSE_SCHEMA_REF},
                                       "example": {"status_code": 401, "message": "Authentication required", "data": []}}},
    },
    "Forbidden": {
        "description": "Forbidden",
        "content": {APPLICATION_JSON: {"schema": {"$ref": ERROR_RESPONSE_SCHEMA_REF},
                                       "example": {"status_code": 403, "message": "Insufficient permissions", "data": []}}},
    },
    "NotFound": {
        "description": "Not Found",
        "content": {APPLICATION_JSON: {"schema": {"$ref": ERROR_RESPONSE_SCHEMA_REF},
                                       "example": {"status_code": 404, "message": "Resource not found", "data": []}}},
    },
    "InternalServerError": {
        "description": "Internal Server Error",
        "content": {APPLICATION_JSON: {"schema": {"$ref": ERROR_RESPONSE_SCHEMA_REF},
                                       "example": {"status_code": 500, "message": "Internal server error", "data": []}}},
    },
}

