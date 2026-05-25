"""Builds consistent JSON response envelopes."""

from fastapi.responses import JSONResponse
from starlette import status


class ResponseBuilder:
    """Fluent builder for standardized API responses."""

    def __init__(self):
        self.results = []
        self.status_code = status.HTTP_200_OK
        self.status_message = ""

    def success(self) -> "ResponseBuilder":
        self.status_code = status.HTTP_200_OK
        return self

    def fail(self, status_code: int) -> "ResponseBuilder":
        self.status_code = status_code
        return self

    def message(self, status_message: str) -> "ResponseBuilder":
        self.status_message = status_message
        return self

    def result_object(self, result) -> "ResponseBuilder":
        self.results = result
        return self

    def get_response(self, add_pagination: bool = True) -> JSONResponse:
        content = {
            "status_code": self.status_code,
            "message": self.status_message,
        }

        if add_pagination and self.results:
            content.update({
                "data": self.results[0],
                "totalPages": self.results[1],
                "totalData": self.results[-1],
            })
        else:
            content["data"] = self.results

        return JSONResponse(status_code=self.status_code, content=content)

