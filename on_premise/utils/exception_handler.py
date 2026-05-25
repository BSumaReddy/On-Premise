"""
Central exception handler decorator.
Wraps any endpoint (sync or async) and maps every known exception type
to a standardised JSON error response via ResponseBuilder.
"""

import asyncio
import json
from functools import wraps
from inspect import iscoroutinefunction

import httpx
import psycopg2
from fastapi import HTTPException
from pydantic import ValidationError

try:
    from sqlalchemy.exc import (
        DataError, IntegrityError, InvalidRequestError,
        MultipleResultsFound, NoResultFound, OperationalError,
        ProgrammingError, SQLAlchemyError,
    )
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

try:
    from pymongo.errors import (
        DuplicateKeyError, OperationFailure, PyMongoError,
        ServerSelectionTimeoutError,
    )
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

from on_premise.utils.api_response_messages import ErrorMessages
from on_premise.utils.custom_exceptions import CustomExceptions
from on_premise.utils.logging import logger
from on_premise.utils.response_builder import ResponseBuilder


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _log_error(error: Exception, input_log: dict, func_name: str):
    import traceback
    input_log["error_trace"] = traceback.format_exc()
    input_log["func"] = func_name
    logger.error(input_log)


def _handle_exceptions(error: Exception, input_log: dict, func_name: str):
    """Map *error* to the correct ResponseBuilder call."""
    _log_error(error, input_log, func_name)

    def _resp(tpl):
        code, msg = tpl
        return ResponseBuilder().fail(code).message(msg).get_response(add_pagination=False)

    # Built-ins
    if isinstance(error, TypeError):
        return _resp(ErrorMessages.INVALID_ARGUMENT_TYPE)
    if isinstance(error, (ValueError, AttributeError, IndexError)):
        return _resp(ErrorMessages.INVALID_INPUT)
    if isinstance(error, KeyError):
        return _resp(ErrorMessages.MISSING_PARAMETER)
    if isinstance(error, (ImportError, ModuleNotFoundError, MemoryError)):
        return _resp(ErrorMessages.SERVICE_UNAVAILABLE)
    if isinstance(error, RuntimeError):
        return _resp(ErrorMessages.DB_OPERATION_FAILED)
    if isinstance(error, (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError)):
        return _resp(ErrorMessages.INVALID_INPUT)
    if isinstance(error, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException)):
        return _resp(ErrorMessages.DB_TIMEOUT)

    # SQLAlchemy
    if SQLALCHEMY_AVAILABLE:
        if isinstance(error, IntegrityError):
            msg = str(error).lower()
            if "unique" in msg or "duplicate" in msg:
                return _resp(ErrorMessages.DB_UNIQUE_VIOLATION)
            if "foreign key" in msg:
                return _resp(ErrorMessages.DB_FOREIGN_KEY_VIOLATION)
            if "not null" in msg:
                return _resp(ErrorMessages.DB_NOT_NULL_VIOLATION)
            return _resp(ErrorMessages.DB_INTEGRITY_ERROR)
        if isinstance(error, OperationalError):
            msg = str(error).lower()
            if "timeout" in msg:
                return _resp(ErrorMessages.DB_TIMEOUT)
            if "connection" in msg:
                return _resp(ErrorMessages.DB_CONNECTION_FAILED)
            return _resp(ErrorMessages.DB_OPERATION_FAILED)
        if isinstance(error, (ProgrammingError, DataError, InvalidRequestError)):
            return _resp(ErrorMessages.INVALID_INPUT)
        if isinstance(error, NoResultFound):
            return _resp(ErrorMessages.RESOURCE_NOT_FOUND)
        if isinstance(error, MultipleResultsFound):
            return _resp(ErrorMessages.DB_INTEGRITY_ERROR)
        if isinstance(error, SQLAlchemyError):
            return _resp(ErrorMessages.DB_OPERATION_FAILED)

    # psycopg2
    if isinstance(error, psycopg2.Error):
        return _resp(ErrorMessages.DB_OPERATION_FAILED)

    # MongoDB
    if MONGODB_AVAILABLE:
        if isinstance(error, DuplicateKeyError):
            return _resp(ErrorMessages.DB_UNIQUE_VIOLATION)
        if isinstance(error, ServerSelectionTimeoutError):
            return _resp(ErrorMessages.DB_TIMEOUT)
        if isinstance(error, (OperationFailure, PyMongoError)):
            return _resp(ErrorMessages.DB_OPERATION_FAILED)

    # FastAPI / Starlette
    if isinstance(error, HTTPException):
        return ResponseBuilder().fail(error.status_code).message(
            str(error.detail) if error.detail else ErrorMessages.UNKNOWN_ERROR[1]
        ).get_response(add_pagination=False)

    # Custom business exceptions
    if isinstance(error, CustomExceptions):
        msg = str(error)
        code, default_msg = ErrorMessages.UNPROCESSABLE_ENTITY
        return ResponseBuilder().fail(code).message(msg if msg else default_msg).get_response(add_pagination=False)

    # Pydantic
    if isinstance(error, ValidationError):
        return _resp(ErrorMessages.VALIDATION_ERROR)

    # File / IO
    if isinstance(error, FileNotFoundError):
        return _resp(ErrorMessages.FILE_NOT_FOUND)
    if isinstance(error, (PermissionError, OSError, IOError)):
        return _resp(ErrorMessages.FILE_WRITE_ERROR)

    # httpx
    if isinstance(error, httpx.RequestError):
        return _resp(ErrorMessages.HTTP_REQUEST_ERROR)
    if isinstance(error, httpx.HTTPStatusError):
        return _resp(ErrorMessages.HTTP_STATUS_ERROR)

    # Network
    if isinstance(error, ConnectionError):
        return _resp(ErrorMessages.EXTERNAL_API_FAILED)

    # Catch-all
    return _resp(ErrorMessages.UNKNOWN_ERROR)


# ---------------------------------------------------------------------------
# Public decorator
# ---------------------------------------------------------------------------

def exception_handler(func):
    """
    Decorator that catches all exceptions and converts them to structured
    JSON error responses.  Supports both sync and async endpoint functions.
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        input_log: dict = {}
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            return _handle_exceptions(exc, input_log, func.__name__)

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        input_log: dict = {}
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            return _handle_exceptions(exc, input_log, func.__name__)

    return async_wrapper if iscoroutinefunction(func) else sync_wrapper

