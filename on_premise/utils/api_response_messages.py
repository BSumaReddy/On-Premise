"""
Standardised API response message constants.
Each entry is a (http_status_code, user_friendly_message) tuple.
"""


class ErrorMessages:
    UNKNOWN_ERROR            = (500, "An unexpected error occurred.")
    INVALID_INPUT            = (400, "Please check your input and try again.")
    MISSING_PARAMETER        = (400, "A required parameter is missing. Please check your request.")
    INVALID_ARGUMENT_TYPE    = (400, "Invalid argument type provided. Please check your input.")
    RESOURCE_NOT_FOUND       = (404, "The requested item could not be found.")
    FILE_NOT_FOUND           = (404, "The requested file could not be found.")
    FILE_READ_ERROR          = (400, "Unable to read the file. Please check the file and try again.")
    FILE_WRITE_ERROR         = (500, "Unable to save the file. Please try again.")
    FILE_TOO_LARGE           = (413, "The file is too large. Please upload a smaller file.")
    AUTH_FAILED              = (401, "Authentication failed. Please check your credentials.")
    TOKEN_EXPIRED            = (401, "Your session has expired. Please sign in again.")
    TOKEN_INVALID            = (401, "Invalid authentication. Please sign in again.")
    ACCESS_DENIED            = (403, "You do not have permission to perform this action.")
    OPERATION_NOT_ALLOWED    = (403, "This operation is not allowed.")
    METHOD_NOT_ALLOWED       = (405, "This operation is not allowed for this resource.")
    UNSUPPORTED_MEDIA_TYPE   = (415, "Unsupported content type. Please check your request format.")
    VALIDATION_ERROR         = (422, "Some fields may be missing or formatted incorrectly.")
    UNPROCESSABLE_ENTITY     = (422, "The request is well-formed but contains semantic errors.")
    RATE_LIMIT_EXCEEDED      = (429, "Too many requests. Please wait a moment and try again.")
    DB_CONNECTION_FAILED     = (500, "Unable to process your request at this time. Please try again later.")
    DB_TIMEOUT               = (504, "The request took too long to process. Please try again.")
    DB_INTEGRITY_ERROR       = (400, "Invalid data provided. Please check all required fields.")
    DB_UNIQUE_VIOLATION      = (409, "This record already exists. Please use a different value.")
    DB_FOREIGN_KEY_VIOLATION = (400, "Cannot perform this operation. The referenced item does not exist.")
    DB_NOT_NULL_VIOLATION    = (400, "Please fill in all required fields.")
    DB_WRITE_ERROR           = (500, "Unable to save your changes. Please try again.")
    DB_OPERATION_FAILED      = (500, "Unable to process your request. Please try again later.")
    EXTERNAL_API_FAILED      = (502, "Unable to connect to external service. Please try again later.")
    HTTP_REQUEST_ERROR       = (503, "Request failed due to a network or connection error.")
    HTTP_STATUS_ERROR        = (502, "External service returned an error. Please try again later.")
    SERVICE_UNAVAILABLE      = (503, "Service is temporarily unavailable. Please try again later.")


class SuccessMessages:
    RETRIEVED_SUCCESSFULLY = (200, "Data retrieved successfully.")
    CREATED_SUCCESSFULLY   = (201, "Resource created successfully.")
    UPDATED_SUCCESSFULLY   = (200, "Resource updated successfully.")
    DELETED_SUCCESSFULLY   = (200, "Resource deleted successfully.")

