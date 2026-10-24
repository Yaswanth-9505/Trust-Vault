class ApiError(Exception):
    """An error with a status code and a message that is safe to show the user."""

    def __init__(self, status: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code or {
            400: "bad_request", 401: "unauthenticated", 403: "forbidden",
            404: "not_found", 409: "conflict", 413: "too_large", 415: "unsupported_type",
            423: "locked", 429: "rate_limited",
        }.get(status, "error")


def bad_request(message):
    return ApiError(400, message)
