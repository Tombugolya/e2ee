class InvalidAPIUsageError(Exception):
    """
    Custom exception class to handle API usage errors.
    """

    def __init__(self, message: str, status_code=400):
        super().__init__()
        self.message = message
        self.status_code = status_code

    def to_dict(self) -> dict:
        return {"message": self.message, "status_code": self.status_code}
