class CustomExceptions(Exception):
    """Used to raise custom business-logic exceptions."""

    def __init__(self, msg: str):
        super().__init__(msg)

