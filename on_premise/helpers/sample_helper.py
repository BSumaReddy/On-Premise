"""
Sample Helper — business-logic utilities for the Sample API.
"""

from on_premise.utils.logging import logger


class SampleHelper:
    """Business-logic layer for the Sample service."""

    @staticmethod
    def build_summary(records: list) -> dict:
        """
        Wrap a list of records in a summary envelope.

        Args:
            records: List of record dicts from the repository layer.

        Returns:
            dict with ``total`` count and the ``items`` list.
        """
        logger.info(f"SampleHelper.build_summary: {len(records)} records")
        return {"total": len(records), "items": records}

    @staticmethod
    def filter_by_name(records: list, name: str | None) -> list:
        """
        Case-insensitive substring filter on the ``name`` field.

        Args:
            records: Full list of record dicts.
            name: Substring to match; pass ``None`` to skip filtering.

        Returns:
            Filtered list.
        """
        if not name:
            return records
        return [r for r in records if name.lower() in r.get("name", "").lower()]

