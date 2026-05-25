"""
Sample Repository — all DB interactions for the Sample resource.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from on_premise.utils.logging import logger


class SampleRepository:
    """
    Data-access layer for sample records.

    Replace the mock data blocks below with real ORM/SQL queries
    once you have a dedicated table in the database.
    """

    @staticmethod
    async def get_all_samples(filters: dict, session: AsyncSession) -> list[dict]:
        """
        Return all sample records (optionally filtered).

        Args:
            filters: Key/value pairs for WHERE conditions.
            session: Injected SQLAlchemy async session.

        Returns:
            List of record dicts.
        """
        logger.info(f"SampleRepository.get_all_samples  filters={filters}")

        # ------------------------------------------------------------------
        # TODO: Replace with real ORM query, e.g.
        #   result = await session.execute(select(SampleModel))
        #   return [row._asdict() for row in result.scalars().all()]
        # ------------------------------------------------------------------
        return [
            {"id": 1, "name": "Alpha Resource",  "status": "active",   "cloud": "aws"},
            {"id": 2, "name": "Beta Resource",   "status": "inactive", "cloud": "azure"},
            {"id": 3, "name": "Gamma Resource",  "status": "active",   "cloud": "gcp"},
        ]

    @staticmethod
    async def get_sample_by_id(sample_id: int, session: AsyncSession) -> dict | None:
        """
        Return a single sample record by primary key, or ``None`` if not found.

        Args:
            sample_id: Integer primary key.
            session:   Injected SQLAlchemy async session.
        """
        logger.info(f"SampleRepository.get_sample_by_id  id={sample_id}")

        # ------------------------------------------------------------------
        # TODO: Replace with real ORM query, e.g.
        #   result = await session.get(SampleModel, sample_id)
        #   return result.__dict__ if result else None
        # ------------------------------------------------------------------
        mock = {
            1: {"id": 1, "name": "Alpha Resource",  "status": "active",   "cloud": "aws"},
            2: {"id": 2, "name": "Beta Resource",   "status": "inactive", "cloud": "azure"},
            3: {"id": 3, "name": "Gamma Resource",  "status": "active",   "cloud": "gcp"},
        }
        return mock.get(sample_id)

    @staticmethod
    async def create_sample(payload: dict, session: AsyncSession) -> dict:
        """
        Persist a new sample record and return the created dict.

        Args:
            payload: Fields for the new record.
            session: Injected SQLAlchemy async session.
        """
        logger.info(f"SampleRepository.create_sample  payload={payload}")

        # ------------------------------------------------------------------
        # TODO: Replace with real insert, e.g.
        #   obj = SampleModel(**payload)
        #   session.add(obj)
        #   await session.commit()
        #   await session.refresh(obj)
        #   return obj.__dict__
        # ------------------------------------------------------------------
        new_record = {"id": 99, **payload}
        return new_record

