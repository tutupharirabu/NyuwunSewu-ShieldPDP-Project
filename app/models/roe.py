from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import TimestampMixin, new_id


class RoeDocument(Base, TimestampMixin):
    """An uploaded Rules-of-Engagement document for an external engagement.

    Retained for compliance / audit even after the scan completes.
    """

    __tablename__ = "roe_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    extracted_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    extraction_warning: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
