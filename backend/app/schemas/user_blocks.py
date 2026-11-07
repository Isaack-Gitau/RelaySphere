from pydantic import BaseModel, Field

from app.schemas.user_discovery import UserDirectoryEntry


class BlockedUsersResponse(BaseModel):
    """One page of the caller's blocked users with an opaque continuation cursor."""

    items: list[UserDirectoryEntry] = Field(max_length=50)
    next_cursor: str | None
