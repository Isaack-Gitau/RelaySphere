import uuid

from pydantic import BaseModel, Field


class UserDirectoryEntry(BaseModel):
    """Public fields of a discoverable user."""

    id: uuid.UUID
    username: str
    display_name: str


class UserSearchResponse(BaseModel):
    """One page of search results with an opaque continuation cursor."""

    items: list[UserDirectoryEntry] = Field(max_length=50)
    next_cursor: str | None
