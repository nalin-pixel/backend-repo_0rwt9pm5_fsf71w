"""
Database Schemas for Comic Reader App

Each Pydantic model maps to a MongoDB collection. Collection name is the lowercase
of the class name (e.g., User -> "user").
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    name: str = Field(..., description="Display name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = Field(None, description="Profile avatar URL")
    is_active: bool = Field(True, description="Whether user is active")


class Comic(BaseModel):
    title: str = Field(...)
    author: Optional[str] = None
    genres: List[str] = Field(default_factory=list)
    synopsis: Optional[str] = None
    cover_url: Optional[str] = None
    rating: float = Field(0, ge=0, le=5)
    tags: List[str] = Field(default_factory=list)


class Chapter(BaseModel):
    comic_id: str = Field(..., description="Reference to Comic _id as string")
    title: str = Field(...)
    number: float = Field(..., description="Chapter number to allow 1.5, etc.")
    images: List[str] = Field(default_factory=list, description="Ordered list of image URLs for the chapter")
    release_date: Optional[str] = None


class Bookmark(BaseModel):
    user_id: str
    comic_id: str


class History(BaseModel):
    user_id: str
    comic_id: str
    chapter_id: Optional[str] = None
    last_read_page: Optional[int] = 0
