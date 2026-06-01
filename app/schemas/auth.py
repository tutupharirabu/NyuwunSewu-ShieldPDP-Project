from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str
    organization_slug: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class UserResponse(BaseModel):
    id: str
    organization_id: str | None
    email: str
    full_name: str
    role: str
    permissions: list[str] = Field(default_factory=list)


class UserCreateRequest(BaseModel):
    email: str
    full_name: str
    password: str = Field(min_length=10)
    role: str
