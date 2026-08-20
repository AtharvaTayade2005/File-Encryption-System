"""
Zero-Knowledge Database Models (SQLAlchemy) & API Validation Schemas (Pydantic).
Guarantees zero-knowledge compliance:
- Users: Stores salt, derived auth_hash (NOT password), public key JWK, and encrypted private key blob.
- Files: Stores UUID, encrypted blob path on disk, IV, encrypted metadata, size, owner.
- SharedKeys: Stores RSA-wrapped DEKs mapped to recipients or anonymous link share tokens.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field

from database import Base


# ============================================================================
# 1. SQLAlchemy ORM Models (Zero-Knowledge Storage)
# ============================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    
    # 16-byte random salt (Base64) used by client for PBKDF2
    salt = Column(String(64), nullable=False)
    
    # Client-derived PBKDF2-SHA256 hash (256-bit Hex) - raw password NEVER reaches server
    auth_hash = Column(String(128), nullable=False)
    
    # Public Key JWK (JSON string) - used by other users to wrap DEKs
    public_key_jwk = Column(Text, nullable=False)
    
    # User's RSA private key JWK encrypted with client's KEK (JSON containing ciphertext & IV)
    # Server cannot decrypt this because it never possesses the KEK or password
    encrypted_private_key = Column(Text, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")
    received_keys = relationship("SharedKey", back_populates="recipient", cascade="all, delete-orphan")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    
    # Path to binary encrypted blob stored on disk (e.g. ./uploads/<id>.enc)
    encrypted_blob_path = Column(String(255), nullable=False)
    
    # 12-byte AES-GCM IV used for file payload (Base64)
    iv = Column(String(64), nullable=False)
    
    # Encrypted metadata JSON blob (contains encrypted filename & mime-type, encrypted with DEK)
    encrypted_metadata = Column(Text, nullable=False)
    
    # Encrypted file size in bytes
    file_size = Column(Integer, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    owner = relationship("User", back_populates="files")
    shared_keys = relationship("SharedKey", back_populates="file", cascade="all, delete-orphan")


class SharedKey(Base):
    __tablename__ = "shared_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String(36), ForeignKey("files.id"), nullable=False, index=True)
    
    # Nullable recipient: None represents link-shared key or owner's key entry
    recipient_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    
    # Base64-encoded RSA-wrapped AES DEK (or owner's wrapped DEK)
    # Note: For anonymous URL link sharing, DEK is in the URL fragment #key=... and never stored here.
    wrapped_key = Column(Text, nullable=False)
    
    # Optional label / target username cached for fast UI listing
    recipient_username = Column(String(50), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    file = relationship("FileRecord", back_populates="shared_keys")
    recipient = relationship("User", back_populates="received_keys")


# ============================================================================
# 2. Pydantic Request / Response Schemas
# ============================================================================

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    salt: str = Field(..., description="Base64 encoded 16-byte random salt")
    auth_hash: str = Field(..., description="Client-derived PBKDF2 auth hash (Hex)")
    public_key_jwk: str = Field(..., description="JSON Web Key string of RSA-OAEP public key")
    encrypted_private_key: str = Field(..., description="JSON string containing {ciphertext, iv} of KEK-encrypted private key")


class UserLoginRequest(BaseModel):
    username: str
    auth_hash: str


class SaltResponse(BaseModel):
    username: str
    salt: str


class PublicKeyResponse(BaseModel):
    username: str
    public_key_jwk: str


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    public_key_jwk: str
    encrypted_private_key: str


class WrappedKeyItem(BaseModel):
    recipient_username: Optional[str] = None
    wrapped_key: str


class FileMetadataResponse(BaseModel):
    file_id: str
    owner_id: str
    owner_username: str
    iv: str
    encrypted_metadata: str
    file_size: int
    created_at: datetime
    wrapped_key_for_me: Optional[str] = None
    shared_users: List[str] = []


class VaultFileItem(BaseModel):
    file_id: str
    owner_id: str
    owner_username: str
    iv: str
    encrypted_metadata: str
    file_size: int
    created_at: datetime
    wrapped_key: str
    shared_with: List[str] = []
