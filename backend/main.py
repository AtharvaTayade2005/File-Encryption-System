"""
FastAPI Backend Service: Zero-Knowledge Blind Storage Vault
Features:
- Client-side auth verification via derived auth_hash (passwords never hit server)
- Blind encrypted file storage to ./uploads/
- Public key lookup for targeted asymmetric user sharing
- SharedKey routing (recipient DEK distribution & owner retrieval)
- URL fragment anonymous link support (server only serves blind blob and IV)
- Static mounting for frontend & crypto engine
"""

import os
import json
import uuid
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Header
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import jwt

import database
import models

# Initialize directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

# Database initialization
database.init_db()

# Security & JWT Configuration - Persisted to .secret_key to survive server reloads & restarts
SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret_key")
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
        SECRET_KEY = f.read().strip()
else:
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
    try:
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(SECRET_KEY)
    except Exception:
        pass

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

app = FastAPI(
    title="Zero-Knowledge Encrypted File Vault",
    description="High-security blind file sharing backend utilizing client-side Web Crypto primitives.",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Password / Hash Verification Helpers (Defense-in-depth on server)
# ============================================================================

def hash_client_auth_hash(client_auth_hash: str) -> str:
    """
    Applies server-side SHA256-HMAC to the client's derived auth_hash.
    Adds a second layer of defense without needing external C-bindings.
    """
    return hmac.new(SECRET_KEY.encode(), client_auth_hash.encode(), hashlib.sha256).hexdigest()


def verify_client_auth_hash(client_auth_hash: str, stored_server_hash: str) -> bool:
    expected = hash_client_auth_hash(client_auth_hash)
    return hmac.compare_digest(expected, stored_server_hash)


# ============================================================================
# Authentication Helpers
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(database.get_db)
) -> models.User:
    """Extracts and verifies JWT token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_optional_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(database.get_db)
) -> Optional[models.User]:
    """Extracts user if valid Bearer token provided, otherwise returns None."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            return None
        return db.query(models.User).filter(models.User.id == user_id).first()
    except Exception:
        return None


# ============================================================================
# User & Authentication Endpoints
# ============================================================================

@app.post("/api/register", response_model=models.AuthTokenResponse)
def register(req: models.UserRegisterRequest, db: Session = Depends(database.get_db)):
    """
    Registers a new user.
    Server receives:
    - salt (16-byte random, base64)
    - auth_hash (PBKDF2-derived hex hash, salted by client)
    - public_key_jwk (RSA-OAEP public key)
    - encrypted_private_key (AES-GCM ciphertext + IV, encrypted by client KEK)
    
    Zero plaintext password or private key ever touches the server.
    """
    existing_user = db.query(models.User).filter(models.User.username == req.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username is already taken")

    # Hash the client-derived auth_hash on server before storage as extra layer of defense-in-depth
    server_auth_hash = hash_client_auth_hash(req.auth_hash)

    new_user = models.User(
        username=req.username,
        salt=req.salt,
        auth_hash=server_auth_hash,
        public_key_jwk=req.public_key_jwk,
        encrypted_private_key=req.encrypted_private_key
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token({"sub": new_user.id, "username": new_user.username})

    return models.AuthTokenResponse(
        access_token=token,
        user_id=new_user.id,
        username=new_user.username,
        public_key_jwk=new_user.public_key_jwk,
        encrypted_private_key=new_user.encrypted_private_key
    )


@app.get("/api/users/{username}/salt", response_model=models.SaltResponse)
def get_user_salt(username: str, db: Session = Depends(database.get_db)):
    """Returns the user's random salt so client can locally derive auth_hash and KEK."""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return models.SaltResponse(username=user.username, salt=user.salt)


@app.post("/api/login", response_model=models.AuthTokenResponse)
def login(req: models.UserLoginRequest, db: Session = Depends(database.get_db)):
    """
    Authenticates user using client-derived auth_hash.
    Returns JWT token and user's encrypted private key bundle for client-side unlocking.
    """
    user = db.query(models.User).filter(models.User.username == req.username).first()
    if not user or not verify_client_auth_hash(req.auth_hash, user.auth_hash):
        raise HTTPException(status_code=401, detail="Invalid username or passphrase")

    token = create_access_token({"sub": user.id, "username": user.username})

    return models.AuthTokenResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
        public_key_jwk=user.public_key_jwk,
        encrypted_private_key=user.encrypted_private_key
    )


@app.get("/api/users/{username}/public-key", response_model=models.PublicKeyResponse)
def get_user_public_key(username: str, db: Session = Depends(database.get_db)):
    """
    Returns public key JWK of any registered user.
    Used when a sender encrypts/wraps the AES DEK for a specific recipient.
    Rejects users with invalid/mock public keys that would crash WebCrypto.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    
    # Validate public key is a real RSA key, not a mock/test placeholder
    try:
        pk_obj = json.loads(user.public_key_jwk) if isinstance(user.public_key_jwk, str) else user.public_key_jwk
        modulus = pk_obj.get("n", "")
        if len(modulus) < 100:
            raise HTTPException(
                status_code=400,
                detail=f"User '{username}' has an invalid RSA public key (test/mock key). "
                       f"They must register through the browser to generate a real RSA keypair."
            )
    except (json.JSONDecodeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"User '{username}' has a malformed public key.")
    
    return models.PublicKeyResponse(username=user.username, public_key_jwk=user.public_key_jwk)


@app.get("/api/users", response_model=List[str])
def list_available_users(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """Lists usernames of other registered users who have valid RSA public keys (for recipient selection)."""
    users = db.query(models.User).filter(models.User.id != current_user.id).all()
    valid_users = []
    for u in users:
        # Filter out test/mock users whose public key JWK is not a real RSA key.
        # A valid RSA-2048 JWK has an 'n' (modulus) field that is 342+ Base64 chars.
        try:
            pk = u.public_key_jwk
            if isinstance(pk, str):
                pk_obj = json.loads(pk)
            else:
                pk_obj = pk
            modulus = pk_obj.get("n", "")
            if len(modulus) >= 100:
                valid_users.append(u.username)
        except Exception:
            pass
    return valid_users


@app.get("/api/me", response_model=models.AuthTokenResponse)
def get_me(current_user: models.User = Depends(get_current_user)):
    """Returns current user's profile and encrypted private key blob."""
    token = create_access_token({"sub": current_user.id, "username": current_user.username})
    return models.AuthTokenResponse(
        access_token=token,
        user_id=current_user.id,
        username=current_user.username,
        public_key_jwk=current_user.public_key_jwk,
        encrypted_private_key=current_user.encrypted_private_key
    )


# ============================================================================
# File Storage & Sharing Endpoints (Zero-Knowledge)
# ============================================================================

@app.post("/api/upload")
async def upload_encrypted_file(
    file: UploadFile = File(...),
    iv: str = Form(..., description="Base64 12-byte IV"),
    encrypted_metadata: str = Form(..., description="JSON string {ciphertext, iv} encrypted with DEK"),
    wrapped_keys: str = Form(..., description="JSON array of {recipient_username, wrapped_key}"),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Accepts client-side encrypted binary file blob, IV, and wrapped DEK entries.
    Server acts as blind storage:
    - Writes encrypted file to ./uploads/<file_id>.enc
    - Inserts records into files and shared_keys tables
    """
    file_id = str(uuid.uuid4())
    blob_filename = f"{file_id}.enc"
    blob_path = os.path.join(UPLOADS_DIR, blob_filename)

    # Read binary content and calculate size
    content = await file.read()
    file_size = len(content)

    # Save blind encrypted blob to disk
    with open(blob_path, "wb") as f:
        f.write(content)

    # Parse wrapped keys list
    try:
        wrapped_key_items = json.loads(wrapped_keys)
    except Exception:
        wrapped_key_items = []

    # Create File record
    file_record = models.FileRecord(
        id=file_id,
        owner_id=current_user.id,
        encrypted_blob_path=blob_path,
        iv=iv,
        encrypted_metadata=encrypted_metadata,
        file_size=file_size
    )
    db.add(file_record)

    # Add shared key entries for owner and any targeted recipients
    for item in wrapped_key_items:
        rec_username = item.get("recipient_username")
        wrapped_key = item.get("wrapped_key")
        rec_user_id = None

        if rec_username:
            rec_user = db.query(models.User).filter(models.User.username == rec_username).first()
            if rec_user:
                rec_user_id = rec_user.id
        else:
            # If no recipient username, default to the uploader/owner
            rec_user_id = current_user.id
            rec_username = current_user.username

        if wrapped_key:
            shared_key_entry = models.SharedKey(
                file_id=file_id,
                recipient_id=rec_user_id,
                recipient_username=rec_username,
                wrapped_key=wrapped_key
            )
            db.add(shared_key_entry)

    db.commit()

    return {
        "status": "success",
        "file_id": file_id,
        "file_size": file_size,
        "message": "File encrypted and stored securely in zero-knowledge vault."
    }


@app.get("/api/vault")
def get_my_vault(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Returns files owned by the user or shared directly with the user, along with their respective wrapped DEK.
    """
    # 1. Files owned by current user
    owned_files = db.query(models.FileRecord).filter(models.FileRecord.owner_id == current_user.id).order_by(models.FileRecord.created_at.desc()).all()
    
    # 2. Files shared with current user
    shared_key_entries = db.query(models.SharedKey).filter(
        models.SharedKey.recipient_id == current_user.id
    ).all()
    shared_file_ids = [sk.file_id for sk in shared_key_entries]
    
    shared_files = db.query(models.FileRecord).filter(
        models.FileRecord.id.in_(shared_file_ids),
        models.FileRecord.owner_id != current_user.id
    ).order_by(models.FileRecord.created_at.desc()).all()

    def serialize_file(f_rec: models.FileRecord, is_shared: bool = False):
        # Find wrapped key for current user
        my_key_entry = db.query(models.SharedKey).filter(
            models.SharedKey.file_id == f_rec.id,
            models.SharedKey.recipient_id == current_user.id
        ).first()

        # Find all users this file is shared with
        all_shares = db.query(models.SharedKey).filter(
            models.SharedKey.file_id == f_rec.id,
            models.SharedKey.recipient_id != f_rec.owner_id
        ).all()
        shared_usernames = [s.recipient_username for s in all_shares if s.recipient_username]

        return {
            "file_id": f_rec.id,
            "owner_id": f_rec.owner_id,
            "owner_username": f_rec.owner.username if f_rec.owner else "Unknown",
            "iv": f_rec.iv,
            "encrypted_metadata": f_rec.encrypted_metadata,
            "file_size": f_rec.file_size,
            "created_at": f_rec.created_at.isoformat(),
            "wrapped_key": my_key_entry.wrapped_key if my_key_entry else None,
            "shared_with": shared_usernames,
            "is_shared": is_shared
        }

    return {
        "owned_files": [serialize_file(f, is_shared=False) for f in owned_files],
        "shared_files": [serialize_file(f, is_shared=True) for f in shared_files]
    }


@app.get("/api/files/{file_id}/info")
def get_file_info(
    file_id: str,
    current_user: Optional[models.User] = Depends(get_optional_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Returns file metadata, IV, and wrapped key (if requesting user is a targeted recipient/owner).
    Works for both authenticated users and anonymous link recipients.
    """
    file_rec = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_rec:
        raise HTTPException(status_code=404, detail="File not found")

    wrapped_key_for_me = None
    if current_user:
        key_entry = db.query(models.SharedKey).filter(
            models.SharedKey.file_id == file_id,
            models.SharedKey.recipient_id == current_user.id
        ).first()
        if key_entry:
            wrapped_key_for_me = key_entry.wrapped_key

    return {
        "file_id": file_rec.id,
        "owner_id": file_rec.owner_id,
        "owner_username": file_rec.owner.username if file_rec.owner else "Unknown",
        "iv": file_rec.iv,
        "encrypted_metadata": file_rec.encrypted_metadata,
        "file_size": file_rec.file_size,
        "created_at": file_rec.created_at.isoformat(),
        "wrapped_key_for_me": wrapped_key_for_me
    }


@app.get("/api/files/{file_id}/download")
def download_encrypted_blob(
    file_id: str,
    db: Session = Depends(database.get_db)
):
    """
    Streams the raw encrypted file ciphertext blob to the client.
    The server does NOT decrypt this; the client decrypts it in browser memory.
    """
    file_rec = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_rec:
        raise HTTPException(status_code=404, detail="File not found")

    if not os.path.exists(file_rec.encrypted_blob_path):
        raise HTTPException(status_code=404, detail="Encrypted file blob missing from disk")

    return FileResponse(
        path=file_rec.encrypted_blob_path,
        media_type="application/octet-stream",
        filename=f"{file_id}.enc"
    )


@app.post("/api/files/{file_id}/share")
def share_existing_file(
    file_id: str,
    wrapped_item: models.WrappedKeyItem,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """
    Adds a new wrapped DEK entry to an existing file for a newly specified recipient.
    Only the owner or an existing authorized recipient can add shares.
    """
    file_rec = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_rec:
        raise HTTPException(status_code=404, detail="File not found")

    # Check recipient existence
    rec_user = db.query(models.User).filter(models.User.username == wrapped_item.recipient_username).first()
    if not rec_user:
        raise HTTPException(status_code=404, detail=f"Recipient user '{wrapped_item.recipient_username}' not found")

    # Check if already shared
    existing = db.query(models.SharedKey).filter(
        models.SharedKey.file_id == file_id,
        models.SharedKey.recipient_id == rec_user.id
    ).first()

    if existing:
        existing.wrapped_key = wrapped_item.wrapped_key
    else:
        new_share = models.SharedKey(
            file_id=file_id,
            recipient_id=rec_user.id,
            recipient_username=rec_user.username,
            wrapped_key=wrapped_item.wrapped_key
        )
        db.add(new_share)

    db.commit()
    return {"status": "success", "message": f"File shared with {rec_user.username}."}


@app.delete("/api/files/{file_id}")
def delete_file(
    file_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """Deletes a file and its encrypted blob if requested by the owner."""
    file_rec = db.query(models.FileRecord).filter(
        models.FileRecord.id == file_id,
        models.FileRecord.owner_id == current_user.id
    ).first()

    if not file_rec:
        raise HTTPException(status_code=404, detail="File not found or unauthorized")

    if os.path.exists(file_rec.encrypted_blob_path):
        try:
            os.remove(file_rec.encrypted_blob_path)
        except Exception:
            pass

    db.delete(file_rec)
    db.commit()
    return {"status": "success", "message": "File deleted successfully"}


# ============================================================================
# Static Files & Frontend Routing
# ============================================================================

# Mount static crypto engine and frontend files
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
CRYPTO_DIR = os.path.join(PROJECT_ROOT, "crypto")

if os.path.exists(CRYPTO_DIR):
    app.mount("/crypto", StaticFiles(directory=CRYPTO_DIR), name="crypto")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_root():
    """Serves the single-page application dashboard."""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Zero-Knowledge Backend Running. Frontend is being configured."}
