import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# App and CORS
app = FastAPI(title="Comic Reader API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Utilities

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def oid(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    return obj


def serialize_doc(doc: dict):
    if not doc:
        return doc
    out = {}
    for k, v in doc.items():
        if k == "_id":
            out["id"] = str(v)
        elif isinstance(v, ObjectId):
            out[k] = str(v)
        else:
            out[k] = v
    return out


# Models
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

# Dependencies
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)

# Routes
@app.get("/")
def root():
    return {"message": "Comic Reader API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", "unknown")
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response

# Auth endpoints
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(result.inserted_id)})
    return TokenResponse(access_token=token)

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)

@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    # In real app, send email with token. Here we just acknowledge.
    return {"message": "If the account exists, a reset link was sent to the email."}

@app.get("/me")
def me(user=Depends(get_current_user)):
    return user

# Comics endpoints
@app.get("/comics")
def list_comics(search: Optional[str] = None, genre: Optional[str] = None, limit: int = 24, page: int = 1):
    query = {}
    if search:
        query["title"] = {"$regex": search, "$options": "i"}
    if genre:
        query["genres"] = {"$in": [genre]}
    cursor = db["comic"].find(query).sort("created_at", -1).skip(max(0, (page-1)*limit)).limit(limit)
    return [serialize_doc(c) for c in cursor]

@app.get("/comics/latest")
def latest_comics(limit: int = 12):
    cursor = db["comic"].find({}).sort("created_at", -1).limit(limit)
    return [serialize_doc(c) for c in cursor]

@app.get("/comics/{comic_id}")
def get_comic(comic_id: str):
    try:
        comic = db["comic"].find_one({"_id": ObjectId(comic_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    if not comic:
        raise HTTPException(status_code=404, detail="Comic not found")
    comic = serialize_doc(comic)
    chapters = db["chapter"].find({"comic_id": comic["id"]}).sort("number", -1)
    comic["chapters"] = [serialize_doc(c) for c in chapters]
    return comic

@app.get("/comics/{comic_id}/chapters")
def get_chapters(comic_id: str):
    chapters = db["chapter"].find({"comic_id": comic_id}).sort("number", -1)
    return [serialize_doc(c) for c in chapters]

@app.get("/chapters/{chapter_id}")
def get_chapter(chapter_id: str):
    try:
        ch = db["chapter"].find_one({"_id": ObjectId(chapter_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    if not ch:
        raise HTTPException(status_code=404, detail="Chapter not found")
    return serialize_doc(ch)

# Bookmarks
@app.get("/bookmarks")
def get_bookmarks(user=Depends(get_current_user)):
    items = db["bookmark"].find({"user_id": user["id"]})
    comics_ids = [i.get("comic_id") for i in items]
    comics = db["comic"].find({"_id": {"$in": [ObjectId(i) for i in comics_ids if i]}})
    return [serialize_doc(c) for c in comics]

@app.post("/bookmarks/{comic_id}")
def add_bookmark(comic_id: str, user=Depends(get_current_user)):
    exists = db["bookmark"].find_one({"user_id": user["id"], "comic_id": comic_id})
    if exists:
        return {"message": "Already bookmarked"}
    db["bookmark"].insert_one({
        "user_id": user["id"],
        "comic_id": comic_id,
        "created_at": datetime.now(timezone.utc)
    })
    return {"message": "Bookmarked"}

@app.delete("/bookmarks/{comic_id}")
def remove_bookmark(comic_id: str, user=Depends(get_current_user)):
    db["bookmark"].delete_one({"user_id": user["id"], "comic_id": comic_id})
    return {"message": "Removed"}

# Reading History
@app.get("/history")
def get_history(user=Depends(get_current_user)):
    items = db["history"].find({"user_id": user["id"]}).sort("updated_at", -1).limit(100)
    return [serialize_doc(i) for i in items]

class HistoryPayload(BaseModel):
    comic_id: str
    chapter_id: Optional[str] = None
    last_read_page: Optional[int] = 0

@app.post("/history")
def add_history(payload: HistoryPayload, user=Depends(get_current_user)):
    db["history"].update_one(
        {"user_id": user["id"], "comic_id": payload.comic_id},
        {"$set": {
            "user_id": user["id"],
            "comic_id": payload.comic_id,
            "chapter_id": payload.chapter_id,
            "last_read_page": payload.last_read_page,
            "updated_at": datetime.now(timezone.utc)
        }, "$setOnInsert": {"created_at": datetime.now(timezone.utc)}},
        upsert=True
    )
    return {"message": "History updated"}

# Seed endpoint (optional, to create sample comics if empty)
@app.post("/seed")
def seed():
    count = db["comic"].count_documents({})
    if count > 0:
        return {"message": "Already seeded"}
    sample = [
        {
            "title": "Minty Adventures",
            "author": "A. Artist",
            "genres": ["Adventure", "Comedy"],
            "synopsis": "A breezy tale through mint-green valleys.",
            "cover_url": "https://images.unsplash.com/photo-1549880338-65ddcdfd017b?w=800&auto=format&fit=crop&q=60",
            "rating": 4.5,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "title": "Cloud City",
            "author": "B. Brush",
            "genres": ["Sci-Fi"],
            "synopsis": "Life among whimsical comic clouds.",
            "cover_url": "https://images.unsplash.com/photo-1526318472351-c75fcf070305?w=800&auto=format&fit=crop&q=60",
            "rating": 4.2,
            "created_at": datetime.now(timezone.utc)
        },
    ]
    ids = db["comic"].insert_many(sample).inserted_ids
    # chapters
    for i, cid in enumerate(ids):
        db["chapter"].insert_many([
            {
                "comic_id": str(cid),
                "title": "Chapter 1",
                "number": 1,
                "images": [
                    "https://picsum.photos/seed/{}-1/900/1300".format(i),
                    "https://picsum.photos/seed/{}-2/900/1300".format(i),
                    "https://picsum.photos/seed/{}-3/900/1300".format(i),
                ],
                "created_at": datetime.now(timezone.utc)
            }
        ])
    return {"message": "Seeded", "count": len(ids)}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
