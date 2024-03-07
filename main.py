from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# Secret key for encoding and decoding JWT tokens
SECRET_KEY = "4d842fb85af9d2d9cc60ac41132e5287c6b2fc01685eedab590278f03cb649de"
# Algorithm used for encoding and decoding JWT tokens
ALGORITHM = "HS256"
# Token expiration time in minutes
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Fake user database for demonstration purposes
fake_users_db = {
    "sullivan": {
        "username": "sullivan",
        "full_name": "sullivan code",
        "email": "sullivan@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


# Pydantic model for the token response
class Token(BaseModel):
    access_token: str
    token_type: str


# Pydantic model for token data
class TokenData(BaseModel):
    username: str | None = None


# Pydantic model for user input during registration
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


# Pydantic model for user details
class User(BaseModel):
    username: str
    email: Optional[str]
    full_name: Optional[str]
    disabled: Optional[bool]


# Pydantic model for user details stored in the database
class UserInDB(User):
    hashed_password: str


# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI application instance
app = FastAPI()


# Function to verify the password against the hashed password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Function to hash the password
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# Function to get user details from the fake database
def get_user(db: dict, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


# Function to authenticate a user based on username and password
def authenticate_user(db: dict, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(db, username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None


# Function to create an access token
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to get the current user based on the provided token
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# Dependency to get the current active user
async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Endpoint to generate an access token
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# Endpoint to get the details of the current user
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> User:
    return current_user


# Endpoint to get the items owned by the current user
@app.get("/users/me/items/")
async def read_own_items(
    current_user: User = Depends(get_current_active_user),
) -> list[dict]:
    return [{"item_id": "Foo", "owner": current_user.username}]
