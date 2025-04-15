import os
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, JSON, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from passlib.context import CryptContext
import uvicorn
import jwt
import httpx

# Constants for JWT
SECRET_KEY = "your_secret_key"  # Replace with a strong key for your application.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Configuration
DATABASE_URL = "sqlite:///./permit_simulation.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# FastAPI Instance
app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password Context for Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Token Handling
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User Database Model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)

# Data Models
class JurisdictionData(Base):
    __tablename__ = "jurisdictions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    code = Column(String, unique=True, index=True)
    approval_rate = Column(Float)
    average_time_weeks = Column(Float)
    resubmission_rate = Column(Float)
    compliance_factors = Column(JSON)

class ProjectType(Base):
    __tablename__ = "project_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    base_approval_modifier = Column(Float)
    base_timeline_modifier = Column(Float)
    required_documents = Column(JSON)
    common_issues = Column(JSON)

class PermitType(Base):
    __tablename__ = "permit_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    base_approval_modifier = Column(Float)
    base_timeline_modifier = Column(Float)
    required_documents = Column(JSON)
    compliance_requirements = Column(JSON)

class SimulationResult(Base):
    __tablename__ = "simulation_results"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer)
    project_name = Column(String)
    jurisdiction_id = Column(Integer)
    project_type_id = Column(Integer)
    permit_type_id = Column(Integer)
    approval_likelihood = Column(Float)
    timeline_weeks = Column(JSON)
    compliance_scores = Column(JSON)
    recommendations = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    blockchain_verified = Column(Boolean, default=False)
    blockchain_data = Column(JSON)

class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer)
    name = Column(String)
    description = Column(Text)
    status = Column(String)
    upload_date = Column(DateTime, default=datetime.utcnow)
    review_date = Column(DateTime)
    file_type = Column(String)
    file_size = Column(Integer)
    url = Column(String)
    comments = Column(Text)
    required = Column(Boolean, default=False)

# Pydantic Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserInDB(UserCreate):
    id: int

class UserOut(BaseModel):
    id: int
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class JurisdictionDataSchema(BaseModel):
    id: int
    name: str
    code: str
    approval_rate: float
    average_time_weeks: float
    resubmission_rate: float
    compliance_factors: Dict

class ProjectTypeSchema(BaseModel):
    id: int
    name: str
    base_approval_modifier: float
    base_timeline_modifier: float
    required_documents: List[str]
    common_issues: List[str]

class PermitTypeSchema(BaseModel):
    id: int
    name: str
    base_approval_modifier: float
    base_timeline_modifier: float
    required_documents: List[str]
    compliance_requirements: Dict

class SimulationResultSchema(BaseModel):
    id: int
    project_id: int
    project_name: str
    jurisdiction_id: int
    project_type_id: int
    permit_type_id: int
    approval_likelihood: float
    timeline_weeks: List[int]
    compliance_scores: Dict
    recommendations: List[str]
    created_at: datetime
    blockchain_verified: bool
    blockchain_data: Dict

class DocumentSchema(BaseModel):
    id: int
    project_id: int
    name: str
    description: str
    status: str
    upload_date: datetime
    review_date: Optional[datetime]
    file_type: str
    file_size: int
    url: str
    comments: str
    required: bool

# Dependency for Database Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User Authentication Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# OAuth2 Token Endpoint
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Protected User Route
@app.get("/users/me", response_model=UserOut)
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Root Endpoint
@app.get("/")
def read_root():
    return {"Hello": "World", "API": "Permit Simulation"}

# Create the Database Tables
Base.metadata.create_all(bind=engine)

# API Endpoints for Jurisdictions
@app.get("/api/jurisdictions", response_model=List[JurisdictionDataSchema])
def read_jurisdictions(db: Session = Depends(get_db)):
    return db.query(JurisdictionData).all()

@app.get("/api/jurisdictions/{id}", response_model=JurisdictionDataSchema)
def read_jurisdiction(id: int, db: Session = Depends(get_db)):
    jurisdiction = db.query(JurisdictionData).filter(JurisdictionData.id == id).first()
    if jurisdiction is None:
        raise HTTPException(status_code=404, detail="Jurisdiction not found")
    return jurisdiction

# Project Types API Endpoints
@app.get("/api/project-types", response_model=List[ProjectTypeSchema])
def read_project_types(db: Session = Depends(get_db)):
    return db.query(ProjectType).all()

@app.get("/api/project-types/{id}", response_model=ProjectTypeSchema)
def read_project_type(id: int, db: Session = Depends(get_db)):
    project_type = db.query(ProjectType).filter(ProjectType.id == id).first()
    if project_type is None:
        raise HTTPException(status_code=404, detail="Project Type not found")
    return project_type

# Permit Types API Endpoints
@app.get("/api/permit-types", response_model=List[PermitTypeSchema])
def read_permit_types(db: Session = Depends(get_db)):
    return db.query(PermitType).all()

@app.get("/api/permit-types/{id}", response_model=PermitTypeSchema)
def read_permit_type(id: int, db: Session = Depends(get_db)):
    permit_type = db.query(PermitType).filter(PermitType.id == id).first()
    if permit_type is None:
        raise HTTPException(status_code=404, detail="Permit Type not found")
    return permit_type

# Simulation API Endpoint
@app.post("/api/simulations", response_model=SimulationResultSchema)
def create_simulation(project_id: int, project_type_id: int, permit_type_id: int, db: Session = Depends(get_db)):
    # Simplified Simulation Logic
    jurisdiction = db.query(JurisdictionData).filter(JurisdictionData.id == project_id).first()
    if jurisdiction is None:
        raise HTTPException(status_code=404, detail="Jurisdiction not found")
    
    project_type = db.query(ProjectType).filter(ProjectType.id == project_type_id).first()
    if project_type is None:
        raise HTTPException(status_code=404, detail="Project Type not found")

    permit_type = db.query(PermitType).filter(PermitType.id == permit_type_id).first()
    if permit_type is None:
        raise HTTPException(status_code=404, detail="Permit Type not found")

    # Example calculations for approval likelihood and timeline
    approval_likelihood = jurisdiction.approval_rate * project_type.base_approval_modifier
    average_time = jurisdiction.average_time_weeks + project_type.base_timeline_modifier
    timeline_weeks = list(range(int(average_time) - 2, int(average_time) + 3))  # +/- 2 weeks variance

    simulation_result = SimulationResult(
        project_id=project_id,
        project_name="Example Project",  # Placeholder name
        jurisdiction_id=jurisdiction.id,
        project_type_id=project_type.id,
        permit_type_id=permit_type.id,
        approval_likelihood=approval_likelihood,
        timeline_weeks=timeline_weeks,
        compliance_scores={"Compliance Factor 1": 80},
        recommendations=["Make sure all compliance factors are addressed."],
        created_at=datetime.utcnow(),
        blockchain_verified=False,
        blockchain_data={"tx_hash": str(uuid.uuid4())}
    )
    
    db.add(simulation_result)
    db.commit()
    db.refresh(simulation_result)
    return simulation_result

@app.get("/api/simulations", response_model=List[SimulationResultSchema])
def read_simulations(db: Session = Depends(get_db)):
    return db.query(SimulationResult).order_by(SimulationResult.created_at.desc()).all()

@app.get("/api/simulations/{id}", response_model=SimulationResultSchema)
def read_simulation(id: int, db: Session = Depends(get_db)):
    simulation = db.query(SimulationResult).filter(SimulationResult.id == id).first()
    if simulation is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return simulation

# Document Management Endpoints
@app.post("/api/projects/{project_id}/documents", response_model=DocumentSchema)
def upload_document(project_id: int, file: UploadFile = File(...), description: str = "", db: Session = Depends(get_db)):
    document_url = f"/files/{file.filename}"
    
    # Simulate file size and store document metadata
    document = Document(
        project_id=project_id,
        name=file.filename,
        description=description,
        status="uploaded",
        upload_date=datetime.utcnow(),
        review_date=None,
        file_type=file.content_type,
        file_size=len(file.file.read()),  # Get the size of the contents
        url=document_url,
        comments="No comments",
        required=False
    )
    db.add(document)
    db.commit()
    db.refresh(document)
    
    return document

@app.get("/api/projects/{project_id}/documents", response_model=List[DocumentSchema])
def read_project_documents(project_id: int, db: Session = Depends(get_db)):
    documents = db.query(Document).filter(Document.project_id == project_id).all()
    return documents

@app.delete("/api/projects/{project_id}/documents/{document_id}", response_model=dict)
def delete_document(project_id: int, document_id: int, db: Session = Depends(get_db)):
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    db.delete(document)
    db.commit()
    return {"detail": "Document deleted"}

@app.get("/api/documents/{document_id}", response_model=DocumentSchema)
def read_document(document_id: int, db: Session = Depends(get_db)):
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document

@app.get("/api/simulations/{simulation_id}/missing-documents", response_model=List[str])
def get_missing_documents(simulation_id: int, db: Session = Depends(get_db)):
    # Placeholder implementation for missing documents
    return ["Missing Document 1", "Missing Document 2"]

# Connect to Gemini API
GEMINI_API_KEY = "AIzaSyB5PweKFL-g04z8BAuF6PImMg1hxr07Zk4"
GEMINI_BASE_URL = "https://api.gemini.com/v1"

# Dependency to get the HTTP client
async def get_http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as client:
        yield client

@app.get("/api/gemini/marketdata")
async def get_market_data(client: httpx.AsyncClient = Depends(get_http_client)):
    headers = {
        "Content-Type": "application/json",
        "X-GEMINI-APIKEY": GEMINI_API_KEY,
    }
    try:
        # Example market data retrieval for BTC/USD
        response = await client.get(f"{GEMINI_BASE_URL}/pubticker/btcusd", headers=headers)
        response.raise_for_status()  # Raise error for bad responses
        return response.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Error fetching market data")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Run the application
if __name__ == "__main__":
    # Create the database tables if they do not exist
    if not os.path.exists("permit_simulation.db"):
        Base.metadata.create_all(bind=engine)

    uvicorn.run(app, host="0.0.0.0", port=8000)
