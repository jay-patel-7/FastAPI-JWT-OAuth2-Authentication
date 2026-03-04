from fastapi import FastAPI, status, HTTPException, Path
from typing import Optional
from pydantic import BaseModel

app = FastAPI()

users = {
    1: {
       "name": "John Doe",
       "website": "https://www.john.com",
       "age": 25,
       "role": "admin"
    },
    2: {
       "name": "Jane Doe",
       "website": "https://www.jane.com",
       "age": 26,
       "role": "user"
    }
}

class User(BaseModel):
    name: str
    website: str
    age: int
    role: str

class UpdateUser(BaseModel):
    name: Optional[str] = None
    website: Optional[str] = None
    age: Optional[int] = None
    role: Optional[str] = None

@app.get("/")
def root():
    return "message"

@app.get("/users/{user_id}")
def get_user(user_id: int = Path(..., description="The ID of the user", gt=0, lt=100)):
    if user_id not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return users[user_id]

@app.post("/users/{user_id}", status_code=status.HTTP_201_CREATED)
def create_user(user_id: int, user: User):
    if user_id in users:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    
    users[user_id] = user.model_dump()
    return user

@app.put("/users/{user_id}")
def update_user(user_id: int, user: UpdateUser):
    if user_id not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.name is not None:
        users[user_id]["name"] = user.name
    if user.website is not None:
        users[user_id]["website"] = user.website
    if user.age is not None:
        users[user_id]["age"] = user.age
    if user.role is not None:
        users[user_id]["role"] = user.role

    return users[user_id]

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    if user_id not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    del_user = users.pop(user_id)

    return {"message": f"User {del_user['name']} deleted"}


@app.get("/users/search/")
def search_user(name: Optional[str] = None):
    if name is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name is required")
    
    for user in users.values():
        if user["name"] == name:
            return user
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")