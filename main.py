import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from datetime import timedelta
from schemas import Token, UserCreate, User
from auth import (
    get_password_hash,
    get_current_user,
    authenticate_user,
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
import models
from mailchimp_marketing import Client
from mailchimp_marketing.api_client import ApiClientError
from database import db_dependency
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

CLICKUP_API_URL = "https://api.clickup.com/api/v2"
CLICKUP_API_TOKEN = os.getenv("CLICKUP_API_TOKEN")
CLICKUP_API_LIST_ID = os.getenv("CLICKUP_API_LIST_ID")


async def create_task_clickup(username: str, user_id: int):
    headers = {
        "Authorization": CLICKUP_API_TOKEN,
        "Content-Type": "application/json"
    }

    task_info = {
        "name": f"Onboarding of new user: {username}, {user_id}",
        "description": "Welcome user and onboard him to the project."
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{CLICKUP_API_URL}/list/{CLICKUP_API_LIST_ID}/task", headers=headers, json=task_info)
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unsuccessful ClickUp task creation")

mailchimp = Client()
mailchimp.set_config({
  "api_key": os.getenv("MAILCHIMP_API_KEY"),
  "server": "us22"
})

mailchimp_audience = {
    "name": "new users",
    "contact": {
        "company": "Mailchimp",
        "address1": "405 N Angier Ave NE",
        "city": "Atlanta",
        "state": "GA",
        "zip": "30308",
        "country": "US"
    },
    "permission_reminder": "you are subscribed to our mailing list",
    "email_type_option": True,
    "campaign_defaults": {
        "from_name": "Inmind training app",
        "from_email": "lmoujaess123@hotmail.com",
        "subject": "Welcome to Inmind training app!",
        "language": "english"
    }
}


async def send_welcome_email(email: str):
    contact_info = {
        "email_address": email,
        "status": "subscribed",
        "merge_fields": {
            "ADDRESS": {
                "addr1": "123 Freddie Ave",
                "city": "Atlanta",
                "state": "GA",
                "zip": "12345",
            }
        }
    }

    try:
        # retrieve list_id
        get_list_response = mailchimp.lists.get_all_lists()
        list_id = get_list_response['lists'][0]['id']
        # add new user as a contact to the list
        mailchimp.lists.add_list_member(list_id, contact_info)
        # create welcome email campaign
        settings = {
            "subject_line": "Welcome to Inmind training app!",
            "title": "Welcome email",
            "preview_text": "We would like to wish you a warm welcome.",
            "from_name": "Inmind training app",
            "reply_to": "lmoujaess123@hotmail.com",
        }
        campaign_creation_response = mailchimp.campaigns.create({"type": "regular", "recipients": {"list_id": list_id}, "settings": settings, "content_type": "template"})
        campaign_id = campaign_creation_response.get('id')
        campaign_content = {
            "plain_text": "Thank you for joining us! We are happy to have you on board.",
            "html": "<h1>Welcome to Inmind Training App!</h1><p>Thank you for joining us! We are excited to have you on board.</p>"
        }
        mailchimp.campaigns.set_content(campaign_id, campaign_content)
        # send campaign
        mailchimp.campaigns.send(campaign_id)
    except ApiClientError as error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error: {error.text}")


@app.post("/signup")
async def signup(user: UserCreate, db: db_dependency):
    existing_user = db.query(models.Users).filter(models.Users.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    hashed_password = get_password_hash(user.plain_password)
    new_user = models.Users(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    await create_task_clickup(new_user.username, new_user.id)
    await send_welcome_email(new_user.email)
    return {"message": "Successful user and clickup task creation."}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
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


@app.get("/users/me/")
async def users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

