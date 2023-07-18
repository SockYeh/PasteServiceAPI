from fastapi import FastAPI, Response, status, Cookie, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json, time, string, datetime
from random import choices
from secrets import token_hex
from typing import Optional
from httpx import AsyncClient


app = FastAPI(docs_url=None, redoc_url=None)
COOKIE_EXPIRE_TIME = 3000
templates = Jinja2Templates(directory="html_files")


class Register(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str


class Login(BaseModel):
    username: str
    password: str


class Paste(BaseModel):
    title: Optional[str]
    content: str
    ttype: str
    expires: int


class Edit(BaseModel):
    title: Optional[str]
    content: str
    type: Optional[str]


@app.get("/api/")
async def root():
    return {"message": "Hello World"}


# ------------------------------ User Auth ------------------------------ #


@app.get("/api/cookie")
async def cookie(auth_token: str = Cookie(None), username: str = Cookie(None)):
    with open("creds.json", "r") as f:
        creds = json.load(f)
    if username not in creds:
        return RedirectResponse(
            url="/api/login", status_code=status.HTTP_401_UNAUTHORIZED
        )

    if auth_token == creds[username]["cookie"]["auth_token"] and creds[username][
        "cookie"
    ]["expires"] > round(time.time()):
        return {"auth_token": auth_token}
    else:
        return {"message": "Cookie expired; please log in again"}


@app.post("/api/login")
async def api_login(
    response: Response,
    form: Login = None,
    username: str = Form(...),
    password: str = Form(...),
):
    if form:
        username = form.username
        password = form.password
    with open("creds.json", "r") as f:
        creds = json.load(f)

    if username not in creds:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "User not found"}

    if creds[username]["password"] != password:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Incorrect password"}

    cook_value = token_hex(16)
    creds[username]["cookie"]["auth_token"] = cook_value
    creds[username]["cookie"]["expires"] = round(time.time()) + COOKIE_EXPIRE_TIME

    with open("creds.json", "w") as f:
        json.dump(creds, f, indent=4)

    response.set_cookie(
        key="auth_token",
        value=cook_value,
        max_age=COOKIE_EXPIRE_TIME,
        expires=COOKIE_EXPIRE_TIME,
    )

    response.set_cookie(key="username", value=username)

    response.status_code = status.HTTP_200_OK
    return {"message": "User logged in successfully"}


@app.post("/api/register")
async def api_register(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...),
    confirm_password: str = Form(...),
    form: Register = None,
):
    if form:
        username = form.username
        password = form.password
        email = form.email
        confirm_password = form.confirm_password

    if password != confirm_password:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "Passwords do not match"}

    cook_value = token_hex(16)

    register_data = {
        "email": email,
        "password": password,
        "cookie": {
            "auth_token": cook_value,
            "max_age": COOKIE_EXPIRE_TIME,
            "expires": round(time.time()) + COOKIE_EXPIRE_TIME,
        },
    }

    with open("creds.json", "r") as f:
        creds = json.load(f)
    if username not in creds:
        creds[username] = register_data
    else:
        response.status_code = status.HTTP_409_CONFLICT
        return {"message": "User already exists"}

    with open("creds.json", "w") as f:
        json.dump(creds, f, indent=4)

    response.set_cookie(
        key="auth_token",
        value=cook_value,
        max_age=COOKIE_EXPIRE_TIME,
        expires=COOKIE_EXPIRE_TIME,
    )
    response.set_cookie(key="username", value=username)

    response.status_code = status.HTTP_201_CREATED
    return {"message": "User registered successfully"}


# ------------------------------ Pasta Logic ------------------------------ #


@app.post("/api/paste")
async def create_paste(
    response: Response,
    title: str = Form(...),
    content: str = Form(...),
    ttype: str = Form(...),
    expires: str = Form(...),
    # form: Paste = None,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    print(response)
    # if form:
    #     title = form.title
    #     content = form.content
    #     type = form.type
    #     expires = form.expires
    with open("creds.json", "r") as f:
        creds = json.load(f)

    if expires == "never":
        expires = 9999999999
    elif expires == "10m":
        expires = 600
    elif expires == "1h":
        expires = 3600

    elif expires == "1d":
        expires = 86400

    elif expires == "7d":
        expires = 604800

    if not (
        auth_token == creds[username]["cookie"]["auth_token"]
        and creds[username]["cookie"]["expires"] > round(time.time())
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Cookie expired; please log in again"}

    with open("pastes.json", "r") as f:
        pastes = json.load(f)

    paste_id = "".join(choices(string.ascii_letters + string.digits, k=8))
    while paste_id in pastes:
        paste_id = "".join(choices(string.ascii_letters + string.digits, k=8))

    pastes[paste_id] = {
        "title": title,
        "content": content,
        "type": ttype,
        "expires_at": str(
            datetime.datetime.fromtimestamp(round(time.time()) + expires)
        ),
        "created_at": str(datetime.datetime.fromtimestamp(round(time.time()))),
        "expires": expires,
        "author": username,
    }
    with open("pastes.json", "w") as f:
        json.dump(pastes, f, indent=4)

    response.status_code = status.HTTP_201_CREATED
    return {"message": "Paste created successfully", "paste_id": paste_id}


@app.delete("/api/paste/{paste_id}")
async def delete_paste(
    response: Response,
    paste_id: str,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    with open("creds.json", "r") as f:
        creds = json.load(f)
    if not (
        auth_token == creds[username]["cookie"]["auth_token"]
        and creds[username]["cookie"]["expires"] > round(time.time())
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Cookie expired; please log in again"}

    with open("pastes.json", "r") as f:
        pastes = json.load(f)

    if paste_id not in pastes:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "Paste not found"}

    paste = pastes[paste_id]

    if datetime.datetime.timestamp(
        datetime.datetime.strptime(
            paste["expires_at"], "%Y-%m-%d %H:%M:%S"
        )  # 2023-07-17 22:10:45
    ) < round(time.time()):
        response.status_code = status.HTTP_404_NOT_FOUND
        pastes.pop(paste_id)
        with open("pastes.json", "w") as f:
            json.dump(pastes, f, indent=4)
        return {"message": "Paste not found"}

    if paste["author"] != username:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": "You are not the author of this paste"}

    pastes.pop(paste_id)

    with open("pastes.json", "w") as f:
        json.dump(pastes, f, indent=4)

    response.status_code = status.HTTP_200_OK
    return {"message": "Paste deleted successfully"}


@app.post("/api/paste/edit/{paste_id}")
async def edit_paste(
    response: Response,
    paste_id: str,
    title=Form(None),
    content=Form(None),
    # form: Edit = None,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    with open("creds.json", "r") as f:
        creds = json.load(f)
    if not (
        auth_token == creds[username]["cookie"]["auth_token"]
        and creds[username]["cookie"]["expires"] > round(time.time())
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Cookie expired; please log in again"}

    with open("pastes.json", "r") as f:
        pastes = json.load(f)

    if paste_id not in pastes:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "Paste not found"}

    paste = pastes[paste_id]

    if datetime.datetime.timestamp(
        datetime.datetime.strptime(
            paste["expires_at"], "%Y-%m-%d %H:%M:%S"
        )  # 2023-07-17 22:10:45
    ) < round(time.time()):
        response.status_code = status.HTTP_404_NOT_FOUND
        pastes.pop(paste_id)
        with open("pastes.json", "w") as f:
            json.dump(pastes, f, indent=4)
        return {"message": "Paste not found"}

    if paste["author"] != username:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": "You are not the author of this paste"}

    paste["content"] = content

    if title:
        paste["title"] = title

    if content == "":
        pastes.pop(paste_id)

    with open("pastes.json", "w") as f:
        json.dump(pastes, f, indent=4)

    response.status_code = status.HTTP_200_OK
    return {"message": "Paste edited successfully"}


@app.get("/api/paste/{paste_id}")
async def get_paste(
    response: Response,
    paste_id: str,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    with open("creds.json", "r") as f:
        creds = json.load(f)
    if not (
        auth_token == creds[username]["cookie"]["auth_token"]
        and creds[username]["cookie"]["expires"] > round(time.time())
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Cookie expired; please log in again"}

    with open("pastes.json", "r") as f:
        pastes = json.load(f)

    if paste_id not in pastes:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "Paste not found"}

    paste_title = pastes[paste_id]["title"]
    paste_content = pastes[paste_id]["content"]
    paste_type = pastes[paste_id]["type"]
    paste_expires_at = pastes[paste_id]["expires_at"]
    paste_expires = pastes[paste_id]["expires"]
    paste_created_at = pastes[paste_id]["created_at"]
    paste_author = pastes[paste_id]["author"]

    if paste_type.lower() == "private" and paste_author != username:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": "Paste is private"}

    if datetime.datetime.timestamp(
        datetime.datetime.strptime(
            paste_expires_at, "%Y-%m-%d %H:%M:%S"
        )  # 2023-07-17 22:10:45
    ) < round(time.time()):
        response.status_code = status.HTTP_404_NOT_FOUND
        pastes.pop(paste_id)
        with open("pastes.json", "w") as f:
            json.dump(pastes, f, indent=4)
        return {"message": "Paste has expired"}

    response.status_code = status.HTTP_200_OK
    return {
        "title": paste_title,
        "content": paste_content,
        "type": paste_type,
        "expires": paste_expires,
        "expires_at": paste_expires_at,
        "created_at": paste_created_at,
        "author": paste_author,
    }


@app.get("/api/pastes")
async def api_paste_list(
    response: Response, auth_token: str = Cookie(None), username: str = Cookie(None)
):
    print(auth_token, username, "hi")
    with open("creds.json", "r") as f:
        creds = json.load(f)
    if not (
        auth_token == creds[username]["cookie"]["auth_token"]
        and creds[username]["cookie"]["expires"] > round(time.time())
    ):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        print("cookie expired")
        return {"message": "Cookie expired; please log in again"}

    with open("pastes.json", "r") as f:
        pastes = json.load(f)
    paste_list = {}
    pts = pastes.copy()
    for paste_id in pts:
        paste = pastes[paste_id]
        if datetime.datetime.timestamp(
            datetime.datetime.strptime(
                paste["expires_at"], "%Y-%m-%d %H:%M:%S"
            )  # 2023-07-17 22:10:45
        ) < round(time.time()):
            pastes.pop(paste_id)
            with open("pastes.json", "w") as f:
                json.dump(pastes, f, indent=4)
            continue
        if paste["type"] == "private" and paste["author"] != username:
            continue
        paste_list[paste_id] = {
            "title": paste["title"],
            "type": paste["type"],
            "expires": paste["expires"],
            "created_at": paste["created_at"],
            "author": paste["author"],
        }
    response.status_code = status.HTTP_200_OK
    return {"total": len(paste_list), "pastes": paste_list}


# ------------------------------ Front End ------------------------------ #
@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/pastes/", response_class=HTMLResponse)
async def paste_list(
    request: Request, auth_token: str = Cookie(None), username: str = Cookie(None)
):
    print(auth_token)
    print(username)
    async with AsyncClient() as sess:
        sess.cookies.set("auth_token", auth_token)
        sess.cookies.set("username", username)

        r = await sess.get(
            "http://localhost:8000/api/pastes",
        )
        print(r.json())
        if r.status_code == 401:
            return RedirectResponse(url="/login")

        pastes = r.json()["pastes"]
        total = r.json()["total"]

        return templates.TemplateResponse(
            "paste_list.html", {"request": request, "pastes": pastes, "total": total}
        )


@app.get("/paste/delete/{paste_id}", response_class=HTMLResponse)
async def paste_delete(
    request: Request,
    paste_id: str,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    async with AsyncClient() as sess:
        sess.cookies.set("auth_token", auth_token)
        sess.cookies.set("username", username)
        r = await sess.get(f"http://localhost:8000/api/paste/{paste_id}")
        title = r.json()["title"]
        r = await sess.delete(
            f"http://localhost:8000/api/paste/{paste_id}",
        )
        print(r.json())
        if r.status_code == 401:
            return RedirectResponse(url="/login")
        if r.status_code == 403:
            return RedirectResponse(url="/pastes/")
        return templates.TemplateResponse(
            "paste_delete.html",
            {"request": request, "paste_id": paste_id, "title": title},
        )


@app.get("/paste/create", response_class=HTMLResponse)
async def paste_create(request: Request):
    return templates.TemplateResponse("create_paste.html", {"request": request})


@app.get("/paste/edit/{paste_id}", response_class=HTMLResponse)
async def paste_edit(request: Request, paste_id: str):
    return templates.TemplateResponse(
        "edit_paste.html", {"request": request, "paste_id": paste_id}
    )


@app.get("/paste/{paste_id}", response_class=HTMLResponse)
async def paste_html(
    request: Request,
    paste_id: str,
    auth_token: str = Cookie(None),
    username: str = Cookie(None),
):
    async with AsyncClient() as sess:
        sess.cookies.set("auth_token", auth_token)
        sess.cookies.set("username", username)

        r = await sess.get(
            f"http://localhost:8000/api/paste/{paste_id}",
        )
        print(r.json())
        if r.status_code == 401:
            return RedirectResponse(url="/login")

        return templates.TemplateResponse(
            "pastes.html", {"request": request, "paste_id": paste_id, "paste": r.json()}
        )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/logout")
async def logout(response: Response):
    response.delete_cookie(key="auth_token")
    response.delete_cookie(key="username")
    return RedirectResponse(url="/login")


from os import system

if __name__ == "__main__":
    system("uvicorn api:app --reload")
