import os
from sched import scheduler
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

import bcrypt
from src import jobs
import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import auth
from . import db
from . import exc
from . import models
from . import requests
from . import responses

jwt_token = 'FSx494aUZzW63qxX5CflmIgBkEX4Hx0NyVbBdi4Q3eE'

app = FastAPI(
    title="DNS API",
    version="1.3.1",
    description="A simple domain and port scanning API",
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


@app.exception_handler(exc.ValidationException)
def handle_validation_exc(_: Request, exception: exc.ValidationException):
    return JSONResponse(status_code=422, content={"detail": str(exception)})


@app.exception_handler(exc.EntityNotFound)
def handle_entity_not_found_exc(_: Request, exception: exc.EntityNotFound):
    return JSONResponse(status_code=404, content={"detail": str(exception)})


@app.post(
    "/api/v1/users/{id_}/onboard",
    status_code=201,
    tags=["Users"],
    summary="Register domain/ipv4(s) - port(s) for user",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.UserDomain],
)
async def onboard_a_user(
    id_: str,
    request: requests.UserOnboardingRequest,
    bg_tasks: BackgroundTasks,
    user: models.User = Depends(auth.get_current_user),
) -> None:

    # only admins can onboard users
    if user.is_admin is False:
        raise HTTPException(status_code=403, detail="Admin access required")

    user_domain = models.UserDomain(
        id_=str(uuid.uuid4()),
        user_id=id_,
        domain=request.domain,
        schedule=request.schedule
    )

    user_ip = models.UserIP(
        id_=str(uuid.uuid4()),
        user_id=id_,
        ipv4_addrs=request.ipv4_addrs,
        ports=request.ports,
    )

    # db.update_schedule(id_, request.schedule)
    db.store_user_domain_registration(user_domain)
    db.store_user_ipv4_registration(user_ip)

    # default domain scans
    bg_tasks.add_task(jobs.scan_domain, user_domain, "dns")
    bg_tasks.add_task(jobs.scan_domain, user_domain, "ssl")
    bg_tasks.add_task(jobs.scan_domain, user_domain, "http")

    # default port scans
    bg_tasks.add_task(jobs.scan_port, user_ip)


# @app.post(
#     "/api/v1/domains",
#     status_code=201,
#     tags=["Domains"],
#     summary="Register a domain for user",
#     dependencies=[Depends(auth.JWTBearer())],
#     response_model=List[models.UserDomain],
# )
# async def register_user_domain(
#     request: requests.DomainRegistrationRequest,
#     bg_tasks: BackgroundTasks,
#     user: models.User = Depends(auth.get_current_user),
# ) -> List[models.UserDomain]:

#     user_domain = db.store_user_domain_registration(user.id_, request)

#     bg_tasks.add_task(jobs.scan_domain, user_domain, "dns")
#     bg_tasks.add_task(jobs.scan_domain, user_domain, "ssl")
#     bg_tasks.add_task(jobs.scan_domain, user_domain, "http")

#     return db.get_user_domains(user.id_)


# @app.post(
#     "/api/v1/ips",
#     status_code=201,
#     tags=["Ipv4(s) & Port(s)"],
#     summary="Register Ipv4 address(s) for user",
#     dependencies=[Depends(auth.JWTBearer())],
#     response_model=List[models.UserIP],
# )
# async def register_user_ipv4(
#     request: requests.Ipv4RegistrationRequest,
#     bg_tasks: BackgroundTasks,
#     user: models.User = Depends(auth.get_current_user),
# ) -> List[models.UserDomain]:

#     user_ip = db.store_user_ipv4_registration(user.id_, request)
#     bg_tasks.add_task(jobs.scan_port, user_ip)
#     return db.get_user_ips(user.id_)


@app.get(
    "/api/v1/domains",
    tags=["Domains"],
    summary="Get a list of registered user domains",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.UserDomain],
)
async def get_self_registered_domains(
    user: models.User = Depends(auth.get_current_user),
) -> List[models.UserDomain]:
    print("domain func running")
    print(user)
    # await asyncio.sleep(2)
    return db.get_user_domains(user.id_)


@app.get(
    "/api/v1/users/{id_}/domains",
    tags=["Users"],
    summary="Get a list of registered user domains",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.UserDomain],
)
async def get_registered_user_domains(
    id_: uuid.UUID,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.UserDomain]:

    if user.is_admin is False:
        raise HTTPException(status_code=403, detail="Admin access required")

    return db.get_user_domains(str(id_))


@app.get(
    "/api/v1/domains/{id_}/scans",
    tags=["Domains"],
    summary="Get a list of domain scans",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.Scan],
)
async def get_domain_scans(
    id_: str,
    _: models.User = Depends(auth.get_current_user),
) -> List[models.Scan]:
    return db.get_domain_scans(id_)


@app.get(
    "/api/v1/scans/{id_}/results",
    tags=["Scans"],
    summary="Get a list of scan results",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.DomainScanResult | models.PortScanResult],
)
async def get_scan_results(
    id_: str,
    _: models.User = Depends(auth.get_current_user),
) -> List[models.DomainScanResult | models.PortScanResult]:

    return db.get_scan_results(id_)


@app.post(
    "/api/v1/scans/port",
    status_code=201,
    tags=["Scans"],
    summary="Run a port scan",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.PortScanResult],
)
async def run_port_scan(
    request: requests.SyncPortScanRequest,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.PortScanResult]:

    scan_id = jobs.scan_port(request.ipv4_addrs, request.ports, user)
    return db.get_port_scan_results(scan_id)


@app.post(
    "/api/v1/scans/dns",
    status_code=201,
    tags=["Scans"],
    summary="Run a dns scan",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.DomainScanResult],
)
async def run_dns_scan(
    request: requests.DomainScanRequest,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.DomainScanResult]:

    scan_id = jobs.scan_domain(request.domain, user, "dns")
    return db.get_domain_scan_results(scan_id)


@app.post(
    "/api/v1/scans/ssl",
    status_code=201,
    tags=["Scans"],
    summary="Run an Ssl scan",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.PortScanResult],
)
async def run_ssl_scan(
    request: requests.DomainScanRequest,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.PortScanResult]:

    scan_id = jobs.scan_domain(request.domain, user, "ssl")
    return db.get_port_scan_results(scan_id)


@app.post(
    "/api/v1/scans/http",
    status_code=201,
    tags=["Scans"],
    summary="Run an Http scan",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.PortScanResult],
)
async def run_http_scan(
    request: requests.DomainScanRequest,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.PortScanResult]:

    scan_id = jobs.scan_domain(request.domain, user, "http")
    return db.get_port_scan_results(scan_id)


@app.get(
    "/api/v1/ips",
    tags=["Ipv4(s) & Port(s)"],
    summary="Get a list of registered user ips",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.UserIP],
)
async def get_self_registered_ips(
    user: models.User = Depends(auth.get_current_user),
) -> List[models.UserIP]:
    return db.get_user_ips(user.id_)


@app.get(
    "/api/v1/users/{id_}/ips",
    tags=["Users"],
    summary="Get a list of registered user ips",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.UserIP],
)
async def get_registered_user_ips(
    id_: str,
    user: models.User = Depends(auth.get_current_user),
) -> List[models.UserIP]:

    if user.is_admin is False:
        raise HTTPException(status_code=403, detail="Admin access required")

    return db.get_user_ips(id_)


@app.get(
    "/api/v1/users",
    tags=["Users"],
    summary="Get a list of registered users",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.User],
)
async def get_registered_users(
    user: models.User = Depends(auth.get_current_user),
) -> List[models.UserIP]:

    if user.is_admin is False:
        raise HTTPException(status_code=403, detail="Admin access required")

    return db.get_users()


@app.post(
    "/api/v1/auth/login",
    tags=["Auth"],
    summary="Login to user account",
    status_code=201,
    response_model=responses.AuthResponse,
)
async def login(request: requests.AuthRequest) -> responses.AuthResponse:

    user = db.get_auth_user_by_email(email=request.email)
    if user is None:
        raise HTTPException(status_code=403, detail="Invalid email/password")

    if not bcrypt.checkpw(request.password.encode(), user.hashed_password.encode()):
        raise HTTPException(status_code=403, detail="Invalid email/password")

    access_token = jwt.encode(
        {
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
            "email": user.email,
            "user_id": user.id_,
            "is_admin": user.is_admin,
        },
        jwt_token,
    )
    return responses.AuthResponse(
        email=user.email,
        user_id=user.id_,
        is_admin=user.is_admin,
        access_token=access_token,
    )


@app.post(
    "/api/v1/users",
    tags=["Users"],
    summary="Sign up user account",
    status_code=201,
    response_model=responses.AuthResponse,
)
async def signup(request: requests.AuthRequest) -> responses.AuthResponse:

    hashed_password = bcrypt.hashpw(
        request.password.encode(), bcrypt.gensalt()
    ).decode()
    user = db.create_user(email=request.email, password=hashed_password)

    access_token = jwt.encode(
        {
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
            "email": user.email,
            "user_id": user.id_,
            "is_admin": user.is_admin,
        },
        jwt_token,
    )

    return responses.AuthResponse(
        email=user.email,
        user_id=user.id_,
        is_admin=user.is_admin,
        access_token=access_token,
    )


@app.post(
    "/api/v1/auth/google",
    tags=["Auth"],
    summary="Login using a Google account",
    status_code=201,
    response_model=responses.AuthResponse,
)
async def login_via_google(request: requests.AuthRequest) -> responses.AuthResponse:
    pass


@app.delete(
    "/api/v1/auth/logout",
    summary="Logout of user account",
    tags=["Auth"],
    status_code=404,
)
async def logout() -> None:
    return


@app.get(
    "/api/v1/ips/{id_}/scans",
    tags=["Ipv4(s) & Port(s)"],
    summary="Get Statistics for port scans",
    dependencies=[Depends(auth.JWTBearer())],
    response_model=List[models.Scan],
)
def get_port_scans(
    id_: str,
    _: models.User = Depends(auth.get_current_user),
) -> List[models.Scan]:
    return db.get_port_scans(id_)


# @app.get(
#     "/api/v1/try_api",
#     tags=["Try"],
#     summary="Try it",
# )
# def try_function():
#     print("hi")
#     return {"success":"Hii"}

# import asyncio
# from apscheduler.schedulers.asyncio import AsyncIOScheduler
# msg_scheduler = AsyncIOScheduler()
# msg_scheduler.add_job(get_self_registered_domains(user = auth.get_current_user), 'interval', minutes=1)
# msg_scheduler.start()

# from apscheduler.schedulers.background import BackgroundScheduler
# msg_scheduler = BackgroundScheduler()
# print_job = msg_scheduler.add_job(try_function, 'interval', minutes=1)
# msg_scheduler.start()
