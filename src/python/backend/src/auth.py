import os

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import db

jwt_token = 'FSx494aUZzW63qxX5CflmIgBkEX4Hx0NyVbBdi4Q3eE'

def verify_jwt(token: str) -> bool:

    try:
        return bool(jwt.decode(token, jwt_token, algorithms=["HS256"]))
    except jwt.exceptions.PyJWTError:
        return False


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials:

        credentials = await super().__call__(request)

        if credentials is None:
            raise HTTPException(status_code=403, detail="Invalid credentials")

        if credentials.scheme != "Bearer":
            raise HTTPException(status_code=403, detail="Invalid authentication scheme")

        if not verify_jwt(credentials.credentials):
            raise HTTPException(status_code=403, detail="Invalid token")

        return credentials


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(JWTBearer())):

    user = jwt.decode(
        credentials.credentials, jwt_token, algorithms=["HS256"]
    )

    return db.get_user_by_id(id_=user["user_id"])
