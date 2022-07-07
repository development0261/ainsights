FROM python:3.10-alpine as production

ENV PYTHONPATH=/app/src

WORKDIR /app

EXPOSE 8000

RUN apk update && apk add build-base bind-tools nmap nmap-scripts musl-dev gcc libffi-dev

COPY ./requirements.txt ./requirements.txt

RUN pip install -r requirements.txt

COPY ./src ./src

CMD [ "sh", "-c", "uvicorn --proxy-headers --host 0.0.0.0 --port ${PORT:-8000} src.app:app" ]
