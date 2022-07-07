FROM node:16-alpine as builder

WORKDIR /app

COPY ./package*.json ./

RUN npm install

COPY ./ ./

RUN npm run build


FROM nginx:1.21.6 as production

COPY --from=builder /app/dist /usr/share/nginx/html
