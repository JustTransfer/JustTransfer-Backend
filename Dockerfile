FROM rust:1.90

WORKDIR /usr/src/myapp
COPY . .

RUN cargo install --path .

EXPOSE 80

CMD ["JujuTransfer"]