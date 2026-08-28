FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/saase .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/saase /usr/local/bin/saase
ENTRYPOINT ["/usr/local/bin/saase"]
