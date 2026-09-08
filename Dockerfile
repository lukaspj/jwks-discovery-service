FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /jwks-discovery-service ./cmd/jwks-discovery-service

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /jwks-discovery-service /jwks-discovery-service
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/jwks-discovery-service"]
