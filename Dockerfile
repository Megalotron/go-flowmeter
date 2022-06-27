###
# Builder stage
# Aim to download dependencies and build binaries
### 
FROM golang:1.18-alpine AS builder

WORKDIR /app

# Copy module
COPY go.mod go.mod
COPY go.sum go.sum

# Cache dependencies
RUN go mod download

# Copy sources
COPY . .

RUN go build -o goflowmeter

###
# App stage
# Final application container
###
FROM busybox AS app

COPY --from=builder /app/goflowmeter /bin/goflowmeter

ENTRYPOINT ["goflowmeter"]