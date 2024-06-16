# Step 1: Build the Go binary
FROM golang:1.21-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the source code into the container
COPY . .

# Build the Go app
RUN go mod tidy
RUN go build -o main .

# Step 2: Create a smaller image to run the Go binary
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .
COPY config.yaml .
COPY license .

# Ensure the binary has execution permissions
RUN chmod +x ./main

# Expose port 8080 to the outside world
EXPOSE 8088

# Command to run the executable
CMD ["./main"]