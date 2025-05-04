FROM golang:latest 

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . ./

RUN go build main.go

EXPOSE 8085

CMD ["./main"]
