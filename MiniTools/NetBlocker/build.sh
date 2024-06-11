#!/bin/zsh
export GOOS=windows
export GOARCH=amd64
go build -o net_blocker.exe main.go