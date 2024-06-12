#!/bin/zsh
export GOOS=windows
export GOARCH=amd64
go build -o ikuai_helper.exe main.go