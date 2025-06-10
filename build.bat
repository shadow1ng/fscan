@echo off&setlocal enabledelayedexpansion
title build fscan
chcp 65001 >nul
@set version=v1.8
@set output=fscan
@set  build_dir=build
@if not exist %build_dir% (
        @mkdir %build_dir%
        @echo create folder %build_dir%
    ) 
@echo output:%output%
@echo build version:%version%
@set outfilename=%output%_windows_386_%version%.exe
@echo build windows/386 …… %build_dir%/%outfilename%
@set GOOS=windows&&set GOARCH=386&& go build  -trimpath -ldflags "-w -s"   -o %build_dir%/%outfilename%  main.go

@set outfilename=%output%_windows_amd64_%version%.exe
@echo build windows/amd64 …… %build_dir%/%outfilename%
@set GOOS=windows&&set GOARCH=amd64&& go build -trimpath  -ldflags "-w -s"  -o %build_dir%/%outfilename%  main.go

@set outfilename=%output%_windows_arm64_%version%.exe
@echo build windows/arm64 …… %build_dir%/%outfilename%
@set GOOS=windows&&set GOARCH=arm64&& go build -trimpath  -ldflags "-w -s"  -o %build_dir%/%outfilename%  main.go

@set CGO_ENABLED=0

@set outfilename=%output%_linux_386_%version%
@echo build linux/386 …… %build_dir%/%outfilename%
@set GOOS=linux&&set GOARCH=386&& go build -trimpath  -ldflags "-w -s"  -o %build_dir%/%outfilename%  main.go

@set outfilename=%output%_linux_amd64_%version%
@echo build linux/amd64 …… %build_dir%/%outfilename%
@set GOOS=linux&&set GOARCH=amd64&& go build -trimpath  -ldflags "-w -s" -o %build_dir%/%outfilename%  main.go

@set outfilename=%output%_darwin_amd64_%version%
@echo build darwin/amd64 …… %build_dir%/%outfilename%
@set GOOS=darwin&&set GOARCH=amd64&& go build  -trimpath -ldflags "-w -s"  -o %build_dir%/%outfilename%   main.go

@set outfilename=%output%_darwin_arm64_%version%
@echo build darwin/arm64 …… %build_dir%/%outfilename%
@set GOOS=darwin&&set GOARCH=arm64&& go build  -trimpath -ldflags "-w -s"  -o %build_dir%/%outfilename%   main.go

@echo build finished!
@pause