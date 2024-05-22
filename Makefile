BUILD_ENV = CGO_ENABLED=0
OPTIONS = -trimpath -ldflags "-w -s"
NAME = fscan

.PHONY: all linux windows macos mips arm clean

all:
	${BUILD_ENV} GOOS=linux GOARCH=386 go build ${OPTIONS} -o release/${NAME}_86 main.go
	${BUILD_ENV} GOOS=linux GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_64 main.go
	${BUILD_ENV} GOOS=windows GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_64.exe main.go
	${BUILD_ENV} GOOS=windows GOARCH=386 go build ${OPTIONS} -o release/${NAME}_86.exe main.go
	${BUILD_ENV} GOOS=darwin GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_darwin64 main.go
	${BUILD_ENV} GOOS=darwin GOARCH=arm64 go build ${OPTIONS} -o release/${NAME}_darwinarm64 main.go
	${BUILD_ENV} GOOS=linux GOARCH=mipsle go build ${OPTIONS} -o release/${NAME}_mipsel main.go
	${BUILD_ENV} GOOS=linux GOARCH=arm64 go build ${OPTIONS} -o release/${NAME}_arm64 main.go

linux:
	${BUILD_ENV} GOOS=linux GOARCH=386 go build ${OPTIONS} -o release/${NAME}_86 main.go
	${BUILD_ENV} GOOS=linux GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_64 main.go
	${BUILD_ENV} GOOS=linux GOARCH=arm64 go build ${OPTIONS} -o release/${NAME}_arm64 main.go

windows:
	${BUILD_ENV} GOOS=windows GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_64.exe main.go
	${BUILD_ENV} GOOS=windows GOARCH=386 go build ${OPTIONS} -o release/${NAME}_86.exe main.go

macos:
	${BUILD_ENV} GOOS=darwin GOARCH=amd64 go build ${OPTIONS} -o release/${NAME}_darwin64 main.go
	${BUILD_ENV} GOOS=darwin GOARCH=arm64 go build ${OPTIONS} -o release/${NAME}_darwinarm64 main.go

arm:
	${BUILD_ENV} GOOS=linux GOARCH=arm GOARM=5 go build ${OPTIONS} -o release/${NAME}_arm64 main.go

mips:
	${BUILD_ENV} GOOS=linux GOARCH=mipsle go build ${OPTIONS} -o release/${NAME}_mipsel main.go


clean:
	@rm release/*