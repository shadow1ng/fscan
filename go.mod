module github.com/shadow1ng/fscan

go 1.19

require (
	github.com/C-Sto/goWMIExec v0.0.1-deva.0.20210704154847-b8ebd6464a06
	github.com/denisenkom/go-mssqldb v0.12.2
	github.com/fatih/color v1.7.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/cel-go v0.13.0
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/jlaffaye/ftp v0.0.0-20220829015825-b85cf1edccd4
	github.com/lib/pq v1.10.6
	github.com/satori/go.uuid v1.2.0
	github.com/sijms/go-ora/v2 v2.5.3
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3
	golang.org/x/crypto v0.3.0
	golang.org/x/net v0.7.0
	golang.org/x/text v0.7.0
	google.golang.org/genproto v0.0.0-20221027153422-115e99e71e1c
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v1.4.10 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/icodeface/tls v0.0.0-20190904083142-17aec93c60e5 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/mattn/go-colorable v0.0.9 // indirect
	github.com/mattn/go-isatty v0.0.3 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	go.uber.org/atomic v1.5.0 // indirect
	go.uber.org/multierr v1.3.0 // indirect
	go.uber.org/tools v0.0.0-20190618225709-2cfd321de3ee // indirect
	go.uber.org/zap v1.14.0 // indirect
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
)

replace github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3 => github.com/shadow1ng/grdp v1.0.3

replace github.com/C-Sto/goWMIExec v0.0.1-deva.0.20210704154847-b8ebd6464a06 => github.com/shadow1ng/goWMIExec v0.0.2
