module github.com/shadow1ng/fscan

go 1.22

toolchain go1.23.3

require (
	github.com/C-Sto/goWMIExec v0.0.1-deva.0.20210704154847-b8ebd6464a06
	github.com/IBM/sarama v1.43.3
	github.com/denisenkom/go-mssqldb v0.12.3
	github.com/fatih/color v1.7.0
	github.com/go-ldap/ldap/v3 v3.4.9
	github.com/go-sql-driver/mysql v1.8.1
	github.com/google/cel-go v0.13.0
	github.com/google/gopacket v1.1.19
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/jlaffaye/ftp v0.2.0
	github.com/lib/pq v1.10.9
	github.com/mitchellh/go-vnc v0.0.0-20150629162542-723ed9867aed
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/satori/go.uuid v1.2.0
	github.com/sijms/go-ora/v2 v2.5.29
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3
	golang.org/x/crypto v0.31.0
	golang.org/x/net v0.32.0
	golang.org/x/text v0.21.0
	google.golang.org/genproto v0.0.0-20221027153422-115e99e71e1c
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v1.4.10 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/eapache/go-resiliency v1.7.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.7 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gosnmp/gosnmp v1.38.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/icodeface/tls v0.0.0-20190904083142-17aec93c60e5 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/mattn/go-colorable v0.0.9 // indirect
	github.com/mattn/go-isatty v0.0.3 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	go.uber.org/atomic v1.5.0 // indirect
	go.uber.org/multierr v1.3.0 // indirect
	go.uber.org/tools v0.0.0-20190618225709-2cfd321de3ee // indirect
	go.uber.org/zap v1.14.0 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
)

replace github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3 => github.com/shadow1ng/grdp v1.0.3

replace github.com/C-Sto/goWMIExec v0.0.1-deva.0.20210704154847-b8ebd6464a06 => github.com/shadow1ng/goWMIExec v0.0.2
