module github.com/shadow1ng/fscan

go 1.16

require (
	github.com/denisenkom/go-mssqldb v0.11.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/protobuf v1.3.4
	github.com/google/cel-go v0.6.0
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/jlaffaye/ftp v0.0.0-20211117213618-11820403398b
	github.com/lib/pq v1.10.4
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca
	github.com/sijms/go-ora/v2 v2.2.16
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/text v0.3.3
	google.golang.org/genproto v0.0.0-20200416231807-8751e049a2a0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3 => github.com/shadow1ng/grdp v1.0.3
