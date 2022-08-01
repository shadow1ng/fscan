module github.com/shadow1ng/fscan

go 1.16

require (
	github.com/denisenkom/go-mssqldb v0.12.2
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/protobuf v1.3.4
	github.com/google/cel-go v0.6.0
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/jlaffaye/ftp v0.0.0-20220630165035-11536801d1ff
	github.com/lib/pq v1.10.6
	github.com/satori/go.uuid v1.2.0
	github.com/sijms/go-ora/v2 v2.4.28
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210610132358-84b48f89b13b
	golang.org/x/text v0.3.6
	google.golang.org/genproto v0.0.0-20200416231807-8751e049a2a0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/tomatome/grdp v0.0.0-20211231062539-be8adab7eaf3 => github.com/shadow1ng/grdp v1.0.3
