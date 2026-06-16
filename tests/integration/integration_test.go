//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/plugins/services"
)

const (
	testHost = "127.0.0.1"
)

func testSession() *common.ScanSession {
	cfg := common.NewConfig()
	cfg.Timeout = 10 * time.Second
	cfg.ModuleThreadNum = 5
	cfg.MaxRetries = 2
	cfg.Credentials.Userdict = nil
	cfg.Credentials.Passwords = nil
	state := common.NewState()
	return common.NewScanSession(cfg, state, &common.FlagVars{})
}

func hostInfo(host string, port int) *common.HostInfo {
	return &common.HostInfo{Host: host, Port: port}
}

func TestMain(m *testing.M) {
	fmt.Println("integration tests: ensure docker-compose services are running")
	os.Exit(m.Run())
}

// ── Redis ──────────────────────────────────────────────────────

func TestRedisUnauthorized(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 16380)
	plugin := services.NewRedisPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected unauthorized redis to succeed, got error: %v", result.Error)
	}
	t.Logf("redis noauth: %+v", result)
}

func TestRedisBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "", Password: "wrong1"},
		{Username: "", Password: "test123"},
	}
	info := hostInfo(testHost, 16379)
	plugin := services.NewRedisPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected redis brute to succeed with test123, got error: %v", result.Error)
	}
	if result.Password != "test123" {
		t.Errorf("expected password test123, got %q", result.Password)
	}
	t.Logf("redis brute: %+v", result)
}

// ── MySQL ──────────────────────────────────────────────────────

func TestMySQLBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "root", Password: "wrong"},
		{Username: "root", Password: "root123"},
	}
	info := hostInfo(testHost, 13307)
	plugin := services.NewMySQLPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected mysql brute to succeed, got error: %v", result.Error)
	}
	t.Logf("mysql brute: user=%s pass=%s", result.Username, result.Password)
}

// ── PostgreSQL ─────────────────────────────────────────────────

func TestPostgreSQLBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "postgres", Password: "wrong"},
		{Username: "postgres", Password: "postgres123"},
	}
	info := hostInfo(testHost, 15432)
	plugin := services.NewPostgreSQLPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected postgresql brute to succeed, got error: %v", result.Error)
	}
	t.Logf("postgresql brute: user=%s pass=%s", result.Username, result.Password)
}

// ── FTP ────────────────────────────────────────────────────────

func TestFTPBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "ftpuser", Password: "wrong"},
		{Username: "ftpuser", Password: "ftp123"},
	}
	info := hostInfo(testHost, 10021)
	plugin := services.NewFTPPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected ftp brute to succeed, got error: %v", result.Error)
	}
	t.Logf("ftp brute: user=%s pass=%s", result.Username, result.Password)
}

// ── SSH ────────────────────────────────────────────────────────

func TestSSHBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "sshuser", Password: "wrong"},
		{Username: "sshuser", Password: "ssh123"},
	}
	info := hostInfo(testHost, 10022)
	plugin := services.NewSSHPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected ssh brute to succeed, got error: %v", result.Error)
	}
	t.Logf("ssh brute: user=%s pass=%s", result.Username, result.Password)
}

// ── MongoDB ────────────────────────────────────────────────────

func TestMongoDBBrute(t *testing.T) {
	// Fixed: BSON key ordering was non-deterministic (Go map), MongoDB requires command name first
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "mongo123"},
	}
	info := hostInfo(testHost, 17017)
	plugin := services.NewMongoDBPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected mongodb brute to succeed, got error: %v", result.Error)
	}
	t.Logf("mongodb brute: user=%s pass=%s", result.Username, result.Password)
}

// ── Memcached ──────────────────────────────────────────────────

func TestMemcachedUnauthorized(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 11211)
	plugin := services.NewMemcachedPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected memcached to succeed, got error: %v", result.Error)
	}
	t.Logf("memcached: type=%s banner=%s", result.Type, result.Banner)
}

// ── Elasticsearch ──────────────────────────────────────────────

func TestElasticsearchUnauthorized(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 19200)
	plugin := services.NewElasticsearchPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected elasticsearch to succeed, got error: %v", result.Error)
	}
	t.Logf("elasticsearch: type=%s vulinfo=%s", result.Type, result.VulInfo)
}

// ── MSSQL ──────────────────────────────────────────────────────

func TestMSSQLBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "sa", Password: "wrong"},
		{Username: "sa", Password: "MssqlTest123!"},
	}
	info := hostInfo(testHost, 11433)
	plugin := services.NewMSSQLPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected mssql brute to succeed, got error: %v", result.Error)
	}
	t.Logf("mssql brute: user=%s pass=%s", result.Username, result.Password)
}

// ── RabbitMQ ───────────────────────────────────────────────────

func TestRabbitMQBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "rabbit123"},
	}
	info := hostInfo(testHost, 15672)
	plugin := services.NewRabbitMQPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected rabbitmq brute to succeed, got error: %v", result.Error)
	}
	t.Logf("rabbitmq brute: user=%s pass=%s", result.Username, result.Password)
}

// ── MQTT ───────────────────────────────────────────────────────

func TestMQTTServiceDetect(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 11883)
	plugin := services.NewMQTTPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected mqtt service detect to succeed, got error: %v", result.Error)
	}
	t.Logf("mqtt: service=%s banner=%s", result.Service, result.Banner)
}

// ── SMB ────────────────────────────────────────────────────────

func TestSMBBrute(t *testing.T) {
	t.Skip("SMB requires port 445 which is reserved on WSL2")
}

// ── LDAP ───────────────────────────────────────────────────────

func TestLDAPBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "cn=admin,dc=test,dc=local", Password: "wrong"},
		{Username: "cn=admin,dc=test,dc=local", Password: "ldap123"},
	}
	info := hostInfo(testHost, 10389)
	plugin := services.NewLDAPPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected ldap brute to succeed, got error: %v", result.Error)
	}
	t.Logf("ldap brute: user=%s pass=%s", result.Username, result.Password)
}

// ── Cassandra ──────────────────────────────────────────────────

func TestCassandraServiceDetect(t *testing.T) {
	session := testSession()
	session.Config.DisableBrute = true
	info := hostInfo(testHost, 19042)
	plugin := services.NewCassandraPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected cassandra service detect to succeed, got error: %v", result.Error)
	}
	t.Logf("cassandra: type=%s banner=%s", result.Type, result.Banner)
}

// ── Neo4j ──────────────────────────────────────────────────────

func TestNeo4jBrute(t *testing.T) {
	session := testSession()
	session.Config.Credentials.UserPassPairs = []config.CredentialPair{
		{Username: "neo4j", Password: "wrong"},
		{Username: "neo4j", Password: "neo4jtest123"},
	}
	info := hostInfo(testHost, 17687)
	plugin := services.NewNeo4jPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected neo4j brute to succeed, got error: %v", result.Error)
	}
	t.Logf("neo4j brute: user=%s pass=%s", result.Username, result.Password)
}

// ── Kafka ──────────────────────────────────────────────────────

func TestKafkaNoAuth(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 19092)
	plugin := services.NewKafkaPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected kafka to succeed, got error: %v", result.Error)
	}
	t.Logf("kafka: type=%s banner=%s", result.Type, result.Banner)
}

// ── SMTP ───────────────────────────────────────────────────────

func TestSMTPServiceDetect(t *testing.T) {
	session := testSession()
	info := hostInfo(testHost, 11025)
	plugin := services.NewSMTPPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("expected smtp to succeed, got error: %v", result.Error)
	}
	t.Logf("smtp: type=%s banner=%s", result.Type, result.Banner)
}

// ── 连接失败场景 ──────────────────────────────────────────────

func TestRedisConnectionRefused(t *testing.T) {
	session := testSession()
	session.Config.Timeout = 3 * time.Second
	info := hostInfo(testHost, 19999)
	plugin := services.NewRedisPlugin()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := plugin.Scan(ctx, info, session)
	if result != nil && result.Success {
		t.Fatal("expected failure on closed port")
	}
}
