package system

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"zfsnas/internal/config"
)

// AWS Signature V4 test suite: "get-vanilla" and "get-vanilla-query-order-key-case"
// (credentials AKIDEXAMPLE, 2015-08-30T12:36:00Z, us-east-1, service "service").
func TestSigV4AWSTestSuite(t *testing.T) {
	cases := []struct{ url, sig string }{
		{"https://example.amazonaws.com/", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
		{"https://example.amazonaws.com/?Param2=value2&Param1=value1", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
	}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, c := range cases {
		req, _ := http.NewRequest("GET", c.url, nil)
		sigV4Sign(req, sha256Hex(nil), "service", "us-east-1", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", now)
		auth := req.Header.Get("Authorization")
		if !strings.HasSuffix(auth, "Signature="+c.sig) {
			t.Errorf("%s:\n got %s\nwant …Signature=%s", c.url, auth, c.sig)
		}
		if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date,") {
			t.Errorf("%s: bad credential scope / signed headers: %s", c.url, auth)
		}
	}
}

func TestURIEncodeAndQuery(t *testing.T) {
	if got := uriEncode("/my bucket/a+b~c.txt", true); got != "/my%20bucket/a%2Bb~c.txt" {
		t.Errorf("path: %s", got)
	}
	if got := canonicalQuery("versioning"); got != "versioning=" {
		t.Errorf("flag query: %q", got)
	}
	if got := canonicalQuery("b=2&a=1&a=0"); got != "a=0&a=1&b=2" {
		t.Errorf("sorted query: %q", got)
	}
}

func TestParseS3Error(t *testing.T) {
	e := parseS3Error(409, []byte(`<?xml version="1.0"?><Error><Code>BucketNotEmpty</Code><Message>The bucket you tried to delete is not empty</Message></Error>`))
	if e.Code != "BucketNotEmpty" || !strings.Contains(e.Error(), "not empty") {
		t.Errorf("xml: %+v", e)
	}
	e = parseS3Error(400, []byte(`{"Code":"InvalidArgument","Message":"bad key"}`))
	if e.Error() != "InvalidArgument: bad key" {
		t.Errorf("json: %q", e.Error())
	}
}

func TestParseQuotaBytes(t *testing.T) {
	cases := map[string]int64{"": 0, "0": 0, "1024": 1024, "50G": 50 << 30, "50GiB": 50 << 30, "1.5T": 3 << 39, "512MB": 512 << 20, "10 gib": 10 << 30}
	for in, want := range cases {
		got, err := parseQuotaBytes(in)
		if err != nil || got != want {
			t.Errorf("%q: got %d %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"abc", "-5G", "5X"} {
		if _, err := parseQuotaBytes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBuildRustFSEnv(t *testing.T) {
	cfg := &config.MinIOConfig{RootUser: "admin", RootPassword: `p"a\ss`, DataDir: "/tank/s3", Port: 9000,
		ConsolePort: 9001, Region: "us-east-1", TLS: true, ServerURL: "https://s3.example.com:9000"}
	env := buildRustFSEnv(cfg)
	for _, want := range []string{
		`RUSTFS_ACCESS_KEY="admin"`, `RUSTFS_SECRET_KEY="p\"a\\ss"`, `RUSTFS_VOLUMES="/tank/s3/rustfs-data"`,
		`RUSTFS_ADDRESS=":9000"`, `RUSTFS_CONSOLE_ADDRESS=":9001"`, `RUSTFS_REGION="us-east-1"`,
		`RUSTFS_SERVER_DOMAINS="s3.example.com"`, `RUSTFS_TLS_PATH="/var/lib/rustfs/tls"`,
	} {
		if !strings.Contains(env, want+"\n") {
			t.Errorf("missing %s in:\n%s", want, env)
		}
	}
	cfg.TLS, cfg.ServerURL = false, "http://192.168.1.10:9000"
	env = buildRustFSEnv(cfg)
	if strings.Contains(env, "RUSTFS_TLS_PATH") || strings.Contains(env, "RUSTFS_SERVER_DOMAINS") {
		t.Errorf("TLS off / IP URL must not set them:\n%s", env)
	}
}
