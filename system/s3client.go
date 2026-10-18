package system

// s3client.go — a small S3 + admin API client for the local RustFS server.
//
// The portal used to drive MinIO through the `mc` CLI. `mc` is archived and
// can no longer be downloaded, so the portal now talks to the server itself:
// AWS Signature Version 4 (standard library only — the project takes no new
// module dependencies) and the handful of calls the S3 page needs. RustFS's
// admin API takes and returns plain JSON (MinIO encrypted admin bodies; RustFS
// does not), which keeps this small.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3Client talks to one S3 endpoint with one set of credentials.
type S3Client struct {
	Endpoint  string // scheme://host:port, no trailing slash
	AccessKey string
	SecretKey string
	Region    string
	HTTP      *http.Client
}

// NewLocalS3Client returns a client for the server on this machine. TLS
// certificates are the server's own self-signed ones, so they are not
// verified (the connection never leaves the host).
func NewLocalS3Client(port int, useTLS bool, accessKey, secretKey, region string) *S3Client {
	scheme := "http"
	tr := &http.Transport{}
	if useTLS {
		scheme = "https"
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback, self-signed
	}
	if region == "" {
		region = "us-east-1"
	}
	return &S3Client{
		Endpoint:  fmt.Sprintf("%s://127.0.0.1:%d", scheme, port),
		AccessKey: accessKey, SecretKey: secretKey, Region: region,
		HTTP: &http.Client{Transport: tr, Timeout: 60 * time.Second},
	}
}

// ── Signature V4 ─────────────────────────────────────────────────────────────

// uriEncode is RFC 3986 percent-encoding as SigV4 defines it: unreserved
// characters stay, everything else becomes %XX (upper case). keepSlash keeps
// "/" for object paths.
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(raw string) string {
	vals, _ := url.ParseQuery(raw)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), vals[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sigV4Sign adds X-Amz-Date and Authorization to req. Every header already on
// the request (plus Host) is signed. payloadHash is the hex SHA-256 of the
// body (S3 also wants it sent as X-Amz-Content-Sha256; callers set that).
func sigV4Sign(req *http.Request, payloadHash, service, region, accessKey, secretKey string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	hdrs := map[string]string{"host": host}
	for k, v := range req.Header {
		hdrs[strings.ToLower(k)] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHdrs strings.Builder
	for _, k := range names {
		canonHdrs.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signed := strings.Join(names, ";")

	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	canonReq := strings.Join([]string{
		req.Method, uriEncode(path, true), canonicalQuery(req.URL.RawQuery),
		canonHdrs.String(), signed, payloadHash,
	}, "\n")

	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonReq))
	k := hmacSHA256([]byte("AWS4"+secretKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

// ── Transport ────────────────────────────────────────────────────────────────

// S3Error is an error answer from the server.
type S3Error struct {
	Status  int
	Code    string
	Message string
}

func (e *S3Error) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	case e.Message != "":
		return e.Message
	case e.Code != "":
		return e.Code
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

func parseS3Error(status int, body []byte) *S3Error {
	e := &S3Error{Status: status}
	var x struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(body, &x) == nil && (x.Code != "" || x.Message != "") {
		e.Code, e.Message = x.Code, x.Message
		return e
	}
	var j map[string]any
	if json.Unmarshal(body, &j) == nil {
		for _, k := range []string{"Code", "code"} {
			if v, ok := j[k].(string); ok {
				e.Code = v
			}
		}
		for _, k := range []string{"Message", "message", "error", "Error"} {
			if v, ok := j[k].(string); ok {
				e.Message = v
			}
		}
		return e
	}
	e.Message = strings.TrimSpace(string(body))
	if len(e.Message) > 300 {
		e.Message = e.Message[:300]
	}
	return e
}

// do sends one signed request. path is already "/bucket" or "/rustfs/admin/…";
// query holds the parameters. A 2xx answer returns its body.
func (c *S3Client) do(method, path string, query url.Values, body []byte, headers map[string]string) ([]byte, error) {
	u := c.Endpoint + uriEncode(path, true)
	if len(query) > 0 {
		u += "?" + encodeQuery(query)
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ph := sha256Hex(body)
	req.Header.Set("X-Amz-Content-Sha256", ph)
	sigV4Sign(req, ph, "s3", c.Region, c.AccessKey, c.SecretKey, time.Now())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return out, parseS3Error(resp.StatusCode, out)
	}
	return out, nil
}

// encodeQuery keeps value-less parameters ("?versioning") as "versioning=",
// which every S3 server accepts and signs the same way.
func encodeQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func flag(name string) url.Values { return url.Values{name: {""}} }

const rustfsAdmin = "/rustfs/admin/v3"

// ── Admin: users & policies ──────────────────────────────────────────────────

// ListUsers returns access key → status ("enabled" / "disabled").
func (c *S3Client) ListUsers() (map[string]string, error) {
	b, err := c.do("GET", rustfsAdmin+"/list-users", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("list-users: %w", err)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = v.Status
	}
	return out, nil
}

// PutUser creates a user, or changes its secret (policies are kept).
func (c *S3Client) PutUser(accessKey, secretKey string, enabled bool) error {
	st := "enabled"
	if !enabled {
		st = "disabled"
	}
	body, _ := json.Marshal(map[string]string{"secretKey": secretKey, "status": st})
	_, err := c.do("PUT", rustfsAdmin+"/add-user", url.Values{"accessKey": {accessKey}}, body,
		map[string]string{"Content-Type": "application/json"})
	return err
}

func (c *S3Client) RemoveUser(accessKey string) error {
	_, err := c.do("DELETE", rustfsAdmin+"/remove-user", url.Values{"accessKey": {accessKey}}, nil, nil)
	return err
}

func (c *S3Client) SetUserStatus(accessKey string, enabled bool) error {
	st := "disabled"
	if enabled {
		st = "enabled"
	}
	_, err := c.do("PUT", rustfsAdmin+"/set-user-status", url.Values{"accessKey": {accessKey}, "status": {st}}, nil, nil)
	return err
}

func (c *S3Client) PutPolicy(name string, policy []byte) error {
	_, err := c.do("PUT", rustfsAdmin+"/add-canned-policy", url.Values{"name": {name}}, policy,
		map[string]string{"Content-Type": "application/json"})
	return err
}

func (c *S3Client) RemovePolicy(name string) error {
	_, err := c.do("DELETE", rustfsAdmin+"/remove-canned-policy", url.Values{"name": {name}}, nil, nil)
	return err
}

func (c *S3Client) policyAttach(op, user, policy string) error {
	body, _ := json.Marshal(map[string]any{"policies": []string{policy}, "user": user})
	_, err := c.do("POST", rustfsAdmin+"/idp/builtin/policy/"+op, nil, body,
		map[string]string{"Content-Type": "application/json"})
	return err
}

func (c *S3Client) AttachPolicy(user, policy string) error {
	return c.policyAttach("attach", user, policy)
}
func (c *S3Client) DetachPolicy(user, policy string) error {
	return c.policyAttach("detach", user, policy)
}

// SetBucketQuota sets a hard quota in bytes; 0 removes it.
func (c *S3Client) SetBucketQuota(bucket string, bytes int64) error {
	body, _ := json.Marshal(map[string]any{"quota": bytes, "quotatype": "hard"})
	_, err := c.do("PUT", rustfsAdmin+"/set-bucket-quota", url.Values{"bucket": {bucket}}, body,
		map[string]string{"Content-Type": "application/json"})
	return err
}

// ── S3: buckets ──────────────────────────────────────────────────────────────

func (c *S3Client) ListBuckets() ([]string, error) {
	b, err := c.do("GET", "/", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(r.Buckets))
	for _, x := range r.Buckets {
		out = append(out, x.Name)
	}
	return out, nil
}

func (c *S3Client) MakeBucket(name string, objectLock bool) error {
	h := map[string]string{}
	if objectLock {
		h["x-amz-bucket-object-lock-enabled"] = "true"
	}
	_, err := c.do("PUT", "/"+name, nil, nil, h)
	return err
}

// SetVersioning: "enabled" or "suspended" (a bucket that never had
// versioning stays "off"; S3 has no way back to off).
func (c *S3Client) SetVersioning(bucket, state string) error {
	st := "Enabled"
	if state == "suspended" {
		st = "Suspended"
	}
	body := []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>` + st + `</Status></VersioningConfiguration>`)
	_, err := c.do("PUT", "/"+bucket, flag("versioning"), body, map[string]string{"Content-Type": "application/xml"})
	return err
}

func (c *S3Client) PutBucketPolicy(bucket string, policy []byte) error {
	_, err := c.do("PUT", "/"+bucket, flag("policy"), policy, map[string]string{"Content-Type": "application/json"})
	return err
}

// DeleteBucketPolicy removes the bucket policy; no policy is not an error.
func (c *S3Client) DeleteBucketPolicy(bucket string) error {
	_, err := c.do("DELETE", "/"+bucket, flag("policy"), nil, nil)
	if e, ok := err.(*S3Error); ok && (e.Status == 404 || e.Code == "NoSuchBucketPolicy") {
		return nil
	}
	return err
}

// DeleteBucketForce removes a bucket with everything in it, every version
// included (RustFS's x-rustfs-force-delete).
func (c *S3Client) DeleteBucketForce(bucket string) error {
	_, err := c.do("DELETE", "/"+bucket, nil, nil, map[string]string{"x-rustfs-force-delete": "true"})
	return err
}
