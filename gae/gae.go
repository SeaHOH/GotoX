package gae

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"appengine"
	"appengine/urlfetch"
)

const (
	Version  = "r9999"
	Password = ""

	DefaultFetchMaxSize        = 1024 * 1024 * 4
	DefaultDeadline            = 20 * time.Second
	DefaultOverquotaDelay      = 4 * time.Second
	DefaultURLFetchClosedDelay = 1 * time.Second
	DefaultDebug               = 0
)

func IsBinary(b []byte) bool {
	if len(b) > 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		// utf-8 text
		return false
	}
	for i, c := range b {
		if c > 0x7f {
			return true
		}
		if c == '\n' && i > 4 {
			break
		}
		if i > 32 {
			break
		}
	}
	return false
}

func IsTextContentType(contentType string) bool {
	// text/* for html, plain text
	// application/{json, javascript} for ajax
	// application/{xml, rss, atom} for xml
	// application/x-www-form-urlencoded for some video api
	parts := strings.SplitN(contentType, "/", 2)
	mct := parts[0]
	if mct == "text" {
		return true
	}
	if mct == "application" {
		sct := strings.SplitN(parts[1], ";", 2)[0]
		return sct == "json" ||
			strings.HasSuffix(sct, "script") ||
			strings.HasSuffix(sct, "xml") ||
			strings.HasPrefix(sct, "xml") ||
			strings.HasPrefix(sct, "rss") ||
			strings.HasPrefix(sct, "atom") ||
			sct == "x-www-form-urlencoded"
	}
	return false
}

func ReadRequest(r io.Reader) (req *http.Request, err error) {
	req = new(http.Request)

	scanner := bufio.NewScanner(r)
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			err = fmt.Errorf("Invaild Request Line: %#v", line)
			return
		}

		req.Method = parts[0]
		req.RequestURI = parts[1]

		if req.URL, err = url.Parse(req.RequestURI); err != nil {
			return
		}
		req.Host = req.URL.Host

		req.Header = http.Header{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		req.Header.Add(key, value)
	}

	if err = scanner.Err(); err != nil {
		// ignore
	}

	if cl := req.Header.Get("Content-Length"); cl != "" {
		if req.ContentLength, err = strconv.ParseInt(cl, 10, 64); err != nil {
			return
		}
	}

	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}

	return
}

func fmtError(c appengine.Context, err error) string {
	return fmt.Sprintf(`{
    "type": "appengine(%s, %s/%s)",
    "host": "%s",
    "software": "%s",
    "error": "%s"
}
`, runtime.Version(), runtime.GOOS, runtime.GOARCH, appengine.DefaultVersionHostname(c), appengine.ServerSoftware(), err.Error())
}

func handlerError(c appengine.Context, rw http.ResponseWriter, err error, code int) {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestCompression)

	data := fmtError(c, err)
	fmt.Fprintf(w, "HTTP/1.1 %d\r\n", code)
	fmt.Fprintf(w, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(w, "Content-Length: %d\r\n", len(data))
	io.WriteString(w, "\r\n")
	io.WriteString(w, data)
	w.Close()

	b0 := []byte{0, 0}
	binary.BigEndian.PutUint16(b0, uint16(b.Len()))

	rw.Header().Set("Content-Type", "image/gif")
	//rw.Header().Set("Content-Length", strconv.Itoa(len(b0)+b.Len()))
	//rw.WriteHeader(http.StatusOK)
	rw.Write(b0)
	rw.Write(b.Bytes())
}

func handler(rw http.ResponseWriter, r *http.Request) {
	var err error
	c := appengine.NewContext(r)

	var hdrLen uint16
	if err := binary.Read(r.Body, binary.BigEndian, &hdrLen); err != nil {
		c.Criticalf("binary.Read(&hdrLen) return %v", err)
		handlerError(c, rw, err, http.StatusBadRequest)
		return
	}

	req, err := ReadRequest(bufio.NewReader(flate.NewReader(&io.LimitedReader{R: r.Body, N: int64(hdrLen)})))
	if err != nil {
		c.Criticalf("http.ReadRequest(%#v) return %#v", r.Body, err)
		handlerError(c, rw, err, http.StatusBadRequest)
		return
	}

	req.RemoteAddr = r.RemoteAddr
	req.TLS = r.TLS
	req.Body = r.Body
	defer req.Body.Close()

	params := make(map[string]string)
	if options := req.Header.Get("X-UrlFetch-Options"); options != "" {
		for _, pair := range strings.Split(options, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 1 {
				params[strings.TrimSpace(pair)] = ""
			} else {
				params[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		req.Header.Del("X-UrlFetch-Options")
	}

	oAE := req.Header.Get("Accept-Encoding")

	debug := DefaultDebug
	if s, ok := params["debug"]; ok && s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			debug = n
		}
	}

	if debug > 1 {
		c.Infof("Parsed Request=%#v\n", req)
	}

	if Password != "" {
		password, ok := params["password"]
		if !ok {
			handlerError(c, rw, fmt.Errorf("urlfetch password required"), http.StatusForbidden)
			return
		} else if password != Password {
			handlerError(c, rw, fmt.Errorf("urlfetch password is wrong"), http.StatusForbidden)
			return
		}
	}

	//deadline := DefaultDeadline
	//if s, ok := params["deadline"]; ok && s != "" {
	//	if n, err := strconv.Atoi(s); err == nil {
	//		deadline = time.Duration(n) * time.Second
	//	}
	//}
	deadline := 5

	fetchMaxSize := DefaultFetchMaxSize
	if s, ok := params["maxsize"]; ok && s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			fetchMaxSize = n
		}
	}

	_, sslVerify := params["sslverify"]

	var resp *http.Response
	for i := 0; i < 2; i++ {
		t := &urlfetch.Transport{
			Context:                       c,
			// useless now, set in Context
			//Deadline:                      deadline,
			AllowInvalidServerCertificate: !sslVerify,
		}

		resp, err = t.RoundTrip(req)
		if resp != nil && resp.Body != nil {
			if v := reflect.ValueOf(resp.Body).Elem().FieldByName("truncated"); v.IsValid() {
				if truncated := v.Bool(); truncated {
					resp.Body.Close()
					err = errors.New("URLFetchServiceError_RESPONSE_TOO_LARGE")
				}
			}
		}

		if err == nil {
			defer resp.Body.Close()
			break
		}

		message := err.Error()
		if strings.Contains(message, "RESPONSE_TOO_LARGE") {
			c.Warningf("URLFetchServiceError %T(%v) deadline=%v, url=%v", err, err, deadline, req.URL.String())
			if s := req.Header.Get("Range"); s != "" {
				if parts1 := strings.Split(s, "="); len(parts1) == 2 {
					if parts2 := strings.Split(parts1[1], "-"); len(parts2) == 2 {
						if start, err1 := strconv.Atoi(parts2[0]); err1 == nil {
							end, err1 := strconv.Atoi(parts2[1])
							if err1 != nil {
								req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+fetchMaxSize))
							} else {
								if end-start > fetchMaxSize {
									req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+fetchMaxSize))
								} else {
									req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
								}
							}
						}
					}
				}
			} else {
				req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fetchMaxSize))
			}
		} else if strings.Contains(message, "Over quota") {
			c.Warningf("URLFetchServiceError %T(%v) deadline=%v, url=%v", err, err, deadline, req.URL.String())
			time.Sleep(DefaultOverquotaDelay)
		} else if strings.Contains(message, "urlfetch: CLOSED") {
			c.Warningf("URLFetchServiceError %T(%v) deadline=%v, url=%v", err, err, deadline, req.URL.String())
			time.Sleep(DefaultURLFetchClosedDelay)
		} else {
			c.Errorf("URLFetchServiceError %T(%v) deadline=%v, url=%v", err, err, deadline, req.URL.String())
			break
		}
	}

	if err != nil {
		handlerError(c, rw, err, http.StatusBadGateway)
		return
	}

	// rewise resp.Header
	resp.Header.Del("Transfer-Encoding")
	if strings.ToLower(resp.Header.Get("Vary")) == "accept-encoding" {
		resp.Header.Del("Vary")
	}
	if resp.ContentLength > 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	oCE := resp.Header.Get("Content-Encoding")
	chunked := false

	// urlfetch will try to decompress the content when "Accept-Encoding" does not contain "gzip"
	// delete "Content-Encoding" when content has decompressed with supported encoding
	if !strings.Contains(oAE, "gzip") &&
		(oCE == "gzip" || oCE == "deflate" || oCE == "br") {
		resp.Header.Del("Content-Encoding")
		oCE = ""
	}

	if oCE == "" &&
		IsTextContentType(resp.Header.Get("Content-Type")) {
		content := reflect.ValueOf(resp.Body).Elem().FieldByName("content").Bytes()
		if IsBinary(content) {
			// urlfetch will remove "Content-Encoding: deflate" when "Accept-Encoding" contains "gzip"
			ext := filepath.Ext(req.URL.Path)
			if ext == "" || IsTextContentType(mime.TypeByExtension(ext)) {
				// ignore wrong "Content-Type"
				resp.Header.Set("Content-Encoding", "deflate")
			}
		} else {
			chunked = true
		}
	}

	if debug > 1 {
		c.Infof("Write Response=%#v\n", resp)
	}

	if debug > 0 {
		c.Infof("%s \"%s %s %s\" %d %s", resp.Request.RemoteAddr, resp.Request.Method, resp.Request.URL.String(), resp.Request.Proto, resp.StatusCode, resp.Header.Get("Content-Length"))
	}

	b := &bytes.Buffer{}

	if chunked {
		fmt.Fprintf(b, "HTTP/1.1 %s\r\n", resp.Status)
		resp.Header.Write(b)
		io.WriteString(b, "\r\n")

		rw.Header().Set("Content-Type", "text/plain")
	} else {
		w, _ := flate.NewWriter(b, flate.BestCompression)
		fmt.Fprintf(w, "HTTP/1.1 %s\r\n", resp.Status)
		resp.Header.Write(w)
		io.WriteString(w, "\r\n")
		w.Close()

		b0 := []byte{0, 0}
		binary.BigEndian.PutUint16(b0, uint16(b.Len()))

		rw.Header().Set("Content-Type", "image/gif")
		// we need not set a "Content-Length" header, App Engine will reset it
		//rw.Header().Set("Content-Length", strconv.FormatInt(int64(len(b0)+b.Len())+resp.ContentLength, 10))
		//rw.WriteHeader(http.StatusOK)
		rw.Write(b0)
	}
	io.Copy(rw, io.MultiReader(b, resp.Body))
}

func favicon(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

func robots(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(rw, "User-agent: *\nDisallow: /\n")
}

func root(rw http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	version, _ := strconv.ParseInt(strings.Split(appengine.VersionID(c), ".")[1], 10, 64)
	ctime := time.Unix(version/(1<<28), 0).Format(time.RFC3339)

	var latest string
	t := &urlfetch.Transport{Context: c}
	req, _ := http.NewRequest("GET", "https://github.com/SeaHOH/GotoX/commits/gaeserver.goproxy/gae", nil)
	resp, err := t.RoundTrip(req)
	if err != nil {
		latest = err.Error()
	} else {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			latest = err.Error()
		} else {
			latest = regexp.MustCompile(`\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ`).FindString(string(data))
		}
	}

	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var message string
	switch {
	case latest == "":
		message = "unable check goproxy latest version, please try after 5 minutes."
	case latest <= ctime:
		message = "already update to latest."
	default:
		message = "please update this server"
	}
	fmt.Fprintf(rw, `{
	"server": "goproxy %s (%s, %s/%s)"
	"latest": "%s",
	"deploy": "%s",
	"message": "%s"
}
`, Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, latest, ctime, message)
}

func init() {
	http.HandleFunc("/_gh/", handler)
	http.HandleFunc("/favicon.ico", favicon)
	http.HandleFunc("/robots.txt", robots)
	http.HandleFunc("/", root)
}
