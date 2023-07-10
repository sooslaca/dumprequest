package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/pkg/namesgenerator"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	log "github.com/sirupsen/logrus"
	"github.com/sooslaca/dumprequest/cmd/server/common"
)

//go:embed web
var webContent embed.FS

//go:embed web-logs
var webLogsContent embed.FS

var staticServerWeb http.Handler
var staticServerLogs http.Handler
var indexTemplate *template.Template
var logsTemplate *template.Template

func init() {
	fsWeb, err := fs.Sub(webContent, "web")
	if err != nil {
		panic(err)
	}
	staticServerWeb = http.FileServer(http.FS(fsWeb))

	indexTemplate, err = template.ParseFS(fsWeb, "index.html")
	if err != nil {
		panic(err)
	}

	fsLogs, err := fs.Sub(webLogsContent, "web-logs")
	if err != nil {
		panic(err)
	}
	staticServerLogs = http.FileServer(http.FS(fsLogs))

	logsTemplate, err = template.ParseFS(fsLogs, "index.html")
	if err != nil {
		panic(err)
	}

}

func serveMainPage(w http.ResponseWriter, r *http.Request) {
	//make sure the url path starts with /
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	upath = path.Clean(upath)

	if upath != "/" {
		f, err := webContent.Open("web" + upath)
		if err != nil {
			fmt.Printf("%v", err)
			if os.IsNotExist(err) {
				http.Error(w, "404 - not found ¯\\_(ツ)_/¯", http.StatusNotFound)
				return
			}
		}
		if err == nil { // check this otherwise panic can happen if above commented out
			f.Close()
		}
	}

	if upath == "/" || upath == "/index.html" {
		indexTemplate.Execute(w, struct {
			Name string
		}{Name: strings.Replace(namesgenerator.GetRandomName(0), "_", "-", -1)})
		return
	}

	staticServerWeb.ServeHTTP(w, r)
}

func serveLogsPage(w http.ResponseWriter, r *http.Request, serverName string) {
	//make sure the url path starts with /
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	upath = path.Clean(upath)

	if upath != "/" {
		f, err := webLogsContent.Open("web-logs" + upath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "404 - not found ¯\\_(ツ)_/¯", http.StatusNotFound)
				return
			}
		}
		if err == nil { // check this otherwise panic can happen if above commented out
			f.Close()
		}
	}

	if upath == "/" || upath == "/index.html" {
		logsTemplate.Execute(w, struct {
			Title string
		}{Title: serverName})
		return
	}

	staticServerLogs.ServeHTTP(w, r)
}

func htmlclient(ua string) bool {
	return strings.Contains(ua, "iPhone")
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 2 {
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}

	requestID, ok := r.Context().Value(requestIDKey).(string)
	if !ok {
		requestID = "unknown"
	}
	mylogger := logger.WithFields(log.Fields{
		"websock_id": requestID,
	})

	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		mylogger.Printf("Error starting server - %s\n", err.Error())
		http.Error(w, "400 - Bad Request ¯\\_(ツ)_/¯", http.StatusBadRequest)
		return
	}

	go func() {
		defer conn.Close()
		mylogger.Println("Client connected")
		for {
			/*msg, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				mylogger.Println("Error receiving data: " + err.Error())
				mylogger.Println("Client disconnected")
				return
			}
			mylogger.Println("Client message received with random number: " + string(msg))*/
			randomNumber := strconv.Itoa(rand.Intn(100))
			err = wsutil.WriteServerMessage(conn, ws.OpText, []byte(randomNumber))
			if err != nil {
				mylogger.Println("Error sending data: " + err.Error())
				mylogger.Println("Client disconnected")
				return
			}
			mylogger.Println("Server message send with random number " + randomNumber)
			time.Sleep(3 * time.Second)
		}
	}()

}

func serveHtml(w http.ResponseWriter, r *http.Request) {
	var helloInfo *tls.ClientHelloInfo
	conn := GetConn(r)
	tlsConn, isTLSConn := conn.(*tls.Conn)
	if isTLSConn {
		helloInfo = getCHI(conn.RemoteAddr().String())
	}

	serverName := r.Host
	if serverName == "" {
		if helloInfo == nil {
			serverName = "!NA!"
		} else {
			serverName = helloInfo.ServerName
		}
	}

	if common.SliceContains(indexDomains, serverName) {
		serveMainPage(w, r)
		return
	}
	if strings.HasPrefix(serverName, "logs-") || strings.HasPrefix(serverName, "logs.") {
		serveLogsPage(w, r, serverName)
		return
	}

	/* 	if r.URL.Path != "/" {
	   		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	   		return
	   	}
	*/

	if htmlclient(r.UserAgent()) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	var output []string
	output = append(output, fmt.Sprintf("Server: %s:%d", r.Host, conn.LocalAddr().(*net.TCPAddr).Port))
	output = append(output, fmt.Sprintf("Remote: %s  [%s GMT]", r.RemoteAddr, time.Now().Format("2006-01-02 15:04:05.000")))
	output = append(output, fmt.Sprintf("%s %s [%s]", r.Method, r.URL, r.Proto))
	output = append(output, "─")

	output = append(output, "--~~~=:> HEADERS <:=~~~--")
	headerkeys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		headerkeys = append(headerkeys, k)
	}
	sort.Strings(headerkeys)
	for _, name := range headerkeys {
		for _, value := range r.Header[name] {
			if strings.ToLower(name) == "cookie" {
				continue
			}
			output = append(output, fmt.Sprintf("%s: %s", name, value))
		}
	}
	output = append(output, "─")
	output = append(output, "--~~~=:> COOKIES <:=~~~--")
	for _, cookie := range r.Cookies() {
		output = append(output, fmt.Sprintf("%s: %s", cookie.Name, cookie.Value))
	}

	if isTLSConn {
		output = append(output, "─")
		output = append(output, "--~~~=:> TLS info <:=~~~--")
		if helloInfo != nil {
			if helloInfo.ServerName == "" {
				output = append(output, "SNI NOT SET")
			} else {
				output = append(output, fmt.Sprintf("SNI: %s", helloInfo.ServerName))
			}
		} else {
			output = append(output, "SNI: UNKNOWN")
		}
		switch tlsConn.ConnectionState().Version {
		case tls.VersionTLS10:
			output = append(output, "Negotiated TLS version: 1.0")
		case tls.VersionTLS11:
			output = append(output, "Negotiated TLS version: 1.1")
		case tls.VersionTLS12:
			output = append(output, "Negotiated TLS version: 1.2")
		case tls.VersionTLS13:
			output = append(output, "Negotiated TLS version: 1.3")
		default:
			output = append(output, "Negotiated TLS version: UNKNOWN")
		}
		if v, exists := common.CipherSuiteMap[tlsConn.ConnectionState().CipherSuite]; exists {
			output = append(output, fmt.Sprintf("Negotiated cipher: %s", v))
		} else {
			output = append(output, fmt.Sprintf("Negotiated cipher: UNKNOWN (0x%x)", tlsConn.ConnectionState().CipherSuite))
		}

		if helloInfo != nil {
			if len(helloInfo.SupportedVersions) > 0 {
				output = append(output, "Client supported TLS versions:")
				for _, version := range helloInfo.SupportedVersions {
					switch version {
					//case tls.VersionSSL30:
					//	output = append(output, "SSL3.0")
					case tls.VersionTLS10:
						output = append(output, "  1.0")
					case tls.VersionTLS11:
						output = append(output, "  1.1")
					case tls.VersionTLS12:
						output = append(output, "  1.2")
					case tls.VersionTLS13:
						output = append(output, "  1.3")
					default:
						output = append(output, fmt.Sprintf("  Unknown (0x%x)", version))
					}
				}
			}
			if len(helloInfo.CipherSuites) > 0 {
				output = append(output, "Client supported ciphers:")
				for _, suite := range helloInfo.CipherSuites {
					if v, exists := common.CipherSuiteMap[suite]; exists {
						output = append(output, fmt.Sprintf("  %s", v))
					} else {
						output = append(output, fmt.Sprintf("  Unknown (0x%x)", suite))
					}
				}
			}
		}
	}

	// write back to client
	longest := 0
	for _, v := range output {
		if len(v) >= longest {
			longest = len(v)
		}
	}

	output = append(output, "─")
	s := "Support this project"
	output = append(output, fmt.Sprintf("%[1]*s", -longest, fmt.Sprintf("%[1]*s", (longest+len(s))/2, s)))
	s = "https://paypal.me/sooslaca"
	output = append(output, fmt.Sprintf("%[1]*s", -longest, fmt.Sprintf("%[1]*s", (longest+len(s))/2, s)))

	if htmlclient(r.UserAgent()) {
		fmt.Fprint(w, "<pre>")
	}
	fmt.Fprint(w, "┌─")
	fmt.Fprint(w, strings.Repeat("─", longest))
	fmt.Fprint(w, "─┐\n")

	for _, v := range output {
		if strings.HasPrefix(v, "─") {
			fmt.Fprint(w, "├─")
		} else {
			fmt.Fprint(w, "│ ")
		}
		fmt.Fprint(w, v)
		for i := len([]rune(v)); i < longest; i++ {
			if strings.HasPrefix(v, "─") {
				fmt.Fprint(w, "─")
			} else {
				fmt.Fprint(w, " ")
			}
		}
		if strings.HasSuffix(v, "─") {
			fmt.Fprint(w, "─┤")
		} else {
			fmt.Fprint(w, " │")
		}
		fmt.Fprint(w, "\n")
	}

	fmt.Fprint(w, "└─")
	fmt.Fprint(w, strings.Repeat("─", longest))
	fmt.Fprint(w, "─┘")
	if htmlclient(r.UserAgent()) {
		fmt.Fprint(w, "</pre>")
	}
	fmt.Fprint(w, "\n")
}
