package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/docker/docker/pkg/namesgenerator"
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

func serveLogsPage(w http.ResponseWriter, r *http.Request) {
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
		logsTemplate.Execute(w, struct {
			Name string
		}{Name: strings.Replace(namesgenerator.GetRandomName(0), "_", "-", -1)})
		return
	}

	staticServerLogs.ServeHTTP(w, r)
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
		serverName = helloInfo.ServerName
	}

	if common.SliceContains(indexDomains, serverName) {
		serveMainPage(w, r)
		return
	}
	if strings.HasPrefix(serverName, "logs-") {
		serveLogsPage(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	if isTLSConn {
		if helloInfo != nil {
			if len(helloInfo.SupportedVersions) > 0 {
				fmt.Fprintf(w, "Client supported TLS versions:\n")
				for _, version := range helloInfo.SupportedVersions {
					switch version {
					//case tls.VersionSSL30:
					//	fmt.Fprintf(w, "SSL3.0")
					case tls.VersionTLS10:
						fmt.Fprintf(w, "1.0")
					case tls.VersionTLS11:
						fmt.Fprintf(w, "1.1")
					case tls.VersionTLS12:
						fmt.Fprintf(w, "1.2")
					case tls.VersionTLS13:
						fmt.Fprintf(w, "1.3")
					default:
						fmt.Fprintf(w, "Unknown (0x%x)", version)
					}
					fmt.Fprintln(w, "")
				}
				fmt.Fprintln(w, "")
			}
			if len(helloInfo.CipherSuites) > 0 {
				fmt.Fprintf(w, "Client supported ciphers:\n")
				for _, suite := range helloInfo.CipherSuites {
					//fmt.Fprintf(w, "  %s \n", tls.CipherSuiteName(suite))
					if v, exists := common.CipherSuiteMap[suite]; exists {
						fmt.Fprintf(w, "  %s \n", v)
					} else {
						fmt.Fprintf(w, "  Unknown (0x%x) \n", suite)
					}
				}
				fmt.Fprintln(w, "")
			}

			state := tlsConn.ConnectionState()
			fmt.Fprintf(w, "Negotiated TLS version: ")
			switch state.Version {
			case tls.VersionTLS10:
				fmt.Fprintf(w, "1.0")
			case tls.VersionTLS11:
				fmt.Fprintf(w, "1.1")
			case tls.VersionTLS12:
				fmt.Fprintf(w, "1.2")
			case tls.VersionTLS13:
				fmt.Fprintf(w, "1.3")
			default:
				fmt.Fprintf(w, "Unknown")
			}
			fmt.Fprintln(w, "")

			fmt.Fprintf(w, "Negotiated cipher: ")
			//fmt.Fprintf(w, "%s\n", tls.CipherSuiteName(state.CipherSuite))
			if v, exists := common.CipherSuiteMap[state.CipherSuite]; exists {
				fmt.Fprintf(w, "%s\n", v)
			} else {
				fmt.Fprintf(w, "Unknown (0x%x)\n", state.CipherSuite)
			}
			fmt.Fprintf(w, "SNI: %s\n", helloInfo.ServerName)
			fmt.Fprintln(w, "")
		}
	}

	fmt.Fprintf(w, "Remote: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "Host: %s\n", r.Host)
	fmt.Fprintf(w, "User-Agent: %s\n", r.UserAgent())
	fmt.Fprintf(w, "Proto: %s\n", r.Proto)
	fmt.Fprintf(w, "Server port: %d\n", conn.LocalAddr().(*net.TCPAddr).Port)
}
