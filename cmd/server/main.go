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

var staticServer http.Handler
var indexTemplate *template.Template

func main() {
	common.ChangeToSelfDir()

	logger := common.SetupLogger()

	router := http.NewServeMux()
	router.HandleFunc("/", serveHtml)

	fsWeb, err := fs.Sub(webContent, "web")
	if err != nil {
		panic(err)
	}
	staticServer = http.FileServer(http.FS(fsWeb))

	indexTemplate, err = template.ParseFS(fsWeb, "index.html")
	if err != nil {
		panic(err)
	}

	StartServer(logger, router)
}

type output struct {
	SupportedSuites []string `json:"supported_suites"`
	SupportedCurves []string `json:"supported_curves"`
	SupportedPoints []string `json:"supported_points"`
}

func xgetConfigForClientHook(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
	return nil, nil
	/*
		 	o := &output{}
			for _, suite := range helloInfo.CipherSuites {
				if v, exists := CipherSuiteMap[suite]; exists {
					o.SupportedSuites = append(o.SupportedSuites, v)
				} else {
					o.SupportedSuites = append(o.SupportedSuites, fmt.Sprintf("Unknown, 0x%x", suite))
				}
			}

			for _, curve := range helloInfo.SupportedCurves {
				if v, exists := CurveMap[curve]; exists {
					o.SupportedCurves = append(o.SupportedCurves, v)
				} else {
					o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown, 0x%x", curve))
				}
				// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
			}
			for _, point := range helloInfo.SupportedPoints {
				// http://tools.ietf.org/html/rfc4492#section-5.1.2).
				o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
			}

			_, err := json.Marshal(o)
			//log.Println(string(j))

			//log.Println(fmt.Printf("Supported groups: %v", helloInfo.SupportedCurves))

			tlsconfig := tlsConfig()
			tlsconfig.Certificates = []tls.Certificate{cert_ecdsa, cert_rsa}
			//ctx := context.WithValue(context.Background(), "myValue", "some value")
			return tlsconfig, nil
	*/
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

	staticServer.ServeHTTP(w, r)
}

func serveHtml(w http.ResponseWriter, r *http.Request) {
	conn := GetConn(r)
	if _, ok := conn.(*tls.Conn); ok {
		helloInfo := getCHI(conn.RemoteAddr().String())
		if helloInfo != nil {
			if common.SliceContains(indexDomains, helloInfo.ServerName) {
				serveMainPage(w, r)
				return
			}
		}
	}
	if common.SliceContains(indexDomains, r.Host) {
		serveMainPage(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	conn = GetConn(r)
	if cc, ok := conn.(*tls.Conn); ok {
		helloInfo := getCHI(conn.RemoteAddr().String())
		if helloInfo != nil {
			if len(helloInfo.SupportedVersions) > 0 {
				fmt.Fprintf(w, "Client supported TLS versions:\n")
				for _, version := range helloInfo.SupportedVersions {
					switch version {
					case tls.VersionSSL30:
						fmt.Fprintf(w, "SSL3.0")
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

			state := cc.ConnectionState()
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
	fmt.Fprintf(w, "Host: %s\n", r.Host)
	fmt.Fprintf(w, "User-Agent: %s\n", r.UserAgent())
	fmt.Fprintf(w, "Proto: %s\n", r.Proto)
	fmt.Fprintf(w, "Server port: %d\n", conn.LocalAddr().(*net.TCPAddr).Port)
	/*
		 	c := GetConn(r)
			if cc, ok := c.(*tls.Conn); ok {
				state := cc.ConnectionState()
				fmt.Fprintln(w, state.Version)
			}
	*/
}

/* func index() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK!")
	})
}
*/
// supportsECDHE returns whether ECDHE key exchanges can be used with this
// pre-TLS 1.3 client.
/* func supportsECDHE(c *Config, supportedCurves []tls.CurveID, supportedPoints []uint8) bool {

	supportsCurve := false
	for _, curve := range supportedCurves {
		if c.supportsCurve(curve) {
			supportsCurve = true
			break
		}
	}

	supportsPointFormat := false
	for _, pointFormat := range supportedPoints {
		if pointFormat == tls.pointFormatUncompressed {
			supportsPointFormat = true
			break
		}
	}

	return supportsCurve && supportsPointFormat
}
*/
