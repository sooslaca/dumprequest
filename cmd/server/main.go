package main

import (
	"net/http"

	"github.com/sooslaca/dumprequest/cmd/server/common"
)

func main() {
	common.ChangeToSelfDir()

	logger := common.SetupLogger()

	// handlers
	router := http.NewServeMux()
	router.HandleFunc("/", serveHtml)
	//router.Handle("/metrics", promhttp.Handler())

	StartServer(logger, router)
}

type output struct {
	SupportedSuites []string `json:"supported_suites"`
	SupportedCurves []string `json:"supported_curves"`
	SupportedPoints []string `json:"supported_points"`
}

/*func xgetConfigForClientHook(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
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
//}

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
