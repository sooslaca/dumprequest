package common

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

type LogFormat struct {
	TimestampFormat string
}

func SliceContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (f *LogFormat) Format(entry *log.Entry) ([]byte, error) {
	var b *bytes.Buffer

	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	b.WriteByte('[')
	b.WriteString(strings.ToUpper(entry.Level.String()))
	b.WriteString("] ")
	b.WriteString(entry.Time.Format(f.TimestampFormat))

	if entry.Message != "" {
		b.WriteString(" - ")
	}

	/* 	if len(entry.Data) > 0 {
	   		b.WriteString(" || ")
	   	}
	*/
	for key, value := range entry.Data {
		b.WriteByte('[')
		b.WriteString(key)
		b.WriteByte('=')
		fmt.Fprint(b, value)
		b.WriteString("] ")
	}

	if entry.Message != "" {
		if strings.HasPrefix(entry.Message, "http: ") {
			b.WriteString(entry.Message[6:])
		} else {
			b.WriteString(entry.Message)
		}
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

func ChangeToSelfDir() {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	os.Chdir(filepath.Dir(ex))
}

func SetupLogger() *log.Logger {
	formatter := LogFormat{}
	formatter.TimestampFormat = "2006-01-02 15:04:05"

	logger := log.New()
	logger.Out = os.Stdout
	logger.SetFormatter(&formatter)
	return logger
}

func longestLine(input string) (longest string) {
	lines := strings.Split(input, "\n")

	size := 0

	for _, v := range lines {
		//fmt.Println(k,v, "Size: ", len(v))

		if len(v) >= size {
			longest = v
			size = len(v)
		}
	}
	return
}
