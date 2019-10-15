package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/jdelic/opensmtpd-filters-go"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

type GreylistdFilter struct{}


func debug(format string, values... interface{}) {
	if *debugOutput {
		log.Printf(format, values...)
	}
}


func queryGreylistd(ip string, token string, sessionId string) {
	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		log.Fatalf("Can't connect to Greylistd socket: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fmt.Sprintf("update %s", ip)))
	if err != nil {
		log.Fatalf("Error while reading from Greylistd socket: %v", err)
	}

	var replyBytes bytes.Buffer
	_, err = io.Copy(&replyBytes, conn)
	if err != nil {
		log.Fatalf("Error while reading reply from Greylistd socket: %v", err)
	}

	reply := replyBytes.String()
	switch reply {
	case "grey":
		opensmtpd.Greylist(token, sessionId, fmt.Sprintf("%v greylisted. Try again later.", ip))
		return
	case "black":
		opensmtpd.HardReject(token, sessionId, fmt.Sprintf("%v blacklisted. Transmission denied.", ip))
		return
	case "white":
		opensmtpd.Proceed(token, sessionId)
		return
	}

	debug("Greylistd returned an error or unknown string (%v). Returning temporary error.")
	opensmtpd.SoftReject(token, sessionId, "There seems to be a technical problem on our end. " +
		"Please try again.")
}


func (g GreylistdFilter) LinkConnect(sessionId string, params []string) {
	conn := params[2]
	if conn[0:4] == "unix" {
		debug("Unix socket.")
		return
	} else {
		src := strings.Split(conn, ":")[0]
		go queryGreylistd(src, params[0], sessionId)
	}
}


var debugOutput *bool
var socketPath *string

func main() {
	log.SetOutput(os.Stderr)
	debugOutput = flag.Bool("debug", false, "Enable debug output")
	socketPath = flag.String("s", "/var/run/greylistd/socket", "The path to greylistd")
	flag.Parse()

	debug("Greylistd Socket path is %s\n", *socketPath)

	opensmtpd.Run(GreylistdFilter{})
}
