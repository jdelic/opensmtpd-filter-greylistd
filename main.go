package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/jdelic/opensmtpd-filters-go"
	"golang.org/x/net/publicsuffix"
)

type GreylistdFilter struct{
	opensmtpd.SessionTrackingMixin
}

func (g *GreylistdFilter) GetName() string {
	return "GreylistdFilter"
}

func debug(format string, values... interface{}) {
	if *debugOutput {
		log.Printf(format, values...)
	}
}

func spfResolve(ip, heloName, mailFrom string) bool {
	res, _ := spf.CheckHostWithSender(net.ParseIP(ip), heloName, mailFrom)
	if res == spf.Pass {
		return true
	}
	return false
}

// extractETLDs returns (eTLD+1, eTLD+2).
// eTLD+1 is the registrable domain (example.com / example.co.uk).
// eTLD+2 is the registrable domain plus one additional left-hand label
// (mail.example.com / smtp.sub.example.co.uk). If no extra label exists,
// eTLD+2 is returned as an empty string.
func extractETLDs(rdns string) (etldPlusOne, etldPlusTwo string) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rdns)), ".")
	if host == "" {
		return "", ""
	}

	if e1, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		etldPlusOne = e1
		// If host equals e1, there's no extra label.
		if host == e1 {
			return etldPlusOne, ""
		}
		// If host ends with ".e1", take the immediate label before e1.
		if strings.HasSuffix(host, "."+e1) {
			prefix := strings.TrimSuffix(host, "."+e1)
			parts := strings.Split(prefix, ".")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				if last != "" {
					etldPlusTwo = last + "." + e1
				}
			}
		}
		return etldPlusOne, etldPlusTwo
	}

	return "", ""
}

func queryGreylistd(session *opensmtpd.SMTPSession, ev opensmtpd.FilterEvent) {
	debug("Querying greylistd for rdns: %v", session.Rdns)
	if session.Rdns != "" {
		etld1, etld2 := extractETLDs(session.Rdns)

		if etld1 != "" {
			debug("Querying greylistd for etld1: %v", etld1)
			conn, err := net.Dial("unix", *socketPath)
			if err != nil {
				log.Fatalf("Can't connect to Greylistd socket: %v", err)
			}

			conn.Write([]byte(fmt.Sprintf("check %s", etld1)))
			var etld1Reply bytes.Buffer
			_, err = io.Copy(&etld1Reply, conn)
			if err != nil {
				log.Fatalf("Error while reading reply from Greylistd socket: %v", err)
			}
			conn.Close()

			if etld1Reply.String() == "white" {
				debug("result: whitelisted.")
				ev.Responder().Proceed()
				return
			}
			debug("no match etld1")
		}

		if etld2 != "" {
			debug("Querying greylistd for etld2: %v", etld2)
			conn, err := net.Dial("unix", *socketPath)
			if err != nil {
				log.Fatalf("Can't connect to Greylistd socket: %v", err)
			}

			conn.Write([]byte(fmt.Sprintf("check %s", etld2)))
			var etld2Reply bytes.Buffer
			_, err = io.Copy(&etld2Reply, conn)
			if err != nil {
				log.Fatalf("Error while reading reply from Greylistd socket: %v", err)
			}
			conn.Close()

			if etld2Reply.String() == "white" {
				debug("result: whitelisted.")
				ev.Responder().Proceed()
				return
			}
			debug("no match etld2")
		}
	}

	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		log.Fatalf("Can't connect to Greylistd socket: %v", err)
	}
	defer conn.Close()

	spfpass := spfResolve(session.SrcIp, session.HeloName, session.MailFrom)

	if spfpass {
		domain := strings.SplitN(session.MailFrom, "@", 2)[1]
		if domain == "" {
			domain = session.HeloName
		}
		_, err = conn.Write([]byte(fmt.Sprintf("update %s", domain)))
	} else {
		_, err = conn.Write([]byte(fmt.Sprintf("update %s", session.SrcIp)))
	}
	if err != nil {
		log.Fatalf("Error while reading from Greylistd socket: %v", err)
	}

	var replyBytes bytes.Buffer
	_, err = io.Copy(&replyBytes, conn)
	if err != nil {
		log.Fatalf("Error while reading reply from Greylistd socket: %v", err)
	}

	responder := ev.Responder()
	reply := replyBytes.String()
	switch reply {
	case "grey":
		responder.Greylist(fmt.Sprintf("%s greylisted. Try again later.", session.SrcIp))
		return
	case "black":
		responder.HardReject(fmt.Sprintf("%s blacklisted. Transmission denied.", session.SrcIp))
		return
	case "white":
		responder.Proceed()
		return
	}

	debug("Greylistd returned an error or unknown string (%v). Returning temporary error.")
	responder.SoftReject("There seems to be a technical problem on our end. " +
		"Please try again.")
}

func (g *GreylistdFilter) MailFrom(wrapper opensmtpd.FilterWrapper, event opensmtpd.FilterEvent) {
	debug("MailFrom event received: %v", event.GetAtoms())
	session := g.GetSession(event.GetSessionId())

	// we don't greylist for authenticated sessions
	if session.UserName != "" {
		event.Responder().Proceed()
		return
	}

	conn := session.Src
	if conn[0:4] == "unix" {
		debug("Unix socket.")
		event.Responder().Proceed()
		return
	} else {
		go queryGreylistd(session, event)
	}
}

var debugOutput *bool
var socketPath *string

func main() {
	log.SetOutput(os.Stderr)
	debugOutput = flag.Bool("debug", false, "Enable debug output")
	socketPath = flag.String("s", "/var/run/greylistd/socket", "The path to greylistd")
	test := flag.String("test", "ip helo sender", "Test the filter against a domain")
	flag.Parse()

	if *test != "ip helo sender" {
		strs := strings.SplitN(*test, " ", 3)

		var srcIp, heloName, mailFrom string
		if len(strs) >= 1 {
			srcIp = strs[0]
		}
		if len(strs) >= 2 {
			heloName = strs[1]
		}
		if len(strs) == 3 {
			mailFrom = strs[2]
		}

		if mailFrom == "" {
			res, err := spf.CheckHost(net.ParseIP(srcIp), heloName)
			fmt.Println("CheckHost:", res, "err=", err)
		} else {
			res, err := spf.CheckHostWithSender(net.ParseIP(srcIp), heloName, mailFrom)
			fmt.Println("CheckHostWithSender:", res, "err=", err)
		}

		return
	}

	debug("Greylistd Socket path is %s\n", *socketPath)

	glFilter := opensmtpd.NewFilter(&GreylistdFilter{})
	opensmtpd.Run(glFilter)
}
