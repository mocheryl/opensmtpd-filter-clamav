// $Id: filter-clamav.go 66 2024-04-14 16:44:05Z umaxx $
// Copyright (c) 2019-2024 Joerg Jung <mail@umaxx.net>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// filter-clamav - opensmtpd filter for clamav

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
	"strings"
)

const (
	v  = "0.6+p0"
	yr = "2019-2024"
)

type closeWriter interface {
	CloseWrite() error
}

type clamav struct {
	sid string
	buf []string
	r   *bool
}

var (
	addr = "localhost:3310"
	l3   *syslog.Writer
	cls  = make(map[string]*clamav)
)

func (cl *clamav) reset(tok string) {
	if cl.buf != nil {
		for _, v := range cl.buf {
			fmt.Printf("filter-dataline|%s|%s|%s\n", cl.sid, tok, v)
		}
	}
	cl.buf = nil
	cl.r = nil
}

func (cl *clamav) status(tok string, ln string) {
	ln = strings.TrimSpace(ln)
	if ln != "stream: OK" && !strings.HasSuffix(ln, "FOUND") {
		l3.Err(fmt.Sprintln(cl.sid, "result", ln))
		cl.reset(tok)
		return
	}
	l3.Info(fmt.Sprintln(cl.sid, "result", ln))
	cl.r = new(bool)
	*cl.r = (ln != "stream: OK")
}

func (cl *clamav) response(tok string, in *bufio.Scanner) {
	if in.Scan() {
		cl.status(tok, in.Text())
		if in.Scan() {
			l3.Warning(fmt.Sprintln(cl.sid, "response"))
		}
	}
	if e := in.Err(); e != nil {
		l3.Err(fmt.Sprintln(cl.sid, "scanner", e))
		cl.reset(tok)
		return
	}
}

func (cl *clamav) process(tok string) {
	netw := `tcp`
	if addr[0] == '/' {
		netw = `unix`
	}
	con, e := net.Dial(netw, addr)
	if e != nil {
		l3.Err(fmt.Sprintln(cl.sid, e))
		cl.reset(tok)
		return
	}
	defer con.Close()
	if _, e = fmt.Fprintf(con, "nINSTREAM\n"); e != nil {
		l3.Err(fmt.Sprintln(cl.sid, "write", e))
		cl.reset(tok)
		return
	}
	b := make([]byte, 4)
	for _, v := range cl.buf {
		binary.BigEndian.PutUint32(b, uint32(len(v)+1))
		if _, e = fmt.Fprintf(con, "%s%s\n", b, v); e != nil {
			l3.Err(fmt.Sprintln(cl.sid, "write", e))
			cl.reset(tok)
			return
		}
	}
	binary.BigEndian.PutUint32(b, 0)
	if _, e = fmt.Fprintf(con, "%s", b); e != nil {
		l3.Err(fmt.Sprintln(cl.sid, "write", e))
		cl.reset(tok)
		return
	}
	if c, ok := con.(closeWriter); ok {
		if e = c.CloseWrite(); e != nil {
			l3.Warning(fmt.Sprintln(cl.sid, "closewrite", e))
		}
	}
	cl.response(tok, bufio.NewScanner(con))
	for _, v := range cl.buf {
		fmt.Printf("filter-dataline|%s|%s|%s\n", cl.sid, tok, v)
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", cl.sid, tok)
}

func (cl *clamav) line(tok string, ln string) {
	if ln == "." {
		go cl.process(tok)
		return
	}
	cl.buf = append(cl.buf, ln)
}

func (cl *clamav) commit(tok string) {
	if cl.r == nil {
		l3.Warning(fmt.Sprintln(cl.sid, "reject filter failed"))
		fmt.Printf("filter-result|%s|%s|reject|451 4.7.1 Virus filter failed\n", cl.sid, tok)
	} else if *cl.r {
		l3.Info(fmt.Sprintln(cl.sid, "reject virus"))
		fmt.Printf("filter-result|%s|%s|reject|554 5.7.1 Virus found\n", cl.sid, tok)
	} else {
		l3.Debug(fmt.Sprintln(cl.sid, "accept"))
		fmt.Printf("filter-result|%s|%s|proceed\n", cl.sid, tok)
	}
}

func register(in *bufio.Scanner) error {
	l3.Info("register")
	for in.Scan() { // skip config
		if in.Text() == "config|ready" {
			fmt.Println("register|report|smtp-in|link-connect")
			fmt.Println("register|filter|smtp-in|data-line")
			fmt.Println("register|filter|smtp-in|commit")
			fmt.Println("register|report|smtp-in|link-disconnect")
			fmt.Println("register|ready")
			return nil
		}
	}
	return in.Err()
}

func run() {
	l3.Info("start")
	defer l3.Info("exit")
	in := bufio.NewScanner(os.Stdin)
	if e := register(in); e != nil {
		l3.Err(fmt.Sprintln("register", e))
		return
	}
	for in.Scan() {
		f := strings.Split(in.Text(), "|")
		t, ver, ev, sid := f[0], f[1], f[4], f[5]
		if (t != "filter" && t != "report") || ver != "0.7" {
			l3.Err(fmt.Sprintln(sid, "protocol", t, ver))
			return
		}
		switch ev {
		case "link-connect":
			cls[sid] = &clamav{sid: sid, buf: nil, r: nil}
		case "data-line":
			if c, ok := cls[sid]; ok {
				c.line(f[6], strings.Join(f[7:], "|"))
			}
		case "commit":
			if c, ok := cls[sid]; ok {
				c.commit(f[6])
			}
		case "link-disconnect":
			if c, ok := cls[sid]; ok {
				delete(cls, c.sid)
			}
		default:
			l3.Err(fmt.Sprintln(sid, "event", ev))
			return
		}
	}
	if e := in.Err(); e != nil {
		l3.Err(fmt.Sprintln("scanner", e))
		return
	}
}

func init() {
	log.SetFlags(log.Lshortfile)
}

func main() {
	var e error
	if len(os.Args) == 2 && os.Args[1] == "version" {
		if err := pledgePromises("stdio", "unveil"); err != nil {
			log.Fatalf("Could not pledge promise: %s\n", err)
		}
		if err := unveilAndBlock(); err != nil {
			log.Fatalf("Could not unveil and block: %s\n", err)
		}

		fmt.Println("filter-clamav", v, "(c)", yr, "Joerg Jung")
		return
	}
	if err := pledgePromises("stdio", "inet", "dns", "unix", "unveil"); err != nil {
		log.Fatalf("Could not pledge promise: %s\n", err)
	}
	if len(os.Args) > 2 {
		log.Fatalf("usage: filter-clamav [<address>]\n%35sfilter-clamav version\n", "")
	}
	if len(os.Args) == 2 {
		addr = os.Args[1]
	}
	u := []string{"/dev/log"}
	if addr[0] == '/' {
		u = append(u, addr)
	}
	if err := unveilReadWrite(u...); err != nil {
		log.Fatalf("Could not unveil for reading and writing: %s\n", err)
	}
	if err := unveilAndBlock("/etc/resolv.conf", "/etc/hosts"); err != nil {
		log.Fatalf("Could not unveil and block: %s\n", err)
	}
	if l3, e = syslog.New(syslog.LOG_MAIL, "filter-clamav"); e != nil {
		log.Fatal(e)
	}
	defer l3.Close()
	run()
}
