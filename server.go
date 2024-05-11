// Copyright (C) 2022 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"src.agwa.name/go-listener/proxy"
	"src.agwa.name/go-listener/tlsutil"

	"slices"
	"encoding/json"
	"io/ioutil"
	"regexp"
	"fmt"
)

type Server struct {
	Backend         BackendDialer
	ProxyProtocol   bool
	DefaultHostname string
	FilterJson		string
	AllowedNames 	[]string
	DeniedNames		[]string
	AllowedPatterns []*regexp.Regexp
	DeniedPatterns	[]*regexp.Regexp
}

func (server *Server) peekClientHello(clientConn net.Conn) (*tls.ClientHelloInfo, net.Conn, error) {
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, nil, err
	}

	clientHello, peekedClientConn, err := tlsutil.PeekClientHelloFromConn(clientConn)
	if err != nil {
		return nil, nil, err
	}

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}

	if clientHello.ServerName == "" {
		if server.DefaultHostname == "" {
			return nil, nil, errors.New("no SNI provided and DefaultHostname not set")
		}
		clientHello.ServerName = server.DefaultHostname
	}

	// Evaluate Blacklisted names then patterns first
	if ( len(server.DeniedNames)!=0 && slices.Contains(server.DeniedNames, clientHello.ServerName)) {
		return nil, nil, errors.New(fmt.Sprintf("Blacklist contains domain %s", clientHello.ServerName))
	}
	if ( len(server.DeniedPatterns)!=0 && patternMatch(server.DeniedPatterns, clientHello.ServerName)) {
		return nil, nil, errors.New(fmt.Sprintf("Blacklist Pattern matches domain %s", clientHello.ServerName))
	}

	// If both whitelist and whitelist regex are defined, either success is good enough to continue
	if ( len(server.AllowedNames)!=0 && len(server.AllowedPatterns)!=0 ) {
			if ( !slices.Contains(server.AllowedNames, clientHello.ServerName) && !patternMatch(server.AllowedPatterns, clientHello.ServerName) )	{
				return nil, nil, errors.New(fmt.Sprintf("Whitelist and Patterns do not match domain %s", clientHello.ServerName))
			}
	} else {
		if ( len(server.AllowedNames)!=0 && !slices.Contains(server.AllowedNames, clientHello.ServerName)) {
			return nil, nil, errors.New(fmt.Sprintf("Whitelist does not contain domain %s", clientHello.ServerName))
		}
		if ( len(server.AllowedPatterns)!=0 && !patternMatch(server.AllowedPatterns, clientHello.ServerName)) {
			return nil, nil, errors.New(fmt.Sprintf("Whitelist Pattern does not match domain %s", clientHello.ServerName))
		}
	}


	return clientHello, peekedClientConn, err
}

func (server *Server) handleConnection(clientConn net.Conn) {
	defer func() { clientConn.Close() }()

	var clientHello *tls.ClientHelloInfo

	if peekedClientHello, peekedClientConn, err := server.peekClientHello(clientConn); err == nil {
		clientHello = peekedClientHello
		clientConn = peekedClientConn
	} else {
		log.Printf("Peeking client hello from %s failed: %s", clientConn.RemoteAddr(), err)
		return
	}

	backendConn, err := server.Backend.Dial(clientHello.ServerName, clientHello.SupportedProtos, clientConn)
	if err != nil {
		log.Printf("Ignoring connection from %s because dialing backend failed: %s", clientConn.RemoteAddr(), err)
		return
	}
	defer backendConn.Close()

	if server.ProxyProtocol {
		header := proxy.Header{RemoteAddr: clientConn.RemoteAddr(), LocalAddr: clientConn.LocalAddr()}
		if _, err := backendConn.Write(header.Format()); err != nil {
			log.Printf("Error writing PROXY header to backend: %s", err)
			return
		}
	}

	go func() {
		io.Copy(backendConn, clientConn)
		backendConn.CloseWrite()
	}()

	io.Copy(clientConn, backendConn)
}

func (server *Server) Serve(listener net.Listener) error {
	if( len(server.FilterJson)>0 ){
		err := server.loadFilterList(server.FilterJson)
		if err != nil {
			log.Println("Cannot parse FilterJson")
		}
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if netErr, isNetErr := err.(net.Error); isNetErr && netErr.Temporary() {
				log.Printf("Temporary network error accepting connection: %s", netErr)
				continue
			}
			return err
		}
		go server.handleConnection(conn)
	}
}

func (server *Server) loadFilterList(filename string) error {
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println("Error opening whitelist file ", filename)
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal(fileData, &jsonData)
	if err != nil {
		log.Println(filename, "Does not contain valid json")
		log.Println(fileData)
		return nil
	}
	candidateWhitelistNames := jsonData["whitelist_names"].([]interface{})
	candidateBlacklistNames := jsonData["blacklist_names"].([]interface{})
	candidateWhitelistPatterns := jsonData["whitelist_patterns"].([]interface{})
	candidateBlacklistPatterns := jsonData["blacklist_patterns"].([]interface{})

	if len(candidateBlacklistNames) >0 {
		newBlackList := domainFilter(candidateBlacklistNames)
		log.Printf("Filtered provided blacklist to :  %#q", newBlackList)
		server.DeniedNames = newBlackList;
	}
	if len(candidateBlacklistPatterns) > 0 {
		newBlackPattern, matchedStrings := patternFilter(candidateBlacklistPatterns)
		log.Printf("Filtered provided blacklist regex to :  %#q", matchedStrings)
		server.DeniedPatterns = newBlackPattern
	}

	if len(candidateWhitelistNames) >0 {
		newWhiteList := domainFilter(candidateWhitelistNames)
		log.Printf("Filtered provided whitelist to :  %#q", newWhiteList)
		server.AllowedNames = newWhiteList;
	}

	if len(candidateWhitelistPatterns) > 0 {
		newWhitePattern, matchedStrings := patternFilter(candidateWhitelistPatterns)
		log.Printf("Filtered provided whitelist regex to : %#q", matchedStrings)
		server.AllowedPatterns = newWhitePattern
	}
	
	return nil
}

func domainFilter(candidates []interface{}) (filtered []string) {
	domainRequirement := regexp.MustCompile(`^(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+).([a-z]){2,}$`)
	for _, testing := range candidates {
		s := testing.(string)
		if domainRequirement.MatchString(s) && !slices.Contains(filtered, s) {
			filtered = append(filtered, s)
		} else {
			log.Println("Invalid or duplicate domain in whitelist file : ", s)
		}
	}
	return filtered
}

func patternFilter(candidates []interface{}) (filtered []*regexp.Regexp, summary []string) {
	for _, testing := range candidates {
		s := testing.(string)
		regexpProbe, err := regexp.Compile(s)
		if err != nil {
			log.Println("Invalid regex ", s)
			log.Println(err)
			continue;
		}
		if ( !slices.Contains(summary,s) ){
			filtered = append(filtered,regexpProbe)
			summary = append(summary,s)
		}
	}
	return filtered, summary
}

func patternMatch(patterns []*regexp.Regexp, needle string) (bool) {
	for _, pattern := range patterns {
		if pattern.MatchString(needle) {
			return true
		}
	}
	return false
}