/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Copyright (c) 2023 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	// "bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// RequestAssertions contains information about the request body and the Ingress
type RequestAssertions struct {
	// Path    string              `json:"path"`
	// Host    string              `json:"host"`
	// Method  string              `json:"method"`
	// Proto   string              `json:"proto"`
	// Headers map[string][]string `json:"headers"`

	Context `json:",inline"`

	TLS *TLSAssertions `json:"tls,omitempty"`
}

// TLSAssertions contains information about the TLS connection.
type TLSAssertions struct {
	Version            string   `json:"version"`
	PeerCertificates   []string `json:"peerCertificates,omitempty"`
	ServerName         string   `json:"serverName"`
	NegotiatedProtocol string   `json:"negotiatedProtocol,omitempty"`
	CipherSuite        string   `json:"cipherSuite"`
}

type preserveSlashes struct {
	mux http.Handler
}

func (s *preserveSlashes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	s.mux.ServeHTTP(w, r)
}

// Context contains information about the context where the echoserver is running
type Context struct {
	Namespace string `json:"namespace"`
	Ingress   string `json:"ingress"`
	Service   string `json:"service"`
	Pod       string `json:"pod"`
}

var context Context

const (
	ContentTypeApplicationJson = "application/json"
	ContentTypeFormUrlencoded  = "application/x-www-form-urlencoded"
	ContentTypeMultipartForm   = "multipart/form-data"
	ContextTypeTextPlain       = "text/plain"
)

func main() {
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "3000"
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	context = Context{
		Namespace: os.Getenv("NAMESPACE"),
		Ingress:   os.Getenv("INGRESS_NAME"),
		Service:   os.Getenv("SERVICE_NAME"),
		Pod:       os.Getenv("POD_NAME"),
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", healthHandler)
	httpMux.HandleFunc("/status/", statusHandler)
	httpMux.HandleFunc("/", echoHandler)
	httpHandler := &preserveSlashes{httpMux}

	errchan := make(chan error)

	go func() {
		fmt.Printf("Starting server, listening on port %s (http)\n", httpPort)
		err := http.ListenAndServe(fmt.Sprintf(":%s", httpPort), httpHandler)
		if err != nil {
			errchan <- err
		}
	}()

	// Enable HTTPS if certificate and private key are given.
	if os.Getenv("TLS_SERVER_CERT") != "" && os.Getenv("TLS_SERVER_PRIVKEY") != "" {
		go func() {
			fmt.Printf("Starting server, listening on port %s (https)\n", httpsPort)
			err := listenAndServeTLS(fmt.Sprintf(":%s", httpsPort), os.Getenv("TLS_SERVER_CERT"), os.Getenv("TLS_SERVER_PRIVKEY"), os.Getenv("TLS_CLIENT_CACERTS"), httpHandler)
			if err != nil {
				errchan <- err
			}
		}()
	}

	select {
	case err := <-errchan:
		panic(fmt.Sprintf("Failed to start listening: %s\n", err.Error()))
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte(`OK`))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	code := http.StatusBadRequest

	re := regexp.MustCompile(`^/status/(\d\d\d)$`)
	match := re.FindStringSubmatch(r.RequestURI)
	if match != nil {
		code, _ = strconv.Atoi(match[1])
	}

	w.WriteHeader(code)
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Echoing back request body made to %s to client (%s)\n", r.RequestURI, r.RemoteAddr)

	contentType := r.Header.Get("Content-Type")
	if len(contentType) == 0 {
		processError(w, fmt.Errorf("Content-Type is not specified"), http.StatusBadRequest)
		return
	}

	reqBodyInBytes, err := io.ReadAll(r.Body)
	var respBodyInBytes []byte
	if err != nil {
		fmt.Errorf("Content-Type invalid or not support: %q", contentType)
		processError(w, err, http.StatusInternalServerError)
		return
	}
	switch contentType {
	case ContextTypeTextPlain:
		respBodyInBytes = reqBodyInBytes[:]
		fmt.Printf("Echoing back %s",string(respBodyInBytes))
	case ContentTypeApplicationJson, ContentTypeFormUrlencoded, ContentTypeMultipartForm:
		respBody := make(map[string]interface{})
		if len(reqBodyInBytes) > 0 {
			err = json.Unmarshal(reqBodyInBytes, &respBody)
			if err != nil {
				processError(w, fmt.Errorf("body unmarshall fail, please check your body format: %q", err.Error()), http.StatusBadRequest)
				return
			}
		}
		
		// body中默认不带ingress信息
		if echoIngressInfo, ok := r.Header["X-Echo-Ingress-Info"]; ok && echoIngressInfo[0] == "true" {
			writeIngressInfo(w, respBody)
		}

		// 追加自定义数据
		if _, ok := r.Header["X-Echo-Set-Body"]; ok {
			writeEchoResponseBody(w, r.Header, respBody)
		}
		respBodyInBytes, err = json.MarshalIndent(respBody, "", " ")
		if err != nil {
			processError(w, err, http.StatusInternalServerError)
			return
		}
	default:
		processError(w, fmt.Errorf("Content-Type invalid or not support: %q", contentType), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(respBodyInBytes)
}

// 将ingress信息追加至response body中
func writeIngressInfo(w http.ResponseWriter, respBody map[string]interface{}) {
	if _, ok := respBody["namespace"]; !ok {
		respBody["namespace"] = context.Namespace
	} else {
		processError(w, fmt.Errorf("namespace field already used in body. If you want to close this warning, please set X-Echo-Ingress-Info to be false."), http.StatusBadRequest)
		return
	}
	if _, ok := respBody["ingress"]; !ok {
		respBody["ingress"] = context.Ingress
	} else {
		processError(w, fmt.Errorf("ingress field already used in body. If you want to close this warning, please set X-Echo-Ingress-Info to be false."), http.StatusBadRequest)
		return
	}
	if _, ok := respBody["service"]; !ok {
		respBody["service"] = context.Service
	} else {
		processError(w, fmt.Errorf("service field already used in body. If you want to close this warning, please set X-Echo-Ingress-Info to be false."), http.StatusBadRequest)
		return
	}
	if _, ok := respBody["pod"]; !ok {
		respBody["pod"] = context.Pod
	} else {
		processError(w, fmt.Errorf("pod field already used in body. If you want to close this warning, please set X-Echo-Ingress-Info to be false."), http.StatusBadRequest)
		return
	}
}

// 将request header["X-Echo-Set-Body"]中的内容追加至response body中
func writeEchoResponseBody(w http.ResponseWriter, headers http.Header, respBody map[string]interface{}) {
	kvs := make(map[string][]string)
	for _, bodyKVList := range headers["X-Echo-Set-Body"] {
		bodyKVs := strings.Split(bodyKVList, ",")
		for _, bodyKV := range bodyKVs {
			name, value, _ := strings.Cut(strings.TrimSpace(bodyKV), ":")
			kvs[name] = append(kvs[name], string(value))
		}
	}
	for key, vs := range kvs {
		if _, ok := respBody[key]; !ok {
			respBody[key] = vs
		}
	}
}

func processError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	body, err := json.Marshal(struct {
		Message string `json:"message"`
	}{
		err.Error(),
	})
	if err != nil {
		w.WriteHeader(code)
		fmt.Fprintln(w, err)
		return
	}

	w.WriteHeader(code)
	w.Write(body)
}

func listenAndServeTLS(addr string, serverCert string, serverPrivKey string, clientCA string, handler http.Handler) error {
	var config tls.Config

	// Optionally enable client certificate validation when client CA certificates are given.
	if clientCA != "" {
		ca, err := ioutil.ReadFile(clientCA)
		if err != nil {
			return err
		}

		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return fmt.Errorf("unable to append certificate in %q to CA pool", clientCA)
		}

		// Verify certificate against given CA but also allow unauthenticated connections.
		config.ClientAuth = tls.VerifyClientCertIfGiven
		config.ClientCAs = certPool
	}

	srv := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: &config,
	}

	return srv.ListenAndServeTLS(serverCert, serverPrivKey)
}

func tlsStateToAssertions(connectionState *tls.ConnectionState) *TLSAssertions {
	if connectionState != nil {
		var state TLSAssertions

		switch connectionState.Version {
		case tls.VersionTLS13:
			state.Version = "TLSv1.3"
		case tls.VersionTLS12:
			state.Version = "TLSv1.2"
		case tls.VersionTLS11:
			state.Version = "TLSv1.1"
		case tls.VersionTLS10:
			state.Version = "TLSv1.0"
		}

		state.NegotiatedProtocol = connectionState.NegotiatedProtocol
		state.ServerName = connectionState.ServerName
		state.CipherSuite = tls.CipherSuiteName(connectionState.CipherSuite)

		// Convert peer certificates to PEM blocks.
		for _, c := range connectionState.PeerCertificates {
			var out strings.Builder
			pem.Encode(&out, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			})
			state.PeerCertificates = append(state.PeerCertificates, out.String())
		}

		return &state
	}

	return nil
}
