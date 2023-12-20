package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"

	// "strings"
	"testing"
)

// 传入空body
func TestEchoEmptyBody(t *testing.T) {
	reqBody := make(map[string]interface{})
	reqBodyInJson, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "http:/0.0.0.0", bytes.NewBuffer(reqBodyInJson))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("host", "foo.com")
	req.Header.Set("X-Echo-Ingress-Info", "false")

	w := httptest.NewRecorder()
	echoHandler(w, req)
	res := w.Result()
	defer res.Body.Close()

	resBodyInJson, err := io.ReadAll(res.Body)
	resBody := make(map[string]interface{})
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	err = json.Unmarshal(resBodyInJson, &resBody)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	if !reflect.DeepEqual(resBody, reqBody) {
		t.Errorf("wrong resbody: %v", string(resBodyInJson))
	}
}

// 基本功能测试
func TestEchoBodyBasic(t *testing.T) {
	reqBody := make(map[string]interface{})
	reqBody["username"]=  []string{"unamexxx"}
	reqBody["password"]=  []string{"pswdxxxx"}
	reqBody["company"]=  []string{"AliBaba", "Tencent"}
	reqBodyInJson, _ := json.MarshalIndent(reqBody, "", " ")

	req := httptest.NewRequest(http.MethodPost, "http:/0.0.0.0", bytes.NewBuffer(reqBodyInJson))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("host", "foo.com")
	req.Header.Set("X-Echo-Ingress-Info", "false")
	
	w := httptest.NewRecorder()
	echoHandler(w, req)
	res := w.Result()
	defer res.Body.Close()

	resBodyInJson, err := io.ReadAll(res.Body)
	resBody := make(map[string]interface{})
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	err = json.Unmarshal(resBodyInJson, &resBody)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	if !reflect.DeepEqual(string(resBodyInJson), string(reqBodyInJson)) {
		t.Errorf("wrong resbody: %v", string(resBodyInJson))
	}
}

// 自定义追加信息
func TestEchoBodyWithExtraSet(t *testing.T) {
	reqBody := make(map[string]interface{})
	reqBody["username"]=  []string{"unamexxx"}
	reqBody["password"]=  []string{"pswdxxxx"}
	reqBody["company"]=  []string{"AliBaba", "Tencent"}
	reqBodyInJson, _ := json.MarshalIndent(reqBody, "", " ")

	req := httptest.NewRequest(http.MethodPost, "http:/0.0.0.0", bytes.NewBuffer(reqBodyInJson))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("host", "foo.com")
	req.Header.Set("X-Echo-Ingress-Info", "false")

	req.Header.Set("X-Echo-Set-Body", "X-not-renamed:test,X-remove:exist,X-replace:not-replaced,X-replace:not-replaced2")
	reqBody["X-not-renamed"]=  []string{"test"}
	reqBody["X-remove"]=  []string{"exist"}
	reqBody["X-replace"]=  []string{"not-replaced","not-replaced2"}
	reqBodyInJson, _ = json.MarshalIndent(reqBody, "", " ")

	w := httptest.NewRecorder()
	echoHandler(w, req)
	res := w.Result()
	defer res.Body.Close()

	resBodyInJson, err := io.ReadAll(res.Body)
	resBody := make(map[string]interface{})
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	err = json.Unmarshal(resBodyInJson, &resBody)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	if !reflect.DeepEqual(string(resBodyInJson), string(reqBodyInJson)) {
		t.Errorf("wrong resbody: %v", string(resBodyInJson))
	}
}