# echo-body
A test image for checking http body in e2e test suites.

**将收到的request body放进response body中返回，request与response的ContentType保持一致，目前支持"application/json"，"application/x-www-form-urlencoded"，"multipart/form-data", "text/plain"**

**其他功能：**

1. 支持response body附带ingress信息，header中设置`X-Echo-Ingress-Info`为`true`可开启，（ContentType需为application/json，application/x-www-form-urlencoded或multipart/form-data
2. 支持response body附带自定义数据，header中通过`X-Echo-Set-Body`字段进行设置，（ContentType需为application/json，application/x-www-form-urlencoded或multipart/form-data

**使用：**

1. echo-body镜像构建

```bash
docker build -t <your_registry_hub>/echo-body:1.5.0 -f ./Dockerfile .
```
2. k8s中容器部署

```bash
kubectl apply -f ./test-env.yaml
```

3. k8s中运行

```bash
# 1. 基本功能
curl -v  http:/0.0.0.0 -H "Content-type: application/json"   -H 'host:foo.com'  -d '{"username":["unamexxxx"],"password":["pswdxxxx"], "company":["AliBaba","BliBaba"]}' 
xxx@xxx:~/echo-body$ curl -v  http:/0.0.0.0 -H "Content-type: application/json"   -H 'host:foo.com'  -d '{"username":["unamexxxx"],"password":["pswdxxxx"], "company":["AliBaba","BliBaba"]}' 
*   Trying 0.0.0.0:80...
* Connected to 0.0.0.0 (127.0.0.1) port 80 (#0)
> POST / HTTP/1.1
> Host:foo.com
> User-Agent: curl/7.81.0
> Accept: */*
> Content-type: application/json
> Content-Length: 83
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/json
< x-content-type-options: nosniff
< date: Wed, 20 Dec 2023 12:45:16 GMT
< content-length: 227
< req-cost-time: 0
< req-arrive-time: 1703076316894
< resp-start-time: 1703076316894
< x-envoy-upstream-service-time: 0
< server: istio-envoy
< 
{
 "company": [
  "AliBaba",
  "BliBaba"
 ],
 "ingress": "",
 "namespace": "echo-body-test",
 "password": [
  "pswdxxxx"
 ],
 "pod": "infra-backend-deployment-65c94bfd4b-2bchj",
 "service": "",
 "username": [
  "unamexxxx"
 ]
* Connection #0 to host 0.0.0.0 left intact
}

# 2. 关闭附带ingress信息
xxx@xxx:~/echo-body$ curl -v  http:/0.0.0.0 -H "Content-type: application/json"   -H 'host:foo.com'  -d '{"username":["unamexxxx"],"password":["pswdxxxx"], "company":["AliBaba","BliBaba"]}'  -H 'X-Echo-Ingress-Info:false'
*   Trying 0.0.0.0:80...
* Connected to 0.0.0.0 (127.0.0.1) port 80 (#0)
> POST / HTTP/1.1
> Host:foo.com
> User-Agent: curl/7.81.0
> Accept: */*
> Content-type: application/json
> X-Echo-Ingress-Info:false
> Content-Length: 83
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/json
< x-content-type-options: nosniff
< date: Wed, 20 Dec 2023 12:48:31 GMT
< content-length: 110
< req-cost-time: 0
< req-arrive-time: 1703076511215
< resp-start-time: 1703076511215
< x-envoy-upstream-service-time: 0
< server: istio-envoy
< 
{
 "company": [
  "AliBaba",
  "BliBaba"
 ],
 "password": [
  "pswdxxxx"
 ],
 "username": [
  "unamexxxx"
 ]
* Connection #0 to host 0.0.0.0 left intact
}

# 3. 自定义追加信息
xxx@xxx:~/echo-body$ curl -v  http:/0.0.0.0:3000 -H "Content-type: application/json"   -H 'host:foo.com'  -d '{"username":["unamexxxx"],"password":["pswdxxxx"], "company":["AliBaba","BliBaba"]}'  -H 'X-Echo-Set-Body:X-not-renamed:test,X-remove:exist,X-replace:not-replaced,X-replace:not-replaced2'
*   Trying 0.0.0.0:3000...
* Connected to 0.0.0.0 (127.0.0.1) port 3000 (#0)
> POST / HTTP/1.1
> Host:foo.com
> User-Agent: curl/7.81.0
> Accept: */*
> Content-type: application/json
> X-Echo-Set-Body:X-not-renamed:test,X-remove:exist,X-replace:not-replaced,X-replace:not-replaced2
> Content-Length: 83
> 
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: application/json
< X-Content-Type-Options: nosniff
< Date: Wed, 20 Dec 2023 13:31:40 GMT
< Content-Length: 290
< 
{
 "X-not-renamed": [
  "test"
 ],
 "X-remove": [
  "exist"
 ],
 "X-replace": [
  "not-replaced",
  "not-replaced2"
 ],
 "company": [
  "AliBaba",
  "BliBaba"
 ],
 "ingress": "",
 "namespace": "",
 "password": [
  "pswdxxxx"
 ],
 "pod": "",
 "service": "",
 "username": [
  "unamexxxx"
 ]
* Connection #0 to host 0.0.0.0 left intact
}
```

4. 测试
见测试代码

**备注：**
1. 支持多种类型body，如"application/json"（已支持），"application/x-www-form-urlencoded"，"multipart/form-data"
2. 目前只测试了body为两层嵌套的情况，即`map[string][]string`，更多层嵌套的情况暂未测试
