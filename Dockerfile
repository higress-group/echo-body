# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build
FROM golang:1.19.0 as builder

ENV CGO_ENABLED=0

WORKDIR /go/src/higress-group/echo-body

COPY echo-body.go go.mod .

RUN go build -trimpath -ldflags="-buildid= -s -w" -o echo-body .

# Use distroless as minimal base image to package the binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details

# FROM gcr.io/distroless/static:nonroot
FROM registry.cn-hangzhou.aliyuncs.com/base-containers/distroless:nonroot

WORKDIR /
COPY --from=builder /go/src/higress-group/echo-body /
USER nonroot:nonroot

ENTRYPOINT ["/echo-body"]
