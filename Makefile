CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all format generate build

all: generate build

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./c/vmlinux.h
	go generate ./...

build: export CGO_ENABLED := 0
build:
	go build -o ./bin/guardsman ./cmd

format:
	find ./ -iname '*.h' -o -iname '*.c' | xargs clang-format -i
	goimports -w ./..
	gofmt -w ./..
