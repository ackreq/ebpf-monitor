APP=ebpf-monitor

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: vmlinux.h
	go generate

.PHONY: fmt
fmt:
	go fmt *.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm gen_execve_*
	-rm vmlinux.h

$(APP): main.go gen_execve_bpfel.go
	CGO_ENABLED=0 go build -o $(APP)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
