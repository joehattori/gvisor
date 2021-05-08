package p9

// JOETODO: move this file out from package p9.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/bytecodealliance/wasmtime-go"
	"gvisor.dev/gvisor/pkg/log"
)

// JOETODO: wrap rustfer with new go routine, and use sync.Once.

var rustfer struct {
	instance *wasmtime.Instance
	memory   *wasmtime.Memory
}

func initWasm() error {
	log.Infof("initWasm called!")
	wasmFile := "/rustfer/rustfer.wasm"

	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(store)
	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.InheritStderr()
	wasiConfig.InheritStdout()

	for _, dir := range []string{"."} {
		if err := wasiConfig.PreopenDir(dir, dir); err != nil {
			return err
		}
	}
	// if err := wasiConfig.PreopenDir("/", "/"); err != nil {
	// 	return err
	// }

	wasi, err := wasmtime.NewWasiInstance(store, wasiConfig, "wasi_snapshot_preview1")
	if err != nil {
		return err
	}

	if err = linker.DefineWasi(wasi); err != nil {
		return err
	}

	module, err := wasmtime.NewModuleFromFile(store.Engine, wasmFile)
	if err != nil {
		return err
	}
	instance, err := linker.Instantiate(module)
	if err != nil {
		return err
	}

	rustfer.instance = instance
	rustfer.memory = instance.GetExport("memory").Memory()
	log.Infof("Wasm rustfer initialization done")

	nom := instance.GetExport("_start").Func()
	_, err = nom.Call()
	return err
}

func callWasmFunc(fd int, t message, r message) error {
	log.Infof("callWasmFunc called!")
	if rustfer.instance == nil {
		if err := initWasm(); err != nil {
			return err
		}
		if err := rustferInit(); err != nil {
			return err
		}
	}
	switch t := t.(type) {
	case *Tlopen:
		r := r.(*Rlopen)
		return rustferApi("rustfer_tlopen", fd, t, r)
	case *Tattach:
		r := r.(*Rattach)
		return rustferApi("rustfer_tattach", fd, t, r)
	default:
		return fmt.Errorf("callWasmFunc: not handled type: %#v", t)
	}
}

func arrayAlloc(arr []int8) (ptr int32, err error) {
	alloc := rustfer.instance.GetExport("rustfer_allocate").Func()
	ret, err := alloc.Call(len(arr))
	if err != nil {
		return
	}
	ptr = ret.(int32)
	mem := rustfer.memory.UnsafeData()
	for i, b := range arr {
		mem[ptr+int32(i)] = byte(b)
	}
	return
}

func bytesAlloc(bytes []byte) (ptr int32, err error) {
	alloc := rustfer.instance.GetExport("rustfer_allocate").Func()
	bytesLen := len(bytes)
	ret, err := alloc.Call(bytesLen + 1)
	if err != nil {
		return
	}
	ptr = ret.(int32)
	mem := rustfer.memory.UnsafeData()
	for i, b := range bytes {
		mem[ptr+int32(i)] = b
	}
	mem[ptr+int32(bytesLen)] = 0
	return
}

func extractMessageFromPtr(ptr int32) []byte {
	mem := rustfer.memory.UnsafeData()
	for i := ptr; ; i++ {
		if mem[i] == '}' {
			return mem[ptr : i+1]
		}
	}
}

func decodeJsonBytes(bs []byte, m message) error {
	reader := bytes.NewReader(bs)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(m); err == nil {
		return nil
	}
	reader.Reset(bs)
	rlerror := &Rlerror{}
	if err := decoder.Decode(rlerror); err != nil {
		return fmt.Errorf("Parsing Rlerror: %v %v", err, string(bs))
	}
	return fmt.Errorf("%+v", rlerror)
}

// JOETODO: avoid hard coding
var ioFds = []int8{9, 10, 11, 12}

func rustferInit() error {
	api := rustfer.instance.GetExport("rustfer_init").Func()
	arrPtr, err := arrayAlloc(ioFds)
	if err != nil {
		return err
	}
	confBytes, err := ioutil.ReadFile("./config/conf.json")
	if err != nil {
		return fmt.Errorf("api: reading conf.json failed: %v", err)
	}
	confPtr, err := bytesAlloc(confBytes)
	if err != nil {
		return fmt.Errorf("api: byte allocation failed: %v", err)
	}
	if _, err = api.Call(len(ioFds), arrPtr, 0, 0, confPtr); err != nil {
		return fmt.Errorf("rustfer_init failed: %v", err)
	}
	return nil
}

func rustferApi(apiName string, fd int, t, r message) error {
	bytes, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	ptr, err := bytesAlloc(bytes)
	if err != nil {
		return fmt.Errorf("bytesAlloc failed: %v", err)
	}
	api := rustfer.instance.GetExport(apiName).Func()
	rPtr, err := api.Call(fd, ptr)
	if err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	bytes = extractMessageFromPtr(rPtr.(int32))
	if err := decodeJsonBytes(bytes, r); err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	log.Debugf("joejson: %v -> %v", string(bytes), r)
	return nil
}
