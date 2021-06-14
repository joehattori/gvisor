package p9

// JOETODO: move this file out from package p9.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/joehattori/wasmer-go/wasmer"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// JOETODO: wrap rustfer with new go routine, and use sync.Once.

var rustfer struct {
	instance *wasmer.Instance
	memory   *wasmer.Memory
}

func initWasm() error {
	log.Infof("initWasm called!")
	wasmBytes, err := ioutil.ReadFile("/rustfer/rustfer.wasm")
	if err != nil {
		return err
	}

	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)

	wasiEnv, err := wasmer.NewWasiStateBuilder("rustfer").
		PreopenDirectory(".").
		InheritStdout().
		InheritStderr().
		Finalize()
	if err != nil {
		return err
	}
	module, err := wasmer.NewModule(store, wasmBytes)
	if err != nil {
		return err
	}

	importObject, err := wasiEnv.GenerateImportObject(store, module)
	if err != nil {
		return err
	}
	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		return err
	}

	rustfer.instance = instance
	rustfer.memory, err = instance.Exports.GetMemory("memory")
	if err != nil {
		return err
	}
	log.Debugf("Wasm rustfer initialization done")

	nom, err := instance.Exports.GetFunction("_start")
	_, err = nom()
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
	case *Twalk:
		r := r.(*Rwalk)
		return rustferApi("rustfer_twalk", fd, t, r)
	case *Twalkgetattr:
		r := r.(*Rwalkgetattr)
		return rustferApi("rustfer_twalkgetattr", fd, t, r)
	case *Tgetxattr:
		r := r.(*Rgetxattr)
		return rustferApi("rustfer_tgetxattr", fd, t, r)
	default:
		return fmt.Errorf("callWasmFunc: not handled type: %#v", t)
	}
}

func arrayAlloc(arr []int8) (ptr int32, size int, err error) {
	var alloc func(...interface{}) (interface{}, error)
	alloc, err = rustfer.instance.Exports.GetFunction("rustfer_allocate")

	var ret interface{}
	ret, err = alloc(len(arr))
	if err != nil {
		return
	}

	ptr = ret.(int32)
	mem := rustfer.memory.Data()
	for i, b := range arr {
		mem[ptr+int32(i)] = byte(b)
	}
	size = len(arr)
	return
}

func bytesAlloc(bytes []byte) (ptr int32, size int, err error) {
	var alloc func(...interface{}) (interface{}, error)
	alloc, err = rustfer.instance.Exports.GetFunction("rustfer_allocate")
	if err != nil {
		return
	}
	bytesLen := len(bytes)
	var ret interface{}
	ret, err = alloc(bytesLen + 1)
	if err != nil {
		return
	}
	ptr = ret.(int32)
	mem := rustfer.memory.Data()
	copy(mem[ptr:ptr+int32(len(bytes))], bytes)
	mem[ptr+int32(bytesLen)] = 0
	size = len(bytes)
	return
}

func dealloc(ptr int32, size int) {
	dealloc, err := rustfer.instance.Exports.GetFunction("rustfer_deallocate")
	if err != nil {
		panic(err)
	}
	if _, err := dealloc(ptr, size); err != nil {
		panic(err)
	}
}

func extractMessageFromPtr(ptr int32) ([]byte, error) {
	mem := rustfer.memory.Data()
	if b := mem[ptr]; b != '{' && b != '[' {
		return []byte{}, fmt.Errorf("Invalid JSON start: %v\nraw: %v\nperipheral: %v", (b), string(mem[ptr:ptr+100]), string(mem[ptr-100:ptr+100]))
	}
	for i := ptr; ; i++ {
		if mem[i] == 0 {
			return mem[ptr : i+1], nil
		}
	}
}

func decodeJsonBytes(bs []byte, m message) error {
	reader := bytes.NewReader(bs)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var err error
	if err = decoder.Decode(m); err == nil {
		return nil
	}
	reader.Reset(bs)
	log.Debugf("Failed to decode %s to %T: %v", string(bs), m, err)
	rlerror := &Rlerror{}
	if err := decoder.Decode(rlerror); err != nil {
		return fmt.Errorf("Parsing Rlerror: %v %v", err, string(bs))
	}
	return fmt.Errorf("%+v", rlerror)
}

// JOETODO: avoid hard coding
var ioFds = []int8{9, 10, 11, 12}

func rustferInit() error {
	api, err := rustfer.instance.Exports.GetFunction("rustfer_init")
	if err != nil {
		return fmt.Errorf("rustfer_init: failed %v", err)
	}
	// arrPtr, _, err := arrayAlloc(ioFds)
	arrPtr, arrSize, err := arrayAlloc(ioFds)
	defer dealloc(arrPtr, arrSize)
	if err != nil {
		return err
	}
	confBytes, err := ioutil.ReadFile("config/conf.json")
	if err != nil {
		return fmt.Errorf("api: reading conf.json failed: %v", err)
	}
	// confPtr, _, err := bytesAlloc(confBytes)
	confPtr, confSize, err := bytesAlloc(confBytes)
	defer dealloc(confPtr, confSize)
	if err != nil {
		return fmt.Errorf("api: byte allocation failed: %v", err)
	}
	if _, err = api(len(ioFds), arrPtr, 0, 0, confPtr); err != nil {
		return fmt.Errorf("rustfer_init failed: %v", err)
	}
	return nil
}

var rustferMu sync.Mutex

func rustferApi(apiName string, fd int, t, r message) error {
	log.Debugf("rustferApi: calling %s", apiName)
	bytes, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	rustferMu.Lock()
	defer rustferMu.Unlock()
	// ptr, _, err := bytesAlloc(bytes)
	ptr, ptrSize, err := bytesAlloc(bytes)
	defer dealloc(ptr, ptrSize)
	if err != nil {
		return fmt.Errorf("bytesAlloc failed: %v", err)
	}
	api, err := rustfer.instance.Exports.GetFunction(apiName)
	if err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	rPtr, err := api(fd, ptr)
	if err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	ptr = rPtr.(int32)
	bytes, err = extractMessageFromPtr(ptr)
	if err != nil {
		return fmt.Errorf("Parsing %s's response failed: %v", apiName, err)
	}
	defer dealloc(ptr, len(bytes))
	if err := decodeJsonBytes(bytes, r); err != nil {
		return fmt.Errorf("%s failed: %v", apiName, err)
	}
	log.Debugf("joejson: %v ->\n%v", string(bytes), r)
	return nil
}
