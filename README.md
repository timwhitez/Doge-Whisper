# Doge-Whisper
golang implementation of  Syswhisper2/Syswhisper3

采用SSN排序的方式获取sysid以绕过hook,

目前采用package动态获取的方式，后续有空的话会加上和原版类似的生成用法,指定api生成一个pkg直接调用

使用方式可以借鉴一下example

## Usage
```
package main

import (
	"fmt"
	"github.com/timwhitez/Doge-Whisper/pkg/dogewhisper"
	"syscall"
	"unsafe"
)

//需要被排除掉的api
var hookedapi = []string{"NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx"}
var hashhooked []string

//致敬原版的hash算法
var SW2_SEED = 0xA7A0175C

func SW2_ROR8(v uint32) uint32 {
	return v>>8 | v<<24
}

func SW2_HashSyscall(fname string) string {
	fn, _ := syscall.BytePtrFromString(fname)
	FunctionName := uintptr(unsafe.Pointer(fn))
	var Hash = uint32(SW2_SEED)
	for j := 0; j < len(fname); j++ {
		i := uintptr(j)
		PartialName := *(*uint16)(unsafe.Pointer(FunctionName + i))
		Hash ^= uint32(PartialName) + SW2_ROR8(Hash)
	}
	return fmt.Sprintf("%x", Hash)
}


func main() {
	// 初始化DW_SYSCALL_LIST ,SW2_HashSyscall可以换成其他加密函数
	var newWhisper = dogewhisper.DWhisper(SW2_HashSyscall)
	if newWhisper == nil {
		return
	}

  //对排除的函数进行hash化，当然你可以直接写成hash之后的list
	for _, v := range hookedapi {
		hashhooked = append(hashhooked, SW2_HashSyscall(v))
	}

  //使用初始化后的DW_SYSCALL_LIST获取NtDelayExecution的sysid
	//SW2_HashSyscall("NtDelayExecution")=4942059d
	sysid := newWhisper.GetSysid("4942059d")
	if sysid == 0 {
		return
	}

	fmt.Printf("NtDelayExecution sysid: 0x%x\n", sysid)
	var ti = -(5000 * 10000)

	//动态获取syscall;ret的地址，排除掉hashhooked列表
	callAddr := dogewhisper.GetCall("", hashhooked, SW2_HashSyscall)
	fmt.Printf("Syscall;ret Address: 0x%x\n", callAddr)

  //执行
	//Call
	r, e1 := dogewhisper.DWcall(sysid, callAddr, uintptr(0), uintptr(unsafe.Pointer(&ti)))
	if e1 != nil {
		fmt.Printf("0x%x\n", r)
		fmt.Println(e1)
	}

}


```
