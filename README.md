# Doge-Whisper
golang implementation of  Syswhisper2/Syswhisper3

按系统调用地址排序获取System Service Number(SSN)即为sysid以绕过hook,

Sorting by System Call Address

dogewhisper.DWhisper() will parse the EAT of NTDLL.dll, locating all function names that begin with "Zw". 

dogewhisper.DWhisper() 将解析 NTDLL.dll 的 EAT，定位所有以“Zw”开头的函数名。

It replaces "Zw" with "Nt" before generating a hash of the function name.

它在生成函数名称的散列之前将“Zw”替换为“Nt”。

It then saves the hash and address of code stub to a table of SYSCALL_ENTRY structures. 

然后它将代码存根的哈希和地址保存到 SYSCALL_ENTRY 结构表中。

After gathering all the names, it uses a simple bubble sort of code addresses in ascending order. 

收集所有名称后，使用简单的冒泡排序代码地址按升序排列。

The SSN is the index of the system call stored in the table. 

System Service Number (SSN) 是存储在表中的系统调用的索引。

与原版的区别之一是在于生成的索引最后是存储于map中以便更快的查找。

目前采用package动态获取的方式，后续有空的话会加上和原版类似的生成用法,指定api生成一个pkg直接调用

后续会集成进gabh项目

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

## Reference
https://github.com/Crummie5/Freshycalls

https://github.com/jthuraisamy/SysWhispers2

https://github.com/klezVirus/SysWhispers3

https://github.com/C-Sto/BananaPhone

https://github.com/timwhitez/Doge-Gabh

https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
