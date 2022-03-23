package dogewhisper

import (
	"fmt"
	"math/rand"
	"time"

	"strings"

	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
)

func (dl *DW_SYSCALL_LIST) GetSysid(s string) uint16 {
	captial, ok := dl.slist[s]
	if ok {
		return captial.Count
	} else {
		return 0
	}
}

func DWhisper(hash func(string) string) *DW_SYSCALL_LIST {
	var newSL DW_SYSCALL_LIST
	newSL.slist = make(map[string]*SYSCALL_LIST)

	//init hasher
	hasher := func(a string) string {
		return a
	}
	if hash != nil {
		hasher = hash
	}

	Ntd, _, _ := gMLO(1)
	if Ntd == 0 {
		return nil
	}

	addrMod := Ntd

	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return nil
	}
	//windows.SleepEx(50, false)
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return nil
	}

	rr := rawreader.New(addrMod, int(modSize))
	p, e := pe.NewFileFromMemory(rr)
	defer p.Close()
	if e != nil {
		return nil
	}
	ex, e := p.Exports()
	if e != nil {
		return nil
	}

	var cl []Count_LIST
	for _, exStub := range ex {
		if !strings.HasPrefix(exStub.Name, "Zw") {
			continue
		}
		nameHash := strings.ToLower(hasher("Nt" + exStub.Name[2:]))
		tmpList := SYSCALL_LIST{
			Count:   0,
			Address: uintptr(exStub.VirtualAddress),
		}
		tmpCList := Count_LIST{
			hashName: nameHash,
			Address:  uintptr(exStub.VirtualAddress),
		}
		newSL.slist[nameHash] = &tmpList
		cl = append(cl, tmpCList)
	}

	for i := 0; i < len(cl)-1; i++ {
		for j := 0; j < len(cl)-i-1; j++ {
			if cl[j].Address > cl[j+1].Address {
				tmp := Count_LIST{
					hashName: cl[j].hashName,
					Address:  cl[j].Address,
				}
				cl[j].Address = cl[j+1].Address
				cl[j].hashName = cl[j+1].hashName
				cl[j+1].Address = tmp.Address
				cl[j+1].hashName = tmp.hashName
			}
		}
	}

	for i := 0; i < len(cl); i++ {
		newSL.slist[cl[i].hashName].Count = uint16(i)
	}

	return &newSL
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetCall(tarApi string, blacklist []string, hash func(string) string) uintptr {
	//init hasher
	hasher := func(a string) string {
		return a
	}
	if hash != nil {
		hasher = hash
	}

	//tolower
	if blacklist != nil && tarApi == "" {
		for i, v := range blacklist {
			blacklist[i] = strings.ToLower(v)
		}
	}

	Ntd, _, _ := gMLO(1)
	if Ntd == 0 {
		return 0
	}

	//fmt.Printf("NtdllBaseAddr: 0x%x\n", Ntd)

	addrMod := Ntd

	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return 0
	}
	//windows.SleepEx(50, false)
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return 0
	}

	rr := rawreader.New(addrMod, int(modSize))
	p, e := pe.NewFileFromMemory(rr)
	if e != nil {
		return 0
	}
	ex, e := p.Exports()
	if e != nil {
		return 0
	}

	rand.Seed(time.Now().UnixNano())
	for i := range ex {
		j := rand.Intn(i + 1)
		ex[i], ex[j] = ex[j], ex[i]
	}

	for i := 0; i < len(ex); i++ {
		exp := ex[i]
		if tarApi != "" {
			if strings.ToLower(hasher(exp.Name)) == strings.ToLower(tarApi) || strings.ToLower(hasher(strings.ToLower(exp.Name))) == strings.ToLower(tarApi) {
				//fmt.Println("Syscall API: " + exp.Name)
				offset := rvaToOffset(p, exp.VirtualAddress)
				b, e := p.Bytes()
				if e != nil {
					return 0
				}
				buff := b[offset : offset+22]
				if buff[18] == 0x0f && buff[19] == 0x05 && buff[20] == 0xc3 {
					//fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
					return Ntd + uintptr(exp.VirtualAddress) + uintptr(18)
				}
			}
		} else {
			if strings.HasPrefix(exp.Name, "Zw") {
				if !contains(blacklist, strings.ToLower(hasher(exp.Name))) && !contains(blacklist, strings.ToLower(hasher(strings.ToLower(exp.Name)))) {
					//fmt.Println("Syscall API: " + exp.Name)
					offset := rvaToOffset(p, exp.VirtualAddress)
					b, e := p.Bytes()
					if e != nil {
						return 0
					}
					buff := b[offset : offset+22]
					if buff[18] == 0x0f && buff[19] == 0x05 && buff[20] == 0xc3 {
						//fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
						return Ntd + uintptr(exp.VirtualAddress) + uintptr(18)
					}
				}
			}
		}
	}
	return 0
}

//GetModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *sstring
	start, size, badstring = getMLO(i)
	modulepath = badstring.String()
	return
}

//rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

//HgSyscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func DWcall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32, err error) {

	errcode = hgSyscall(callid, syscallA, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func ntH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress)).E_lfanew)))
}

//sstring is the stupid internal windows definiton of a unicode string. I hate it.
type sstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s sstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32)

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)
