package inode

import "fmt"

var objs bpfObjects

// LoadBPFObjects loads bpf objects for inode based security check.
// https://github.com/torvalds/linux/blob/v5.15/include/linux/lsm_hook_defs.h#L110
func LoadBPFObjects() (func() error, error) {
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load inode bpf objects: %s", err)
	}
	return objs.Close, nil
}
