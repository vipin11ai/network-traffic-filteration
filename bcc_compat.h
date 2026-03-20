#ifndef __BCC_COMPAT_H
#define __BCC_COMPAT_H

struct bpf_wq { };

#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 0x100
#endif

#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0x110
#endif

#endif
