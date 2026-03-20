from bcc import BPF
code = """
#ifdef KBUILD_MODNAME
#warning "KBUILD_MODNAME is defined"
#endif
#ifdef __clang__
#warning "__clang__ is defined"
#endif
"""
try:
    BPF(text=code)
except Exception as e:
    print(e)
