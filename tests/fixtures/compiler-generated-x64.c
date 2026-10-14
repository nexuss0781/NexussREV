/*
 * Compiler-generated Gate 1 fixture source. Built with:
 * clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O1 -c -o compiler-generated-x64.obj compiler-generated-x64.c
 * lld-link /entry:entry /subsystem:console /nodefaultlib /noimplib /machine:x64 /timestamp:0 /out:compiler-generated-x64.exe compiler-generated-x64.obj
 */
__declspec(dllexport) int Add(int left, int right) {
    return left + right;
}

void entry(void) {
    volatile int result = Add(19, 23);
    (void)result;
}
