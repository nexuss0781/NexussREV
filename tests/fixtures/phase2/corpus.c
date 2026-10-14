// Original NexussREV benchmark fixture source; intentionally tiny and freely redistributable.
__declspec(dllexport) __declspec(noinline) int add_one(int value) {
    return value + 1;
}

__declspec(dllexport) __declspec(noinline) int call_add(int value) {
    return add_one(value) * 2;
}

__declspec(noinline) static int private_helper(int value) {
    return value ^ 0x35;
}

__declspec(dllexport) __declspec(noinline) int call_helper(int value) {
    return private_helper(value);
}
