# zld

Zig's ld drop-in replacement, called ZigLD or `zld` for short

## Quick start guide

### Building

You will need latest Zig in your path. You can get nightly binaries from [here](https://ziglang.org/download/).

```
$ zig build
```

This will create the `ld.zld` (Elf), `ld64.zld` (MachO), `link-zld` (Coff) and `wasm-zld` (Wasm) binaries in `zig-out/bin/`.
You can then use it like you'd use a standard linker.

```
$ cat <<EOF > hello.c
#include <stdio.h>

int main() {
    fprintf(stderr, "Hello, World!\n");
    return 0;
}
EOF

# Create .o using system clang
$ clang -c hello.c

# Or, create .o using zig cc
$ zig cc -c hello.c

# On macOS
$ ./zig-out/bin/ld64.zld hello.o -o hello

# On Linux
$ ./zig-out/bin/ld.zld hello.o -o hello

# Run!
$ ./hello
```

### Testing

If you'd like to run unit and end-to-end tests, run the tests like you'd normally do for any other Zig project.

```
$ zig build test
```

## Why did you decide to unarchive this repo?

Excellent question! If you recall, back in March 2021, I've moved the development of the linker directly
to upstream (Zig master), and since then, `zld` (or `zig ld` in fact) has been able to link a variety
of projects targeting Mach-O file format. Now I am in the process of implementing a traditional ELF linker,
so I've decided to repeat the process which in my humble opinion worked out pretty well for Mach-O. The idea
is to start small by adding basic linking in a standalone repo (separate from Zig master), and when the linker 
matures enough, upstream it into Zig. I think this approach makes sense and allows me to focus on the target
file format only rather than try and tackle both a new file format and challenges of incremental linking.

Having said that, I've also decided to downstream all latest developments to the traditional Mach-O linker
back into this repo, thus making `zld` a capable standalone linker when it comes to linking Mach-O. I'll strive
to make it a direct replacement for any system linker, however, note that my priority will always be advancing
of `zig ld` (which is not to say that I won't backport fixes from one to another). At the end of the day, the idea
will be to swap in `zig ld` in place of any other linker.

## Supported backends

- [x] Mach-O
- [x] ELF (non-PIE static and dynamic, x86_64)
- [x] ELF (PIE, DSO, x86_64)
- [x] ELF (aarch64)
- [ ] ELF (riscv64)
- [ ] COFF/PE
- [x] Wasm (static)

## Contributing

You are welcome to contribute to this repo, but ask you to see if you could also contribute the same fix
to Zig too. This will make my life easier and you will have made many Zig developers happy!
