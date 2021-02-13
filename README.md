# zld

Zig's lld drop-in replacement, called ZigLD or `zld` for short

**Disclaimer**: this is a WIP so things naturally will not work as intended or at all.
However, with a bit of luck, and some spare time, I reckon `zld` can handle most common
cases (with a special focus on cross-compilation) relatively quickly.

## Quick start guide

### Building

Make sure you have at least Zig 0.8.0 in your path. Ideally, you're using Zig compiled
from source tracking the master branch.

```
$ zig build
```

This will create the `zld` binary in `zig-cache/bin/zld`. You can then use it like you'd
use a standard linker (bearing in mind that you can only one object file: see the [Roadmap](##Roadmap)).

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

# Link away!
$ ./zig-cache/bin/zld hello.o -o hello

# Run!
$ ./hello
```

### Testing

If you'd like to run unit and end-to-end tests (when you'll decide you wanna contribute for instance),
run the tests like you'd normally do for any other Zig project.

```
$ zig build test
```

## Why `zld`?

Excellent question! Lemme be perfectly frank with you. We're having immense problems with
the `lld` on macOS. Actually, it just doesn't work as it should and it's nowhere near in terms of the
functionality of its other counterparts on other platforms (e.g., linking Elf with `lld` just works...).
The purpose of this project is to implement a drop-in replacement for `lld` in Zig. Mind you, I'm not trying
to replace the WIP of an incremental Mach-O linker! On the contrary, this linker being a traditional
linker will be used to augment the incremental linking in Zig, and if all goes well, we might
use it to perform optimised linking in the Release mode.

So that's that...

## Roadmap

Currently, the entire roadmap is organised around macOS/Mach-O support. This is mainly because
that's the binary format I'm most familiar with. Having said that, I'd welcome contributions
adding some support to other widely used formats such as Elf, Coff, PE, etc.

- [x] link `.o` generated from simple C program on macOS targeting `aarch64`
- [x] link the same `.o` but targeting `x86_64`
- [x] unhack, or refactor, for basic single `.o` linking
- [x] link multiple `.o`
- [x] link simple `.zig` (this includes TLV so should be interesting!)
- [ ] converge with Zig's stage2
- [ ] handle multiple dynamic libraries
- [ ] handle frameworks
