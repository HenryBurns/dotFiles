---
name: cpp-binary-size
description: Find and fix binary-size bloat in a C++ codebase, which usually also cuts compile time. Use when a binary, object file or package grew, when asked to shrink a binary, when a header looks costly to include, or when reviewing a header that adds namespace-level variables, `using` declarations, explicit template instantiations or inline function bodies. Covers why flags and stripping are the wrong first move, why headers dominate, how to rank headers by what they emit, the recurring constructs that force the compiler to emit code nobody uses and their fixes, and how to prove a fix worked.
---

# C++ binary size

This skill does not depend on any one codebase. Each repo's own tooling, size budget and history
belong in a skill about that repo.

## Where the size comes from

- **Fix the code before the flags.** Compiler and linker flags are rarely free. Each one trades
  away debuggability, build time or runtime speed, and a mature codebase has usually already chosen
  its flags on purpose. Stripping symbols makes the file smaller but does not remove any code.
  Treat flag changes as a last resort, and find out why the current flags were chosen before you
  change them.
- **Most of the file is debug info, but emitted code drives it.** In a debug-info build, a section
  breakdown typically shows `.debug_*` sections taking most of the file and `.text` only a few
  percent. Debug info grows roughly in step with emitted code and data, so the lasting fix is still
  to emit less.
- **Headers multiply every problem.** A construct in a `.cpp` file costs once. The same construct in
  a header costs once for each translation unit (TU) that includes it, and core headers are often
  included thousands of times. A single line in a widely included header can add tens of MB to a
  large binary.
- **Size and compile time move together.** Anything that makes the compiler emit more bytes also
  makes it do more work. A size fix is usually a build-time fix too, which helps when arguing for
  it.

## Rank headers by what they emit

A header that only declares things should add nothing to an object file. To measure what a header
emits:

1. Compile the header as its own TU, and record the object size.
2. Copy the header, delete everything except its `#include` lines, compile that, and record the
   object size.
3. Subtract. The difference is the header's **exclusive object size**. Anything above zero means
   some construct in the header forces the compiler to emit code or data even when nothing uses
   it.
4. Multiply by the number of TUs that include the header (from the dependency files or a build
   graph), and rank by the product.

Use the build's real flags. Take them from the build system or `compile_commands.json`, unless the
repo says that file is not authoritative. Compare like with like: gcc and clang, and debug and
release, can rank the same header very differently.

Two quick checks that need no tooling:

```
# Variables with internal linkage that appear in many object files: header statics.
nm -C *.o | awk '$2 ~ /^[bdr]$/ && $3 !~ /^\.L/ {$1=""; $2=""; print}' | sort | uniq -c | sort -rn | head

# Which sections hold the size.
size -A <binary>           # or: bloaty -d sections <binary>
```

A name that appears once per TU in the `nm` output is a header static. The `.L` filter removes the
compiler's own string-literal labels. bloaty's per-symbol view (`-d symbols`, `-d compileunits`)
gives the most detail, but it can fail on some gcc output.

**Finding the bad line.** Once you have a header with a nonzero exclusive size, remove lines from it
until the size drops to zero. Usually a single line is responsible, so this goes quickly. Check the
patterns below first.

## Constructs that emit code nobody asked for

These cover most cases. Some were found empirically: the compiler is seen to emit more, but nobody
has a confirmed explanation. Measure before and after, and do not state a mechanism as fact.

| Construct in a header | Why it costs | Fix |
|---|---|---|
| A namespace-level `static` or `const` variable of non-trivial type (strings, containers, objects with constructors). | Internal linkage: every TU gets its own copy and its own static initializer, which also slows startup. | `static constexpr` if the type allows it (`std::string` → `std::string_view`). Otherwise `extern` in the header, defined in one `.cpp` file. |
| A namespace-level variable with an initializer and no `static`, or an `inline` variable. | Every TU that sees it must be able to emit and initialize it. | Same as above. |
| A `static inline` class member initialized in the class body. | The `.cpp` file that owns the class no longer owns the storage, so every TU carries it. | Declare `static T const x;` in the class, then put `constexpr inline T cls::x{...};` after the class, where the type is complete. The `inline` is required: in this out-of-class definition, `constexpr` does not imply it. |
| A using-declaration such as `using ns::name;`. | Seen with clang to emit bytes even when nothing uses the name. An alias does not. | `using name = ns::name;`. The alias form does not work for objects or overload sets; qualify those uses instead. |
| An explicit instantiation (`template struct foo<int>;`) in a header, often written to restrict the allowed parameters. | Forces every includer to instantiate every listed template in full. | Delete it. Explicit instantiation belongs in a `.cpp` file, paired with `extern template` in the header. |
| A `{}` initializer on a container member (`std::vector<T> v{};`). | Seen to emit more than default construction, probably because of allocator instantiation. | Remove the `{}`, which gives the same behaviour. Caveat: this can stop the owning struct from being aggregate-initialized with `{}`. |
| An inline function body that touches statics or thread-locals, such as a base-class method. | The compiler can evaluate it, and emit what it references, even when nothing calls it. | Move the body to a `.cpp` file. For a template, use a separate `_impl` file that holds all the definitions. |
| Registration macros or per-TU objects (loggers, diagnostics sources, auto-registration). | Once per TU, and often registered once per TU as well. | Move them to the `.cpp` file, or delete them if unused. |
| Validation done at runtime for every call site (format strings, for example). | A static initializer for each call site in each TU. | Validate at compile time (`consteval` or `constexpr` checks). |
| A heavy `#include` in a widely included header. | Mostly compile time. Size grows when the included header has any of the constructs above. | Include-what-you-use, forward declarations, and splitting the header into a lighter declarations-only header. |

**Traps when moving a definition into a `.cpp` file:**
- If two libraries depend on each other, the definition has to go in the one that sits lower in the
  link order.
- Changing a value to `extern` changes when it is initialized. If anything reads it during static
  initialization, you have created a static-init-order bug. Prefer `constexpr` when the type allows
  it.

## Prove the fix

- The header's exclusive object size is now zero; say so in the commit's testing note.
- The binary's size before and after, from the same build configuration. Give a section breakdown
  when the change is large.
- These are refactors that should not change behaviour, so run the normal tests too.
- Once a pattern is fixed across the tree, add a lint rule for it (ast-grep, clang-tidy) so it does
  not come back. Regressions are cheap to fix right after they land and expensive to find later.

## When the extra size is wanted

Adding debug symbols, or keeping them in more build types, is a different question from bloat.
Weigh three things:
- **The size budget** for the shipped package.
- **What the symbols are for:** stack traces in crashes, and which builds and test stages need them.
- **The cost of symbolizing.** An in-process symbolizer such as libbacktrace pays its setup cost
  at every startup, which adds up for a short-lived tool that runs many times. A symbolizer outside
  the process pays only when something crashes.
