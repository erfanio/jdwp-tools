# JDWP Tools

* `jdwp_lib` contains a library to interact with a remote JVM via JDWP.
* `jdwp_stack_trace` is a tool build with `jdwp_lib` to set breakpoints and
  print a stack trace to System.err when the breakpoint is hit.

When debugging latency sensitive processes it's important to have lightweight
breakpoints but I found that IntelliJ's debugger needs MANY round trips (some
of them are in parallel) to print a stack trace. This is because IntelliJ's
debugger is walking the stack and asking the JVM information about each stack
frame which requires O(n) round trips where n = stack depth.

`jdwp_stack_trace` tool relies on `Thread.dumpStack` to print a stack trace to
System.err. The first breakpoint will require 3 round trips (look up
`dumpStack` method ID, invoke method, resume VM), but subsequent breakpoints
only need 2 round trips.

## Run

```bash
# Get rustup from your package manager or use www.rust-lang.org/tools/install
$ rustup default nightly
$ cargo build
$ ./target/debug/jdwp_stack_trace
```
