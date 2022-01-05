# QueryWorkingSet AntiTamper Example

Just an example of a well-known technique to detect memory tampering via Windows Working Sets.

Non-writable pages are being shared among processes that need them. Each process reads the *same copy*.
Once one process modifies the protection of a page to write to it, the system will copy the page and serve the process its own copy. Once in this state, the `Shared` member of the `PSAPI_WORKING_SET_INFORMATION` (returned by QueryWorkingSet(Ex) API(s)) will be `FALSE` (`0`).

A process can check his `.text` section (or any non-writable section) by querying his Working Set (using QueryWorkingSet(Ex) API(s)) and checking the `Shared` member (and may have use of the `ShareCount` member).

- Running without a debugger
  ![img.png](doc/images/img1.png)
  
- Running under a debugger (you need to place a breakpoint somewhere in `main.c` `main()` routine)
  ![img.png](doc/images/img2.png)
  
The page RVA in the screenshot above would be `0x5000`, once you load the built sample into your favorite disassembler you can notice that the page at RVA `0x5000` is where you put the breakpoint.

Have fun 🏴‍☠️
