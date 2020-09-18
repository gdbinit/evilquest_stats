EvilQuest/ThiefQuest Mach-O Stats
(c) Pedro Vilaça 2020, All rights reserved.  
reverser@put.as - https://reverse.put.as  

reference: https://reverse.put.as/2020/09/17/evilquest-revisited/

Small utility to gather Mach-O stats about code and strings sections to prove that code is the same only strings are different.

Supports parallel execution in case you have the same near half a million samples as I do.

```
Usage:
  -i string
        file or folder to analyse
  -n int
        number of parallel scanners to run (default 1) (default 1)
```
