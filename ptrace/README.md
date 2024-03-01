# Linux process injection with ptrace

Proof of concept for injecting simple shellcode via ptrace into a running process. 

## Running

First of all compile:

    make all

Then run victim-process/sample and take note of the PID.

    ./victim-process/sample

Now, in a different terminal, run the 

    ./inject <victim_pid>

You'll see after a while a shell appearing in the victim process.

It is interesting to compare the memory of the victim process before and after the injection.

Before:

    00400000-00401000 r--p 00000000 00:20 77706661                           <path>/sample
    00401000-00402000 r-xp 00001000 00:20 77706661                           <path>/sample
    00402000-00403000 r--p 00002000 00:20 77706661                           <path>/sample
    00403000-00404000 r--p 00002000 00:20 77706661                           <path>/sample
    00404000-00405000 rw-p 00003000 00:20 77706661                           <path>/sample
    020d0000-020f1000 rw-p 00000000 00:00 0                                  [heap]
    7f9acb27c000-7f9acb27e000 rw-p 00000000 00:00 0 
    7f9acb27e000-7f9acb2a4000 r--p 00000000 00:20 8289013                    /usr/lib64/libc.so.6
    7f9acb2a4000-7f9acb404000 r-xp 00026000 00:20 8289013                    /usr/lib64/libc.so.6
    7f9acb404000-7f9acb452000 r--p 00186000 00:20 8289013                    /usr/lib64/libc.so.6
    7f9acb452000-7f9acb456000 r--p 001d3000 00:20 8289013                    /usr/lib64/libc.so.6
    7f9acb456000-7f9acb458000 rw-p 001d7000 00:20 8289013                    /usr/lib64/libc.so.6
    7f9acb458000-7f9acb462000 rw-p 00000000 00:00 0 
    7f9acb47a000-7f9acb47b000 r--p 00000000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7f9acb47b000-7f9acb4a2000 r-xp 00001000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7f9acb4a2000-7f9acb4ac000 r--p 00028000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7f9acb4ac000-7f9acb4ae000 r--p 00031000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7f9acb4ae000-7f9acb4b0000 rw-p 00033000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7fff0ade9000-7fff0ae0b000 rw-p 00000000 00:00 0                          [stack]
    7fff0aff6000-7fff0affa000 r--p 00000000 00:00 0                          [vvar]
    7fff0affa000-7fff0affc000 r-xp 00000000 00:00 0                          [vdso]
    ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]

and after

    55589d9b0000-55589d9df000 r--p 00000000 00:20 8015534                    /usr/bin/bash
    55589d9df000-55589daca000 r-xp 0002f000 00:20 8015534                    /usr/bin/bash
    55589daca000-55589daff000 r--p 0011a000 00:20 8015534                    /usr/bin/bash
    55589daff000-55589db03000 r--p 0014e000 00:20 8015534                    /usr/bin/bash
    55589db03000-55589db0c000 rw-p 00152000 00:20 8015534                    /usr/bin/bash
    55589db0c000-55589db17000 rw-p 00000000 00:00 0 
    55589f5b9000-55589f61c000 rw-p 00000000 00:00 0                          [heap]
    7fd5540ab000-7fd5540ae000 rw-p 00000000 00:00 0 
    7fd5540ae000-7fd5540d4000 r--p 00000000 00:20 8289013                    /usr/lib64/libc.so.6
    7fd5540d4000-7fd554234000 r-xp 00026000 00:20 8289013                    /usr/lib64/libc.so.6
    7fd554234000-7fd554282000 r--p 00186000 00:20 8289013                    /usr/lib64/libc.so.6
    7fd554282000-7fd554286000 r--p 001d3000 00:20 8289013                    /usr/lib64/libc.so.6
    7fd554286000-7fd554288000 rw-p 001d7000 00:20 8289013                    /usr/lib64/libc.so.6
    7fd554288000-7fd554290000 rw-p 00000000 00:00 0 
    7fd554290000-7fd55429e000 r--p 00000000 00:20 6287319                    /usr/lib64/libtinfo.so.6.4
    7fd55429e000-7fd5542b2000 r-xp 0000e000 00:20 6287319                    /usr/lib64/libtinfo.so.6.4
    7fd5542b2000-7fd5542c0000 r--p 00022000 00:20 6287319                    /usr/lib64/libtinfo.so.6.4
    7fd5542c0000-7fd5542c4000 r--p 0002f000 00:20 6287319                    /usr/lib64/libtinfo.so.6.4
    7fd5542c4000-7fd5542c5000 rw-p 00033000 00:20 6287319                    /usr/lib64/libtinfo.so.6.4
    7fd5542c5000-7fd5542c7000 rw-p 00000000 00:00 0 
    7fd5542df000-7fd5542e0000 r--p 00000000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7fd5542e0000-7fd554307000 r-xp 00001000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7fd554307000-7fd554311000 r--p 00028000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7fd554311000-7fd554313000 r--p 00031000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7fd554313000-7fd554315000 rw-p 00033000 00:20 8289010                    /usr/lib64/ld-linux-x86-64.so.2
    7ffdce3b2000-7ffdce3d3000 rw-p 00000000 00:00 0                          [stack]
    7ffdce3f8000-7ffdce3fc000 r--p 00000000 00:00 0                          [vvar]
    7ffdce3fc000-7ffdce3fe000 r-xp 00000000 00:00 0                          [vdso]
    ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]



