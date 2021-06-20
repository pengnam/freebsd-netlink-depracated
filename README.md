# freebsd-netlink


Design document is here
https://docs.google.com/document/d/1VGci3zucEhCphwLkCPVFjLkMudW2vdZUkgjTyqOSaCU/edit#


## Note:

### About headers:
As per common practice, I have seperated the userspace API from the kernel API (that has access to the userspace API). I kept it simple, and I kept the userspace api in linux/netlink.h and the kernel api in net/netlink.h

### About the set-up:
I kept the set-up to be similar to Luigi's project, since it allowed me to install it as a module easily and it works. I'm using case 2.

### About the files:
1. linux/netlink.h: userspace netlink header. To be added as part of include folder 
2. net/netlink.h: kernel netlink header. To be in the kernel source folder with the source files
3. nl_sock.c: source file implementation
