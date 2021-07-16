# freebsd-netlink


Design document is here
https://docs.google.com/document/d/1VGci3zucEhCphwLkCPVFjLkMudW2vdZUkgjTyqOSaCU/edit#


## Note:

### About headers:
As per common practice, I have seperated the userspace API from the kernel API (that has access to the userspace API). I kept it simple, and I kept the userspace api in linux/netlink.h and the kernel api in net/netlink.h


### About the files:
1. linux/netlink.h: userspace netlink header. To be added as part of include folder 
2. net/netlink.h: kernel netlink header. To be in the kernel source folder with the source files
3. nl_sock.c: source file implementation. Contains most of the netlink code.


### Existing major todo list
1. we currently assume the initial m_get to retreive a message of a sufficient size for a packet *which allows us to write straight into the buffer instead of using m_append*. The reason for this is because when "closing" a message, we call nlmsg_end or other functions to end the header, we use pointer artihmethic to determine the size of the message. Alternative is to call m_pullup before calling nlmsg_end on the message, or to continuously resize and transfer the message when more data is needed.

2. use m_tag for proto values in the m_buff

