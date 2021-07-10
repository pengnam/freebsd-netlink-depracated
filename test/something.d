fbt:netlink2:nl_send:entry
{
        stack();
	printf("test");
}

fbt:netlink2:raw_input_netlink_cb:entry
{
        stack();
	printf("working");
}


fbt:netlink2:nl_msg_from_netlink:entry
{
        stack();
	printf("nice");
}
fbt:kernel:raw_input_ext:entry
{
	
	this->m = (struct mbuf*) arg0;
	this->proto = (struct sockproto*) arg1;
	printf("m_len: %d\n", this->m->m_len);
	printf("proto: %d\n", this->proto->sp_protocol);


}
fbt:kernel:sbappendaddr:entry
{
	printf("test: %p\n", arg1);
	this->sb = (struct sockbuf*) arg1;
	this->want = (this->sb)->sb_flags;
	printf("SB_WAIT: %d", this->want & 0x04 );
	/* #define sb_notify(sb)   (((sb)->sb_flags & (SB_WAIT | SB_SEL | SB_ASYNC | SB_UPCALL | SB_AIO | SB_KNOTE)) != 0)*/
}
fbt:kernel:sbappendaddr:return
{
	printf("inside\n");
	stack();
	printf("Returning: %d\n", arg1);

}
fbt:kernel:m_copym:return
{printf("copym %p", arg1);}


fbt:kernel:sowakeup:entry
{printf("wakeup: %p", arg0);}

fbt:kernel:sowakeup:entry
{printf("wakeup: %p", arg0);}
