
#include <net/netlink.h>

/*---- start debugging macros --luigi */
#define ND(format, ...)
#define D(format, ...)                                          \
	do {                                                    \
		struct timeval __xxts;                          \
		microtime(&__xxts);                             \
		printf("%03d.%06d [%4d] %-25s " format "\n",    \
				(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
				__LINE__, __FUNCTION__, ##__VA_ARGS__);         \
	} while (0)

	static int
nla_type(const struct nlattr *nla)
{
	return nla->nla_type;
}
	static int
nla_len(const struct nlattr *nla)
{
	return nla->nla_len;
}
static inline void *nla_data(struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}
/**
 * Check if netlink attribute fits into remaining bytes
 */
static inline int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int) sizeof(*nla) &&
		nla->nla_len >= sizeof(*nla) &&
		nla->nla_len <= remaining;
}

/**
 * Returns the next netlink attribute in the attribute stream and
 * decrements remaining by the size of the current attribute.
 */
static inline struct nlattr *nla_next(struct nlattr *nla, int *remaining)
{
	unsigned int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) nla + totlen);
}




	static int
nla_validate(struct nlattr *nla, int maxtype,
		struct nla_policy *policy, 
		unsigned int depth) 
{
	const struct nla_policy *pt;
	int attribute_type, attribute_length, minlen, error; 

	if (depth >= MAX_POLICY_RECURSION_DEPTH) {
		return EINVAL;
	}

	attribute_type = nla_type(nla);
	attribute_length = nla_len(nla);
	//TODO: Both use types which are confusing :(
	if (attribute_type < 0 || attribute_type > maxtype) {
		return 0;
	}
	pt = &policy[attribute_type];
	KASSERT(pt < NLA_TYPE_MAX, "type value not in range");

	//Match datatypes with exact length
	if (nla_attr_len[pt->type] && attribute_length != nla_attr_len[pt->type]) {
		//NOTE: In linux, warning is returned
		return EINVAL;
	}
	//There are some policy types that do not immediately follow the attribute_length >= pt->len rule 
	switch (pt->type) {

		case NLA_REJECT:
			//Reject all attributes with the tag
			return EINVAL;
		case NLA_FLAG:
			//Should not have any data
			if (attribute_length>0)
				return ERANGE;
			break;
		case NLA_STRING:
			if (pt->len) {
				//get data
				if (attribute_length < 1) {
					return ERANGE;
				}
				char *buf = nla_data(nla);

				if (buf[attribute_length - 1] == '\0')
					attribute_length--;

				if (attribute_length > pt->len)
					return ERANGE;

			}
			break;
		case NLA_NESTED:
			if (attribute_length == 0)
				break;
			if (attribute_length < NLA_HDRLEN)
				return ERANGE;
			if (pt->nested_policy) {
				error = nla_validate(nla_data(nla), maxtype, pt->nested_policy, depth + 1); 
				if (error) {
					return error;
				}
			}
			break;


		default:
			// Refer to policy minimum length, else use pre-defined minimum length
			if (pt->len)
				minlen = pt->len;
			else
				minlen = nla_attr_minlen[pt->type];

			if (attribute_length < minlen)
				return ERANGE;
	}
	//TODO: Further validation
	return 0;
}

	static int
nla_validate_parse(struct nlattr *head, int maxtype,int len,
		struct nla_policy *policy, 
		struct nlattr **tb, unsigned int depth) 
{
	int error;
	uint16_t type;
	struct nlattr *nla;
	int rem;


	if (depth >= MAX_POLICY_RECURSION_DEPTH) {
		// Max recursion depth exceeded
		return EINVAL;
	}

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));
	nla_for_each_attribute(nla, head, len, rem) {
		type = nla_type(nla);
		if (type > maxtype) {
			return EINVAL;
		}
		if (policy) {
			error = nla_validate(nla, maxtype, policy,  depth);
			if (error < 0)
				return error;
		}

		tb[type] = (struct nlattr *)nla;
	}
	return 0;
}

	static inline int
nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data)
{
	struct nlattr *nla;
	size_t totlen = NLMSG_ALIGN(NLA_HDRLEN) + NLMSG_ALIGN(attrlen);
	struct nlmsghdr *hdr = mtod(m, struct nlmsghdr *);

	//TODO: Check size limit or change to append
	nla = (struct nlattr *)(nl_data_end_ptr(m));
	nla->nla_len = totlen;
	nla->nla_type = attrtype;
	if (attrlen > 0) {
		bcopy(data, (unsigned char*)nl_data_end_ptr(m) + NLMSG_ALIGN(NLA_HDRLEN), attrlen);
	}
	//TODO: check sizes
	m->m_pkthdr.len += totlen;
	m->m_len += totlen;
	hdr->nlmsg_len += NLMSG_ALIGN(NLA_HDRLEN)  + attrlen;

	return 0;
}

	static inline struct nlattr*
nla_nest_start(struct mbuf *m, int attrtype) 
{
	struct nlattr* nla = (struct nlattr*) nl_data_end_ptr(m);
	if (nla_put(m, attrtype, 0, NULL) > 0) {
		return NULL;
	}
	return nla;
}


static inline int
nla_nest_end(struct mbuf *m, struct nlattr *nla) {
	nla->nla_len = (unsigned char *)nl_data_end_ptr(m) - (unsigned char *) nla;
	return nla->nla_len;
}


	static inline int
nla_put_u8(struct mbuf *m, int attrtype, uint8_t value)
{
	return nla_put(m, attrtype, sizeof(uint8_t), &value);
}

	static inline int
nla_put_u16(struct mbuf *m, int attrtype, uint16_t value)
{
	return nla_put(m, attrtype, sizeof(uint16_t), &value);
}

	static inline int
nla_put_u32(struct mbuf *m, int attrtype, uint32_t value)
{
	return nla_put(m, attrtype, sizeof(uint32_t), &value);
}

	static inline int
nla_put_u64(struct mbuf *m, int attrtype, uint64_t value)
{
	return nla_put(m, attrtype, sizeof(uint64_t), &value);
}

	static inline int
nla_put_s8(struct mbuf *m, int attrtype, int8_t value)
{
	return nla_put(m, attrtype, sizeof(int8_t), &value);
}

	static inline int
nla_put_s16(struct mbuf *m, int attrtype, int16_t value)
{
	return nla_put(m, attrtype, sizeof(int16_t), &value);
}

	static inline int
nla_put_s32(struct mbuf *m, int attrtype, int32_t value)
{
	return nla_put(m, attrtype, sizeof(int32_t), &value);
}

	static inline int
nla_put_s64(struct mbuf *m, int attrtype, int64_t value)
{
	return nla_put(m, attrtype, sizeof(int64_t), &value);
}
	static inline int
nla_put_flag(struct mbuf *m, int attrtype)
{
	return nla_put(m, attrtype, 0, NULL);
}

	static inline int
nla_put_string(struct mbuf *m, int attrtype, const char *str)
{
	return nla_put(m, attrtype, strlen(str) + 1, str);
}

	static inline uint8_t
nla_get_u8( struct nlattr *nla)
{
	return *( uint8_t *) nla_data(nla);
}

	static inline uint16_t
nla_get_u16( struct nlattr *nla)
{
	return *( uint16_t *) nla_data(nla);
}
	static inline uint32_t
nla_get_u32( struct nlattr *nla)
{
	return *( uint32_t *) nla_data(nla);
}

	static inline uint64_t 
nla_get_u64( struct nlattr *nla)
{
	return *( uint64_t *) nla_data(nla);
}
	static inline int8_t
nla_get_s8( struct nlattr *nla)
{
	return *( int8_t *) nla_data(nla);
}

	static inline int16_t
nla_get_s16( struct nlattr *nla)
{
	return *( int16_t *) nla_data(nla);
}
	static inline int32_t
nla_get_s32( struct nlattr *nla)
{
	return *( int32_t *) nla_data(nla);
}

	static inline int64_t 
nla_get_s64( struct nlattr *nla)
{
	return *( int64_t *) nla_data(nla);
}


static inline int
nla_get_flag(struct nlattr *nla) {
	return !!nla;
}

	static int 
nla_memcpy(void *dest, struct nlattr *src, int count)
{
	int minlen = min(count, nla_len(src));

	memcpy(dest, nla_data(src), minlen);
	if (count > minlen)
		memset((char*)dest + minlen, 0, count - minlen);

	return minlen;
}


static int
nla_strcpy(char *dst, struct nlattr *nla, size_t dstsize) {

	size_t srclen = nla_len(nla);
	char *src = nla_data(nla);
	ssize_t ret;
	size_t len;


	if (srclen > 0 && src[srclen - 1] == '\0')
		srclen--;

	if (srclen >= dstsize) {
		len = dstsize - 1;
		ret = E2BIG;
	} else {
		len = srclen;
		ret = len;
	}

	memcpy(dst, src, len);
	/* Zero pad end of dst. */
	memset(dst + len, 0, dstsize - len);

	return ret;
}

