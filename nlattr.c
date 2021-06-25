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
 * nla_ok - check if the netlink attribute fits into the remaining bytes
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 */
static inline int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int) sizeof(*nla) &&
		nla->nla_len >= sizeof(*nla) &&
		nla->nla_len <= remaining;
}

/**
 * nla_next - next netlink attribute in attribute stream
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 *
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
		struct nla_policy *policy, unsigned int validate,
		unsigned int depth) 
{
	const struct nla_policy *pt;
	int attribute_type, attribute_length, minlen; 

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
			//TODO:
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
		struct nla_policy *policy, unsigned int validate,
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
			return -EINVAL;
		}
		if (policy) {
			error = nla_validate(nla, maxtype, policy, validate, depth);
			if (error < 0)
				return error;
		}

		tb[type] = (struct nlattr *)nla;
	}
	return 0;
}

	static int
nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data)
{
	struct nlattr *nla;
	size_t totlen = NLMSG_ALIGN(NLA_HDRLEN) + NLMSG_ALIGN(attrlen);

	//TODO: Check size limit
	nla = mtod(m, struct nlattr *);
	nla->nla_len = totlen;
	nla->nla_type = attrtype;
	if (attrlen > 0) {
		bcopy(data, mtod(m, char *) + NLMSG_ALIGN(NLA_HDRLEN), attrlen);
	}
	m->m_pkthdr.len += totlen;
	return 0;
}
