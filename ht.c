#include "ht.h"

int ht_init(ht *x, unsigned tab, unsigned long (*hash)(void *,unsigned))
{
	unsigned tmps;

	x->b = (htbucket **)malloc(tmps = tab * sizeof(htbucket *));
	if (!x->b) return -1;
	memset(x->b, 0, tmps);

	x->s = tab;
	x->hash = hash;
	return 1;
}
static int ht_die_fn(ht *x, void *key, unsigned klen, void *data)
{
	if (ht_delete(x, key, klen) != 1)
		return HT_WILLFAIL;
	return HT_RESTART;
}
int ht_die(ht *x)
{
	if (ht_walk(x, ht_die_fn) == -1)
		return 1;
	return 0;
}
int ht_ondelete(ht *x, int (*fn)(void *data))
{
	x->ondel = fn;
	return 1;
}
int ht_walk(ht *x, int (*fn)(ht *x, void *key, unsigned klen, void *data))
{
	unsigned i;
	htbucket *n;
	int ret = -1;

restart_l:
	for (i = 0; i < x->s; i++) {
		n = x->b[i];
		if (n == 0)
			continue;
		while (n) {
			switch (fn(x, n->key, n->klen, n->data)) {
			case HT_RESTART:	goto restart_l;
			case HT_FAILNOW:	return 0;
			case HT_SUCCESSNOW:	return 1;
			case HT_TRIPSUCCESS:	ret = 1; break;
			case HT_TRIPFAIL:	ret = 0; break;
			case HT_WILLSUCCESS:	if (ret != 0) ret = 1; break;
			case HT_WILLFAIL:	if (ret != 1) ret = 0; break;
			case HT_NEXT:		break;
			case HT_AGAIN:		continue;
			};
			n = (htbucket *)n->next;
		}
	}
	return ret;
}

static int ht_store_flag(ht *x, void *key, unsigned klen, void *data, int flag)
{
	htbucket *n;
	unsigned long hash;
	unsigned pos;

	hash = x->hash(key, klen);
	n = x->b[pos = hash % x->s];
	while (n) {
		if (n->hash == hash && n->klen == klen &&
			memcmp(key, n->key, klen) == 0) {
			return 0; /* collision */
		}
		n = (htbucket *)n->next;
	}

	n = (htbucket *)malloc(sizeof(htbucket));
	if (!n) return -1;

	n->key = key;
	n->klen = klen;
	n->hash = x->hash(key, klen);;
	n->data = data;
	n->next = (void *)x->b[pos];
	n->free_data = flag;
	x->b[pos] = (htbucket *)n;

	return 1;
}
int ht_store(ht *x, void *key, unsigned klen, void *data)
{
	int ret;

	return ht_store_flag(x, key, klen, data, 0);
}
int ht_storecopy(ht *x, void *key, unsigned klen, void *data, unsigned dlen)
{
	int ret;
	void *copy;

	copy = (void *)malloc(dlen);
	if (!copy) return -1;
	memcpy(copy, data, dlen);
	ret = ht_store_flag(x, key, klen, copy, 1);

	if (ret != 1)
		free(copy);
	return ret;
}
void *ht_fetch(ht *x, void *key, unsigned klen)
{
	htbucket *n;
	unsigned long hash;

	hash = x->hash(key, klen);
	n = x->b[hash % x->s];
	while (n) {
		if (n->hash == hash && n->klen == klen &&
			memcmp(key, n->key, klen) == 0) {
			return n->data;
		}
		n = (htbucket *)n->next;
	}
	return (void *)0;
}
int ht_delete(ht *x, void *key, unsigned klen)
{
	htbucket *n, *ln;
	unsigned long hash;
	unsigned pos;

	hash = x->hash(key, klen);
	n = x->b[pos = hash % x->s];
	ln = 0;
	while (n) {
		if (n->hash == hash && n->klen == klen &&
			memcmp(key, n->key, klen) == 0) {
			if (ln)
				ln->next = n->next;
			else
				x->b[pos] = n->next;
			if (n->free_data)
				free(n->data);
			free(n);
			return 1;
		}
		ln = n;
		n = (htbucket *)n->next;
	}
	return 0;
}
