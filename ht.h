#ifndef __ht_h
#define __ht_h

typedef struct {
	void *key;
	unsigned klen;
	unsigned long hash;
	void *data;
	int free_data;

	void *next;
} htbucket;
typedef struct {
	unsigned s;
	htbucket **b;
	unsigned long (*hash)(void *,unsigned);
	int (*ondel)(void *);
} ht;

enum {	HT_RESTART,
	HT_FAILNOW, HT_SUCCESSNOW,
	HT_TRIPSUCCESS, HT_TRIPFAIL,
	HT_WILLSUCCESS, HT_WILLFAIL,
	HT_NEXT, HT_AGAIN,
};

int ht_init(ht *x, unsigned tab, unsigned long (*hash)(void *, unsigned));
int ht_die(ht *x);
int ht_walk(ht *x, int (*fn)(ht *, void *, unsigned, void *));
int ht_store(ht *x, void *, unsigned, void *);
int ht_storecopy(ht *x, void *, unsigned, void *, unsigned);
void *ht_fetch(ht *x, void *, unsigned);
int ht_delete(ht *x, void *, unsigned);
int ht_ondelete(ht *x, int (*fn)(void *data));

#endif
