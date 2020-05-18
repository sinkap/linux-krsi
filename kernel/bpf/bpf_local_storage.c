// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook  */
#include "linux/bpf.h"
#include "asm-generic/bug.h"
#include "linux/err.h"
#include "linux/fs.h"
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <net/sock.h>
#include <uapi/linux/sock_diag.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_lsm.h>

static atomic_t cache_idx;

#define LOCAL_STORAGE_CREATE_FLAG_MASK					\
	(BPF_F_NO_PREALLOC | BPF_F_CLONE)

struct bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

enum bpf_local_storage_type {
	BPF_LOCAL_STORAGE_SK,
	BPF_LOCAL_STORAGE_INODE,
};

/* Thp map is not the primary owner of a bpf_local_storage_elem.
 * Instead, the sk->sk_bpf_storage is.
 *
 * The map (bpf_local_storage_map) is for two purposes
 * 1. Define the size of the "local storage".  It is
 *    the map's value_size.
 *
 * 2. Maintain a list to keep track of all elems such
 *    that they can be cleaned up during the map destruction.
 *
 * When a bpf local storage is being looked up for a
 * particular sk,  the "bpf_map" pointer is actually used
 * as the "key" to search in the list of elem in
 * the respective bpf_local_storage owned by the object.
 *
 * e.g. sk->sk_bpf_storage is the mini-map with the "bpf_map" pointer
 * as the searching key.
 */
struct bpf_local_storage_map {
	struct bpf_map map;
	/* Lookup elem does not require accessing the map.
	 *
	 * Updating/Deleting requires a bucket lock to
	 * link/unlink the elem from the map.  Having
	 * multiple buckets to improve contention.
	 */
	struct bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
};

struct bpf_local_storage_data {
	/* smap is used as the searching key when looking up
	 * from sk->sk_bpf_storage.
	 *
	 * Put it in the same cacheline as the data to minimize
	 * the number of cachelines access during the cache hit case.
	 */
	struct bpf_local_storage_map __rcu *smap;
	u8 data[] __aligned(8);
};

/* Linked to bpf_local_storage and bpf_local_storage_map */
struct bpf_local_storage_elem {
	struct hlist_node map_node;	/* Linked to bpf_local_storage_map */
	struct hlist_node snode;	/* Linked to bpf_local_storage */
	struct bpf_local_storage __rcu *local_storage;
	struct rcu_head rcu;
	/* 8 bytes hole */
	/* The data is stored in aother cacheline to minimize
	 * the number of cachelines access during a cache hit.
	 */
	struct bpf_local_storage_data sdata ____cacheline_aligned;
};

#define SELEM(_SDATA)                                                          \
	container_of((_SDATA), struct bpf_local_storage_elem, sdata)
#define SDATA(_SELEM) (&(_SELEM)->sdata)
#define BPF_STORAGE_CACHE_SIZE	16

struct bpf_local_storage {
	struct bpf_local_storage_data __rcu *cache[BPF_STORAGE_CACHE_SIZE];
	struct hlist_head list;		/* List of bpf_local_storage_elem */
	/* The object that owns the the above "list" of
	 * bpf_local_storage_elem
	 */
	union {
		struct sock *sk;
		struct inode *inode;
	};
	struct rcu_head rcu;
	raw_spinlock_t lock;	/* Protect adding/removing from the "list" */
	enum bpf_local_storage_type stype;
};

static struct bucket *select_bucket(struct bpf_local_storage_map *smap,
				    struct bpf_local_storage_elem *selem)
{
	return &smap->buckets[hash_ptr(selem, smap->bucket_log)];
}

static int omem_charge(struct sock *sk, unsigned int size)
{
	/* same check as in sock_kmalloc() */
	if (size <= sysctl_optmem_max &&
	    atomic_read(&sk->sk_omem_alloc) + size < sysctl_optmem_max) {
		atomic_add(size, &sk->sk_omem_alloc);
		return 0;
	}

	return -ENOMEM;
}

static bool selem_linked_to_node(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->snode);
}

static bool selem_linked_to_map(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->map_node);
}

static struct bpf_local_storage_elem *selem_alloc(
	struct bpf_local_storage_map *smap, void *value)
{
	struct bpf_local_storage_elem *selem;

	selem = kzalloc(smap->elem_size, GFP_ATOMIC | __GFP_NOWARN);
	if (selem) {
		if (value)
			memcpy(SDATA(selem)->data, value, smap->map.value_size);
		return selem;
	}

	return NULL;
}

static struct bpf_local_storage_elem *sk_selem_alloc(
	struct bpf_local_storage_map *smap, struct sock *sk, void *value,
	bool charge_omem)
{
	struct bpf_local_storage_elem *selem;

	if (charge_omem && omem_charge(sk, smap->elem_size))
		return NULL;

	selem = selem_alloc(smap, value);
	if (selem)
		return selem;

	if (charge_omem)
		atomic_sub(smap->elem_size, &sk->sk_omem_alloc);

	return NULL;
}

static void __unlink_local_storage(struct bpf_local_storage *local_storage,
				   bool uncharge_omem)
{
	struct bpf_storage_blob *bsb;
	struct inode *inode;
	struct sock *sk;

	switch (local_storage->stype) {
	case BPF_LOCAL_STORAGE_SK:
		sk = local_storage->sk;
		if (uncharge_omem)
			atomic_sub(sizeof(struct bpf_local_storage),
				   &sk->sk_omem_alloc);

		/* After this RCU_INIT, sk may be freed and cannot be used */
		RCU_INIT_POINTER(sk->sk_bpf_storage, NULL);
		local_storage->sk = NULL;
		break;
	case BPF_LOCAL_STORAGE_INODE:
		inode = local_storage->inode;
		bsb = bpf_inode(inode);
		if (!bsb)
			return;

		RCU_INIT_POINTER(bsb->storage, NULL);
		local_storage->inode = NULL;
		break;
	}
}

/* local_storage->lock must be held and selem->local_storage == local_storage.
 * The caller must ensure selem->smap is still valid to be
 * dereferenced for its smap->elem_size and smap->cache_idx.
 *
 * uncharge_omem is only relevant when:
 *
 *	local_storage->stype == BPF_LOCAL_STORAGE_SK
 */
static bool __selem_unlink(struct bpf_local_storage *local_storage,
			   struct bpf_local_storage_elem *selem,
			   bool uncharge_omem)
{
	struct bpf_local_storage_map *smap;
	bool free_local_storage;

	smap = rcu_dereference(SDATA(selem)->smap);
	free_local_storage = hlist_is_singular_node(&selem->snode,
						    &local_storage->list);

	/* local_storage is not freed now.  local_storage->lock is
	 * still held and raw_spin_unlock_bh(&local_storage->lock)
	 * will be done by the caller.
	 * Although the unlock will be done under
	 * rcu_read_lock(),  it is more intutivie to
	 * read if kfree_rcu(local_storage, rcu) is done
	 * after the raw_spin_unlock_bh(&local_storage->lock).
	 *
	 * Hence, a "bool free_local_storage" is returned
	 * to the caller which then calls the kfree_rcu()
	 * after unlock.
	 */
	if (free_local_storage)
		__unlink_local_storage(local_storage, uncharge_omem);


	hlist_del_init_rcu(&selem->snode);
	if (rcu_access_pointer(local_storage->cache[smap->cache_idx]) ==
	    SDATA(selem))
		RCU_INIT_POINTER(local_storage->cache[smap->cache_idx], NULL);

	kfree_rcu(selem, rcu);

	return free_local_storage;
}

static void __selem_link(struct bpf_local_storage *local_storage,
			    struct bpf_local_storage_elem *selem)
{
	RCU_INIT_POINTER(selem->local_storage, local_storage);
	hlist_add_head(&selem->snode, &local_storage->list);
}

static void selem_unlink_map(struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_map *smap;
	struct bucket *b;

	if (unlikely(!selem_linked_to_map(selem)))
		/* selem has already be unlinked from smap */
		return;

	smap = rcu_dereference(SDATA(selem)->smap);
	b = select_bucket(smap, selem);
	raw_spin_lock_bh(&b->lock);
	if (likely(selem_linked_to_map(selem)))
		hlist_del_init_rcu(&selem->map_node);
	raw_spin_unlock_bh(&b->lock);
}

static void selem_link_map(struct bpf_local_storage_map *smap,
			   struct bpf_local_storage_elem *selem)
{
	struct bucket *b = select_bucket(smap, selem);

	raw_spin_lock_bh(&b->lock);
	RCU_INIT_POINTER(SDATA(selem)->smap, smap);
	hlist_add_head_rcu(&selem->map_node, &b->list);
	raw_spin_unlock_bh(&b->lock);
}

static void selem_unlink(struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage *local_storage;
	bool free_local_storage = false;

	/* Always unlink from map before unlinking from local_storage
	 * because selem will be freed after successfully unlinked from
	 * the local_storage.
	 */
	selem_unlink_map(selem);

	if (unlikely(!selem_linked_to_node(selem)))
		/* selem has already been unlinked from its owner */
		return;

	local_storage = rcu_dereference(selem->local_storage);
	raw_spin_lock_bh(&local_storage->lock);
	if (likely(selem_linked_to_node(selem)))
		free_local_storage = __selem_unlink(local_storage, selem, true);
	raw_spin_unlock_bh(&local_storage->lock);

	if (free_local_storage)
		kfree_rcu(local_storage, rcu);
}

static struct bpf_local_storage_data *
__local_storage_lookup(struct bpf_local_storage *local_storage,
		    struct bpf_local_storage_map *smap,
		    bool cacheit_lockit)
{
	struct bpf_local_storage_data *sdata;
	struct bpf_local_storage_elem *selem;

	/* Fast path (cache hit) */
	sdata = rcu_dereference(local_storage->cache[smap->cache_idx]);
	if (sdata && rcu_access_pointer(sdata->smap) == smap)
		return sdata;

	/* Slow path (cache miss) */
	hlist_for_each_entry_rcu(selem, &local_storage->list, snode)
		if (rcu_access_pointer(SDATA(selem)->smap) == smap)
			break;

	if (!selem)
		return NULL;

	sdata = SDATA(selem);
	if (cacheit_lockit) {
		/* spinlock is needed to avoid racing with the
		 * parallel delete.  Otherwise, publishing an already
		 * deleted sdata to the cache will become a use-after-free
		 * problem in the next __local_storage_lookup().
		 */
		raw_spin_lock_bh(&local_storage->lock);
		if (selem_linked_to_node(selem))
			rcu_assign_pointer(
				local_storage->cache[smap->cache_idx], sdata);
		raw_spin_unlock_bh(&local_storage->lock);
	}

	return sdata;
}

static struct bpf_local_storage_data *
sk_storage_lookup(struct sock *sk, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *sk_storage;
	struct bpf_local_storage_map *smap;

	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return __local_storage_lookup(sk_storage, smap, cacheit_lockit);
}

static struct bpf_local_storage_data *inode_storage_lookup(
	struct inode *inode, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *inode_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_inode(inode);
	if (!bsb)
		return ERR_PTR(-ENOENT);

	inode_storage = rcu_dereference(bsb->storage);
	if (!inode_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return __local_storage_lookup(inode_storage, smap, cacheit_lockit);
}

static int check_flags(const struct bpf_local_storage_data *old_sdata,
		       u64 map_flags)
{
	if (old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static struct bpf_local_storage *
bpf_local_storage_alloc(struct bpf_local_storage_map *smap)
{
	struct bpf_local_storage *storage;

	storage = kzalloc(sizeof(*storage), GFP_ATOMIC | __GFP_NOWARN);
	if (!storage)
		return NULL;

	INIT_HLIST_HEAD(&storage->list);
	raw_spin_lock_init(&storage->lock);
	return storage;
}

/* Publish local_storage to the address.  This is used because we are already
 * in a region where we cannot grab a lock on the object owning the storage (
 * (e.g sk->sk_lock). Hence, atomic ops is used.
 *
 * From now on, the addr pointer is protected
 * by the local_storage->lock.  Hence, upon freeing,
 * the local_storage->lock must be held before unlinking the storage from the
 * owner.
 */
static int publish_local_storage(struct bpf_local_storage_elem *first_selem,
				 struct bpf_local_storage **addr,
				 struct bpf_local_storage *curr)
{
	struct bpf_local_storage *prev;

	prev = cmpxchg(addr, NULL, curr);
	if (unlikely(prev)) {
		/* Note that even first_selem was linked to smap's
		 * bucket->list, first_selem can be freed immediately
		 * (instead of kfree_rcu) because
		 * bpf_local_storage_map_free() does a
		 * synchronize_rcu() before walking the bucket->list.
		 * Hence, no one is accessing selem from the
		 * bucket->list under rcu_read_lock().
		 */
		selem_unlink_map(first_selem);
		return -EAGAIN;
	}

	return 0;
}

static int sk_storage_alloc(struct sock *sk,
			    struct bpf_local_storage_map *smap,
			    struct bpf_local_storage_elem *first_selem)
{
	struct bpf_local_storage *curr;
	int err;

	err = omem_charge(sk, sizeof(*curr));
	if (err)
		return err;

	curr = bpf_local_storage_alloc(smap);
	if (!curr) {
		err = -ENOMEM;
		goto uncharge;
	}

	curr->sk = sk;
	curr->stype = BPF_LOCAL_STORAGE_SK;

	__selem_link(curr, first_selem);
	selem_link_map(smap, first_selem);

	err = publish_local_storage(first_selem,
		(struct bpf_local_storage **)&sk->sk_bpf_storage, curr);
	if (err)
		goto uncharge;

	return 0;

uncharge:
	kfree(curr);
	atomic_sub(sizeof(*curr), &sk->sk_omem_alloc);
	return err;
}

static int inode_storage_alloc(struct inode *inode,
			       struct bpf_local_storage_map *smap,
			       struct bpf_local_storage_elem *first_selem)
{
	struct bpf_storage_blob *bsb;
	struct bpf_local_storage *curr;
	int err;

	bsb = bpf_inode(inode);
	if (!bsb)
		return -EINVAL;

	curr = bpf_local_storage_alloc(smap);
	if (!curr)
		return -ENOMEM;

	curr->inode = inode;
	curr->stype = BPF_LOCAL_STORAGE_INODE;

	__selem_link(curr, first_selem);
	selem_link_map(smap, first_selem);

	err = publish_local_storage(first_selem,
		(struct bpf_local_storage **)&bsb->storage, curr);
	if (err) {
		kfree(curr);
		return err;
	}

	return 0;
}

static int check_update_flags(struct bpf_map *map, u64 map_flags)
{
	/* BPF_EXIST and BPF_NOEXIST cannot be both set */
	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST) ||
	    /* BPF_F_LOCK can only be used in a value with spin_lock */
	    unlikely((map_flags & BPF_F_LOCK) && !map_value_has_spin_lock(map)))
		return -EINVAL;

	return 0;
}

static int map_to_storage_type(struct bpf_map *map)
{
	switch (map->map_type) {
	case BPF_MAP_TYPE_SK_STORAGE:
		return BPF_LOCAL_STORAGE_SK;
	case BPF_MAP_TYPE_INODE_STORAGE:
		return BPF_LOCAL_STORAGE_INODE;
	default:
		return -EINVAL;
	}
}

/* sk cannot be going away because it is linking new elem
 * to sk->sk_bpf_storage. (i.e. sk->sk_refcnt cannot be 0).
 * Otherwise, it will become a leak (and other memory issues
 * during map destruction).
 */
static struct bpf_local_storage_data *local_storage_update(
	void *owner, struct bpf_map *map, void *value, u64 map_flags)
{
	struct bpf_local_storage_data *old_sdata = NULL;
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *local_storage;
	struct bpf_local_storage_map *smap;
	enum bpf_local_storage_type stype;
	struct bpf_storage_blob *bsb;
	struct inode *inode;
	struct sock *sk;
	int err;

	err = check_update_flags(map, map_flags);
	if (err)
		return ERR_PTR(err);

	stype = map_to_storage_type(map);
	if (stype < 0)
		return ERR_PTR(stype);

	smap = (struct bpf_local_storage_map *)map;

	switch (stype) {
	case BPF_LOCAL_STORAGE_SK:
		sk = owner;
		local_storage = rcu_dereference(sk->sk_bpf_storage);
		break;
	case BPF_LOCAL_STORAGE_INODE:
		inode = owner;
		bsb = bpf_inode(inode);
		local_storage = rcu_dereference(bsb->storage);
		break;
	default:
		WARN_ON_ONCE(1);
		return ERR_PTR(-EINVAL);
	}

	if (!local_storage || hlist_empty(&local_storage->list)) {
		/* Very first elem */
		err = check_flags(NULL, map_flags);
		if (err)
			return ERR_PTR(err);

		switch (stype) {
		case BPF_LOCAL_STORAGE_SK:
			selem = sk_selem_alloc(smap, sk, value, true);
			if (!selem)
				return ERR_PTR(-ENOMEM);

			err = sk_storage_alloc(sk, smap, selem);
			if (err) {
				kfree(selem);
				atomic_sub(smap->elem_size, &sk->sk_omem_alloc);
				return ERR_PTR(err);
			}

			return SDATA(selem);
		case BPF_LOCAL_STORAGE_INODE:
			selem = selem_alloc(smap, value);
			if (!selem)
				return ERR_PTR(-ENOMEM);

			err = inode_storage_alloc(inode, smap, selem);
			if (err) {
				kfree(selem);
				return ERR_PTR(err);
			}

			return SDATA(selem);
		}
	}

	if ((map_flags & BPF_F_LOCK) && !(map_flags & BPF_NOEXIST)) {
		/* Hoping to find an old_sdata to do inline update
		 * such that it can avoid taking the local_storage->lock
		 * and changing the lists.
		 */
		old_sdata = __local_storage_lookup(local_storage, smap, false);
		err = check_flags(old_sdata, map_flags);
		if (err)
			return ERR_PTR(err);

		if (old_sdata && selem_linked_to_node(SELEM(old_sdata))) {
			copy_map_value_locked(map, old_sdata->data,
					      value, false);
			return old_sdata;
		}
	}

	raw_spin_lock_bh(&local_storage->lock);

	/* Recheck local_storage->list under local_storage->lock */
	if (unlikely(hlist_empty(&local_storage->list))) {
		/* A parallel del is happening and local_storage is going
		 * away.  It has just been checked before, so very
		 * unlikely.  Return instead of retry to keep things
		 * simple.
		 */
		err = -EAGAIN;
		goto unlock_err;
	}

	old_sdata = __local_storage_lookup(local_storage, smap, false);
	err = check_flags(old_sdata, map_flags);
	if (err)
		goto unlock_err;

	if (old_sdata && (map_flags & BPF_F_LOCK)) {
		copy_map_value_locked(map, old_sdata->data, value, false);
		selem = SELEM(old_sdata);
		goto unlock;
	}

	/* local_storage->lock is held.  Hence, we are sure
	 * we can unlink and uncharge the old_sdata successfully
	 * later.  Hence, instead of charging the new selem now
	 * and then uncharge the old selem later (which may cause
	 * a potential but unnecessary charge failure),  avoid taking
	 * a charge at all here (the "!old_sdata" check) and the
	 * old_sdata will not be uncharged later during __selem_unlink().
	 */
	switch (stype) {
	case BPF_LOCAL_STORAGE_SK:
		selem = sk_selem_alloc(smap, sk, value, !old_sdata);
		if (!selem) {
			err = -ENOMEM;
			goto unlock_err;
		}
		break;
	case BPF_LOCAL_STORAGE_INODE:
		selem = selem_alloc(smap, value);
		if (!selem) {
			err = -ENOMEM;
			goto unlock_err;
		}
		break;
	}

	/* First, link the new selem to the map */
	selem_link_map(smap, selem);

	/* Second, link (and publish) the new selem to local_storage */
	__selem_link(local_storage, selem);

	/* Third, remove old selem, SELEM(old_sdata) */
	if (old_sdata) {
		selem_unlink_map(SELEM(old_sdata));
		__selem_unlink(local_storage, SELEM(old_sdata), false);
	}

unlock:
	raw_spin_unlock_bh(&local_storage->lock);
	return SDATA(selem);

unlock_err:
	raw_spin_unlock_bh(&local_storage->lock);
	return ERR_PTR(err);
}

static int sk_storage_delete(struct sock *sk, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = sk_storage_lookup(sk, map, false);
	if (!sdata)
		return -ENOENT;

	selem_unlink(SELEM(sdata));

	return 0;
}

static int inode_storage_delete(struct inode *inode, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = inode_storage_lookup(inode, map, false);
	if (!sdata)
		return -ENOENT;

	selem_unlink(SELEM(sdata));

	return 0;
}

/* Called by __sk_destruct() & bpf_sk_storage_clone() */
void bpf_sk_storage_free(struct sock *sk)
{
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *sk_storage;
	bool free_sk_storage = false;
	struct hlist_node *n;

	rcu_read_lock();
	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage) {
		rcu_read_unlock();
		return;
	}

	/* Netiher the bpf_prog nor the bpf-map's syscall
	 * could be modifying the sk_storage->list now.
	 * Thus, no elem can be added-to or deleted-from the
	 * local_storage->list by the bpf_prog or by the bpf-map's syscall.
	 *
	 * It is racing with bpf_local_storage_map_free() alone
	 * when unlinking elem from the sk_storage->list and
	 * the map's bucket->list.
	 */
	raw_spin_lock_bh(&sk_storage->lock);
	hlist_for_each_entry_safe(selem, n, &sk_storage->list, snode) {
		/* Always unlink from map before unlinking from
		 * sk_storage.
		 */
		selem_unlink_map(selem);
		free_sk_storage = __selem_unlink(sk_storage, selem, true);
	}
	raw_spin_unlock_bh(&sk_storage->lock);
	rcu_read_unlock();

	if (free_sk_storage)
		kfree_rcu(sk_storage, rcu);
}

/* Called by __destroy_inode() */
void bpf_inode_storage_free(struct inode *inode)
{
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *local_storage;
	bool free_inode_storage = false;
	struct bpf_storage_blob *bsb;
	struct hlist_node *n;

	bsb = bpf_inode(inode);
	if (!bsb)
		return;

	rcu_read_lock();

	local_storage = rcu_dereference(bsb->storage);
	if (!local_storage) {
		rcu_read_unlock();
		return;
	}

	/* Netiher the bpf_prog nor the bpf-map's syscall
	 * could be modifying the local_storage->list now.
	 * Thus, no elem can be added-to or deleted-from the
	 * local_storage->list by the bpf_prog or by the bpf-map's syscall.
	 *
	 * It is racing with bpf_local_storage_map_free() alone
	 * when unlinking elem from the local_storage->list and
	 * the map's bucket->list.
	 */
	raw_spin_lock_bh(&local_storage->lock);
	hlist_for_each_entry_safe(selem, n, &local_storage->list, snode) {
		/* Always unlink from map before unlinking from
		 * local_storage.
		 */
		selem_unlink_map(selem);
		free_inode_storage =
			__selem_unlink(local_storage, selem, false);
	}
	raw_spin_unlock_bh(&local_storage->lock);
	rcu_read_unlock();

	/* free_inoode_storage should always be true as long as
	 * local_storage->list was non-empty.
	 */
	if (free_inode_storage)
		kfree_rcu(local_storage, rcu);
}

static void bpf_local_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage_map *smap;
	struct bucket *b;
	unsigned int i;

	smap = (struct bpf_local_storage_map *)map;

	/* Note that this map might be concurrently cloned from
	 * bpf_sk_storage_clone. Wait for any existing bpf_sk_storage_clone
	 * RCU read section to finish before proceeding. New RCU
	 * read sections should be prevented via bpf_map_inc_not_zero.
	 */
	synchronize_rcu();

	/* bpf prog and the userspace can no longer access this map
	 * now.  No new selem (of this map) can be added
	 * to the bpf_local_storage or to the map bucket's list.
	 *
	 * The elem of this map can be cleaned up here
	 * or by bpf_local_storage_free() during the destruction of the
	 * owner object. eg. __sk_destruct or __destroy_inode.
	 */
	for (i = 0; i < (1U << smap->bucket_log); i++) {
		b = &smap->buckets[i];

		rcu_read_lock();
		/* No one is adding to b->list now */
		while ((selem = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(&b->list)),
						 struct bpf_local_storage_elem,
						 map_node))) {
			selem_unlink(selem);
			cond_resched_rcu();
		}
		rcu_read_unlock();
	}

	/* bpf_local_storage_free() may still need to access the map.
	 * e.g. bpf_local_storage_free() has unlinked selem from the map
	 * which then made the above while((selem = ...)) loop
	 * exited immediately.
	 *
	 * However, the bpf_local_storage_free() still needs to access
	 * the smap->elem_size to do the uncharging in
	 * __selem_unlink().
	 *
	 * Hence, wait another rcu grace period for the
	 * bpf_local_storage_free() to finish.
	 */
	synchronize_rcu();

	kvfree(smap->buckets);
	kfree(map);
}

/* U16_MAX is much more than enough for sk local storage
 * considering a tcp_sock is ~2k.
 */
#define MAX_VALUE_SIZE							\
	min_t(u32,							\
	      (KMALLOC_MAX_SIZE - MAX_BPF_STACK -			\
	       sizeof(struct bpf_local_storage_elem)),			\
	      (U16_MAX - sizeof(struct bpf_local_storage_elem)))

static int bpf_local_storage_map_alloc_check(union bpf_attr *attr)
{
	if (attr->map_flags & ~LOCAL_STORAGE_CREATE_FLAG_MASK ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->max_entries ||
	    attr->key_size != sizeof(int) || !attr->value_size ||
	    /* Enforce BTF for userspace sk dumping */
	    !attr->btf_key_type_id || !attr->btf_value_type_id)
		return -EINVAL;

	if (!bpf_capable())
		return -EPERM;

	if (attr->value_size > MAX_VALUE_SIZE)
		return -E2BIG;

	return 0;
}


static struct bpf_map *
bpf_local_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;
	unsigned int i;
	u32 nbuckets;
	u64 cost;
	int ret;

	smap = kzalloc(sizeof(*smap), GFP_USER | __GFP_NOWARN);
	if (!smap)
		return ERR_PTR(-ENOMEM);
	bpf_map_init_from_attr(&smap->map, attr);

	nbuckets = roundup_pow_of_two(num_possible_cpus());
	/* Use at least 2 buckets, select_bucket() is undefined behavior with 1 bucket */
	nbuckets = max_t(u32, 2, nbuckets);
	smap->bucket_log = ilog2(nbuckets);
	cost = sizeof(*smap->buckets) * nbuckets + sizeof(*smap);

	ret = bpf_map_charge_init(&smap->map.memory, cost);
	if (ret < 0) {
		kfree(smap);
		return ERR_PTR(ret);
	}

	smap->buckets = kvcalloc(sizeof(*smap->buckets), nbuckets,
				 GFP_USER | __GFP_NOWARN);
	if (!smap->buckets) {
		bpf_map_charge_finish(&smap->map.memory);
		kfree(smap);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < nbuckets; i++) {
		INIT_HLIST_HEAD(&smap->buckets[i].list);
		raw_spin_lock_init(&smap->buckets[i].lock);
	}

	smap->elem_size =
		sizeof(struct bpf_local_storage_elem) + attr->value_size;
	smap->cache_idx = (unsigned int)atomic_inc_return(&cache_idx) %
		BPF_STORAGE_CACHE_SIZE;

	return &smap->map;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

static int bpf_local_storage_map_check_btf(const struct bpf_map *map,
					const struct btf *btf,
					const struct btf_type *key_type,
					const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

static void *bpf_sk_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct socket *sock;
	int fd, err = -EINVAL;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		sdata = sk_storage_lookup(sock->sk, map, true);
		sockfd_put(sock);
		return sdata ? sdata->data : NULL;
	}

	return ERR_PTR(err);
}

static void *bpf_inode_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct inode *inode;
	int err = -EINVAL;

	if (key) {
		inode = *(struct inode **)(key);
		sdata = inode_storage_lookup(inode, map, true);
		return sdata ? sdata->data : NULL;
	}

	return ERR_PTR(err);
}

static int bpf_sk_storage_update_elem(struct bpf_map *map, void *key,
					 void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct socket *sock;
	int fd, err;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		sdata = local_storage_update(sock->sk, map, value, map_flags);
		sockfd_put(sock);
		return PTR_ERR_OR_ZERO(sdata);
	}

	return err;
}

static int bpf_inode_storage_update_elem(struct bpf_map *map, void *key,
					 void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct inode *inode;
	int err = -EINVAL;

	if (key) {
		inode = *(struct inode **)(key);
		sdata = local_storage_update(inode, map, value, map_flags);
		return PTR_ERR_OR_ZERO(sdata);
	}
	return err;
}

static int bpf_sk_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct socket *sock;
	int fd, err;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		err = sk_storage_delete(sock->sk, map);
		sockfd_put(sock);
	}

	return err;
}

static int bpf_inode_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct inode *inode;
	int err = -EINVAL;

	if (key) {
		inode = *(struct inode **)(key);
		err = inode_storage_delete(inode, map);
	}

	return err;
}

static struct bpf_local_storage_elem *
bpf_sk_storage_clone_elem(struct sock *newsk,
			  struct bpf_local_storage_map *smap,
			  struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_elem *copy_selem;

	copy_selem = sk_selem_alloc(smap, newsk, NULL, true);
	if (!copy_selem)
		return NULL;

	if (map_value_has_spin_lock(&smap->map))
		copy_map_value_locked(&smap->map, SDATA(copy_selem)->data,
				      SDATA(selem)->data, true);
	else
		copy_map_value(&smap->map, SDATA(copy_selem)->data,
			       SDATA(selem)->data);

	return copy_selem;
}

int bpf_sk_storage_clone(const struct sock *sk, struct sock *newsk)
{
	struct bpf_local_storage *new_sk_storage = NULL;
	struct bpf_local_storage *sk_storage;
	struct bpf_local_storage_elem *selem;
	int ret = 0;

	RCU_INIT_POINTER(newsk->sk_bpf_storage, NULL);

	rcu_read_lock();
	sk_storage = rcu_dereference(sk->sk_bpf_storage);

	if (!sk_storage || hlist_empty(&sk_storage->list))
		goto out;

	hlist_for_each_entry_rcu(selem, &sk_storage->list, snode) {
		struct bpf_local_storage_elem *copy_selem;
		struct bpf_local_storage_map *smap;
		struct bpf_map *map;

		smap = rcu_dereference(SDATA(selem)->smap);
		if (!(smap->map.map_flags & BPF_F_CLONE))
			continue;

		/* Note that for lockless listeners adding new element
		 * here can race with cleanup in bpf_local_storage_map_free.
		 * Try to grab map refcnt to make sure that it's still
		 * alive and prevent concurrent removal.
		 */
		map = bpf_map_inc_not_zero(&smap->map);
		if (IS_ERR(map))
			continue;

		copy_selem = bpf_sk_storage_clone_elem(newsk, smap, selem);
		if (!copy_selem) {
			ret = -ENOMEM;
			bpf_map_put(map);
			goto out;
		}

		if (new_sk_storage) {
			selem_link_map(smap, copy_selem);
			__selem_link(new_sk_storage, copy_selem);
		} else {
			ret = sk_storage_alloc(newsk, smap, copy_selem);
			if (ret) {
				kfree(copy_selem);
				atomic_sub(smap->elem_size,
					   &newsk->sk_omem_alloc);
				bpf_map_put(map);
				goto out;
			}

			new_sk_storage =
				rcu_dereference(copy_selem->local_storage);
		}
		bpf_map_put(map);
	}

out:
	rcu_read_unlock();

	/* In case of an error, don't free anything explicitly here, the
	 * caller is responsible to call bpf_local_storage_free.
	 */

	return ret;
}

BPF_CALL_4(bpf_sk_storage_get, struct bpf_map *, map, struct sock *, sk,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	if (flags > BPF_SK_STORAGE_GET_F_CREATE)
		return (unsigned long)NULL;

	sdata = sk_storage_lookup(sk, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	if (flags == BPF_LOCAL_STORAGE_GET_F_CREATE &&
	    /* Cannot add new elem to a going away sk.
	     * Otherwise, the new elem may become a leak
	     * (and also other memory issues during map
	     *  destruction).
	     */
	    refcount_inc_not_zero(&sk->sk_refcnt)) {
		sdata = local_storage_update(sk, map, value, BPF_NOEXIST);
		/* sk must be a fullsock (guaranteed by verifier),
		 * so sock_gen_put() is unnecessary.
		 */
		sock_put(sk);
		return IS_ERR(sdata) ?
			(unsigned long)NULL : (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_4(bpf_inode_storage_get, struct bpf_map *, map, struct inode *, inode,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	sdata = inode_storage_lookup(inode, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		sdata = local_storage_update(inode, map, value, BPF_NOEXIST);
		return IS_ERR(sdata) ?
			(unsigned long)NULL : (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_sk_storage_delete, struct bpf_map *, map, struct sock *, sk)
{
	if (refcount_inc_not_zero(&sk->sk_refcnt)) {
		int err;

		err = sk_storage_delete(sk, map);
		sock_put(sk);
		return err;
	}

	return -ENOENT;
}

BPF_CALL_2(bpf_inode_storage_delete,
	   struct bpf_map *, map, struct inode *, inode)
{
	return inode_storage_delete(inode, map);
}

const struct bpf_map_ops sk_storage_map_ops = {
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = bpf_local_storage_map_alloc,
	.map_free = bpf_local_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_sk_storage_lookup_elem,
	.map_update_elem = bpf_sk_storage_update_elem,
	.map_delete_elem = bpf_sk_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
};

const struct bpf_map_ops inode_storage_map_ops = {
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = bpf_local_storage_map_alloc,
	.map_free = bpf_local_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_inode_storage_lookup_elem,
	.map_update_elem = bpf_inode_storage_update_elem,
	.map_delete_elem = bpf_inode_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
};

const struct bpf_func_proto bpf_sk_storage_get_proto = {
	.func		= bpf_sk_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_SOCKET,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_sk_storage_delete_proto = {
	.func		= bpf_sk_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_SOCKET,
};

static int bpf_inode_storage_get_btf_ids[4];
const struct bpf_func_proto bpf_inode_storage_get_proto = {
	.func		= bpf_inode_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
	.btf_id		= bpf_inode_storage_get_btf_ids,
};

static int bpf_inode_storage_delete_btf_ids[2];
const struct bpf_func_proto bpf_inode_storage_delete_proto = {
	.func		= bpf_sk_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID,
	.btf_id		= bpf_inode_storage_delete_btf_ids,
};

struct bpf_sk_storage_diag {
	u32 nr_maps;
	struct bpf_map *maps[];
};

/* The reply will be like:
 * INET_DIAG_BPF_SK_STORAGES (nla_nest)
 *	SK_DIAG_BPF_STORAGE (nla_nest)
 *		SK_DIAG_BPF_STORAGE_MAP_ID (nla_put_u32)
 *		SK_DIAG_BPF_STORAGE_MAP_VALUE (nla_reserve_64bit)
 *	SK_DIAG_BPF_STORAGE (nla_nest)
 *		SK_DIAG_BPF_STORAGE_MAP_ID (nla_put_u32)
 *		SK_DIAG_BPF_STORAGE_MAP_VALUE (nla_reserve_64bit)
 *	....
 */
static int nla_value_size(u32 value_size)
{
	/* SK_DIAG_BPF_STORAGE (nla_nest)
	 *	SK_DIAG_BPF_STORAGE_MAP_ID (nla_put_u32)
	 *	SK_DIAG_BPF_STORAGE_MAP_VALUE (nla_reserve_64bit)
	 */
	return nla_total_size(0) + nla_total_size(sizeof(u32)) +
		nla_total_size_64bit(value_size);
}

void bpf_sk_storage_diag_free(struct bpf_sk_storage_diag *diag)
{
	u32 i;

	if (!diag)
		return;

	for (i = 0; i < diag->nr_maps; i++)
		bpf_map_put(diag->maps[i]);

	kfree(diag);
}
EXPORT_SYMBOL_GPL(bpf_sk_storage_diag_free);

static bool diag_check_dup(const struct bpf_sk_storage_diag *diag,
			   const struct bpf_map *map)
{
	u32 i;

	for (i = 0; i < diag->nr_maps; i++) {
		if (diag->maps[i] == map)
			return true;
	}

	return false;
}

struct bpf_sk_storage_diag *
bpf_sk_storage_diag_alloc(const struct nlattr *nla_stgs)
{
	struct bpf_sk_storage_diag *diag;
	struct nlattr *nla;
	u32 nr_maps = 0;
	int rem, err;

	/* bpf_local_storage_map is currently limited to CAP_SYS_ADMIN as
	 * the map_alloc_check() side also does.
	 */
	if (!bpf_capable())
		return ERR_PTR(-EPERM);

	nla_for_each_nested(nla, nla_stgs, rem) {
		if (nla_type(nla) == SK_DIAG_BPF_STORAGE_REQ_MAP_FD)
			nr_maps++;
	}

	diag = kzalloc(sizeof(*diag) + sizeof(diag->maps[0]) * nr_maps,
		       GFP_KERNEL);
	if (!diag)
		return ERR_PTR(-ENOMEM);

	nla_for_each_nested(nla, nla_stgs, rem) {
		struct bpf_map *map;
		int map_fd;

		if (nla_type(nla) != SK_DIAG_BPF_STORAGE_REQ_MAP_FD)
			continue;

		map_fd = nla_get_u32(nla);
		map = bpf_map_get(map_fd);
		if (IS_ERR(map)) {
			err = PTR_ERR(map);
			goto err_free;
		}
		if (map->map_type != BPF_MAP_TYPE_SK_STORAGE) {
			bpf_map_put(map);
			err = -EINVAL;
			goto err_free;
		}
		if (diag_check_dup(diag, map)) {
			bpf_map_put(map);
			err = -EEXIST;
			goto err_free;
		}
		diag->maps[diag->nr_maps++] = map;
	}

	return diag;

err_free:
	bpf_sk_storage_diag_free(diag);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(bpf_sk_storage_diag_alloc);

static int diag_get(struct bpf_local_storage_data *sdata, struct sk_buff *skb)
{
	struct nlattr *nla_stg, *nla_value;
	struct bpf_local_storage_map *smap;

	/* It cannot exceed max nlattr's payload */
	BUILD_BUG_ON(U16_MAX - NLA_HDRLEN < MAX_VALUE_SIZE);

	nla_stg = nla_nest_start(skb, SK_DIAG_BPF_STORAGE);
	if (!nla_stg)
		return -EMSGSIZE;

	smap = rcu_dereference(sdata->smap);
	if (nla_put_u32(skb, SK_DIAG_BPF_STORAGE_MAP_ID, smap->map.id))
		goto errout;

	nla_value = nla_reserve_64bit(skb, SK_DIAG_BPF_STORAGE_MAP_VALUE,
				      smap->map.value_size,
				      SK_DIAG_BPF_STORAGE_PAD);
	if (!nla_value)
		goto errout;

	if (map_value_has_spin_lock(&smap->map))
		copy_map_value_locked(&smap->map, nla_data(nla_value),
				      sdata->data, true);
	else
		copy_map_value(&smap->map, nla_data(nla_value), sdata->data);

	nla_nest_end(skb, nla_stg);
	return 0;

errout:
	nla_nest_cancel(skb, nla_stg);
	return -EMSGSIZE;
}

static int bpf_sk_storage_diag_put_all(struct sock *sk, struct sk_buff *skb,
				       int stg_array_type,
				       unsigned int *res_diag_size)
{
	/* stg_array_type (e.g. INET_DIAG_BPF_SK_STORAGES) */
	unsigned int diag_size = nla_total_size(0);
	struct bpf_local_storage *sk_storage;
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage_map *smap;
	struct nlattr *nla_stgs;
	unsigned int saved_len;
	int err = 0;

	rcu_read_lock();

	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage || hlist_empty(&sk_storage->list)) {
		rcu_read_unlock();
		return 0;
	}

	nla_stgs = nla_nest_start(skb, stg_array_type);
	if (!nla_stgs)
		/* Continue to learn diag_size */
		err = -EMSGSIZE;

	saved_len = skb->len;
	hlist_for_each_entry_rcu(selem, &sk_storage->list, snode) {
		smap = rcu_dereference(SDATA(selem)->smap);
		diag_size += nla_value_size(smap->map.value_size);

		if (nla_stgs && diag_get(SDATA(selem), skb))
			/* Continue to learn diag_size */
			err = -EMSGSIZE;
	}

	rcu_read_unlock();

	if (nla_stgs) {
		if (saved_len == skb->len)
			nla_nest_cancel(skb, nla_stgs);
		else
			nla_nest_end(skb, nla_stgs);
	}

	if (diag_size == nla_total_size(0)) {
		*res_diag_size = 0;
		return 0;
	}

	*res_diag_size = diag_size;
	return err;
}

int bpf_sk_storage_diag_put(struct bpf_sk_storage_diag *diag,
			    struct sock *sk, struct sk_buff *skb,
			    int stg_array_type,
			    unsigned int *res_diag_size)
{
	/* stg_array_type (e.g. INET_DIAG_BPF_SK_STORAGES) */
	unsigned int diag_size = nla_total_size(0);
	struct bpf_local_storage *sk_storage;
	struct bpf_local_storage_data *sdata;
	struct nlattr *nla_stgs;
	unsigned int saved_len;
	int err = 0;
	u32 i;

	*res_diag_size = 0;

	/* No map has been specified.  Dump all. */
	if (!diag->nr_maps)
		return bpf_sk_storage_diag_put_all(sk, skb, stg_array_type,
						   res_diag_size);

	rcu_read_lock();
	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage || hlist_empty(&sk_storage->list)) {
		rcu_read_unlock();
		return 0;
	}

	nla_stgs = nla_nest_start(skb, stg_array_type);
	if (!nla_stgs)
		/* Continue to learn diag_size */
		err = -EMSGSIZE;

	saved_len = skb->len;
	for (i = 0; i < diag->nr_maps; i++) {
		sdata = __local_storage_lookup(sk_storage,
				(struct bpf_local_storage_map *)diag->maps[i],
				false);

		if (!sdata)
			continue;

		diag_size += nla_value_size(diag->maps[i]->value_size);

		if (nla_stgs && diag_get(sdata, skb))
			/* Continue to learn diag_size */
			err = -EMSGSIZE;
	}
	rcu_read_unlock();

	if (nla_stgs) {
		if (saved_len == skb->len)
			nla_nest_cancel(skb, nla_stgs);
		else
			nla_nest_end(skb, nla_stgs);
	}

	if (diag_size == nla_total_size(0)) {
		*res_diag_size = 0;
		return 0;
	}

	*res_diag_size = diag_size;
	return err;
}
EXPORT_SYMBOL_GPL(bpf_sk_storage_diag_put);
