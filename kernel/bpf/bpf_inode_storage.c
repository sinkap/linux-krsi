// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Facebook
 * Copyright 2020 Google LLC.
 */

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
#include <linux/btf_ids.h>
#include <linux/fdtable.h>

static struct bpf_local_storage_elem *
inode_selem_alloc(struct bpf_local_storage_map *smap, void *owner,
		  void *value, bool charge_omem)
{
	return bpf_selem_alloc(smap, value);
}

static bool unlink_inode_storage(struct bpf_local_storage *local_storage,
				 struct bpf_local_storage_elem *selem,
				 bool uncharge_omem)
{
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;
	bool free_local_storage;
	struct inode *inode;

	inode = local_storage->owner;
	bsb = bpf_inode(inode);
	if (!bsb)
		return false;

	smap = rcu_dereference(SDATA(selem)->smap);
	/* All uncharging on sk->sk_omem_alloc must be done first.
	 * sk may be freed once the last selem is unlinked from sk_storage.
	 */

	free_local_storage = hlist_is_singular_node(&selem->snode,
						    &local_storage->list);

	if (free_local_storage) {
		/* After this RCU_INIT, sk may be freed and cannot be used */
		RCU_INIT_POINTER(bsb->storage, NULL);
		local_storage->owner = NULL;
	}

	return free_local_storage;

}

static struct bpf_local_storage_data *inode_storage_lookup(struct inode *inode,
							   struct bpf_map *map,
							   bool cacheit_lockit)
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
	return bpf_local_storage_lookup(inode_storage, smap, cacheit_lockit);
}

static int inode_storage_alloc(void *owner, struct bpf_local_storage_map *smap,
			       struct bpf_local_storage_elem *first_selem)
{
	struct bpf_local_storage *curr;
	struct bpf_storage_blob *bsb;
	struct inode *inode = owner;
	int err;

	bsb = bpf_inode(inode);
	if (!bsb)
		return -EINVAL;

	curr = bpf_local_storage_alloc(smap);
	if (!curr)
		return -ENOMEM;

	curr->owner = inode;

	bpf_selem_link_storage(curr, first_selem);
	bpf_selem_link_map(smap, first_selem);

	err = bpf_local_storage_publish(first_selem,
		(struct bpf_local_storage **)&bsb->storage, curr);
	if (err) {
		kfree(curr);
		return err;
	}

	return 0;
}

static struct bpf_local_storage_data *inode_storage_update(void *owner,
							   struct bpf_map *map,
							   void *value,
							   u64 map_flags)
{
	struct bpf_local_storage_data *old_sdata = NULL;
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *local_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;
	struct inode *inode;
	int err;

	err = bpf_local_storage_check_update_flags(map, map_flags);
	if (err)
		return ERR_PTR(err);

	inode = owner;
	bsb = bpf_inode(inode);
	local_storage = rcu_dereference(bsb->storage);
	smap = (struct bpf_local_storage_map *)map;

	if (!local_storage || hlist_empty(&local_storage->list)) {
		/* Very first elem */
		selem = map->ops->map_selem_alloc(smap, owner, value, !old_sdata);
		if (!selem)
			return ERR_PTR(-ENOMEM);

		err = inode_storage_alloc(owner, smap, selem);
		if (err) {
			kfree(selem);
			return ERR_PTR(err);
		}

		return SDATA(selem);
	}

	return bpf_local_storage_update(owner, map, local_storage, value,
					map_flags);
}


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
		bpf_selem_unlink_map(selem);
		free_inode_storage =
			bpf_selem_unlink_storage(local_storage, selem, false);
	}
	raw_spin_unlock_bh(&local_storage->lock);
	rcu_read_unlock();

	/* free_inoode_storage should always be true as long as
	 * local_storage->list was non-empty.
	 */
	if (free_inode_storage)
		kfree_rcu(local_storage, rcu);
}


static void *bpf_fd_inode_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct file *f;
	int fd;

	fd = *(int *)key;
	f = fcheck(fd);
	if (!f)
		return ERR_PTR(-EINVAL);

	sdata = inode_storage_lookup(f->f_inode, map, true);
	return sdata ? sdata->data : NULL;
}

static int bpf_fd_inode_storage_update_elem(struct bpf_map *map, void *key,
					 void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct file *f;
	int fd;

	fd = *(int *)key;
	f = fcheck(fd);
	if (!f)
		return -EINVAL;

	sdata = inode_storage_update(f->f_inode, map, value, map_flags);
	return PTR_ERR_OR_ZERO(sdata);
}

static int inode_storage_delete(struct inode *inode, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = inode_storage_lookup(inode, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata));

	return 0;
}

static int bpf_fd_inode_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct file *f;
	int fd;

	fd = *(int *)key;
	f = fcheck(fd);
	if (!f)
		return -EINVAL;

	return inode_storage_delete(f->f_inode, map);
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
		sdata = inode_storage_update(inode, map, value, BPF_NOEXIST);
		return IS_ERR(sdata) ?
			(unsigned long)NULL : (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_inode_storage_delete,
	   struct bpf_map *, map, struct inode *, inode)
{
	return inode_storage_delete(inode, map);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

DEFINE_BPF_STORAGE_CACHE(inode);

static struct bpf_map *inode_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;

	smap = bpf_local_storage_map_alloc(attr);
	if (IS_ERR(smap))
		return ERR_CAST(smap);

	smap->cache_idx = cache_idx_get_inode();
	return &smap->map;
}

static void inode_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_map *smap;

	smap = (struct bpf_local_storage_map *)map;
	cache_idx_free_inode(smap->cache_idx);
	bpf_local_storage_map_free(smap);
}

static int inode_storage_map_btf_id;
const struct bpf_map_ops inode_storage_map_ops = {
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = inode_storage_map_alloc,
	.map_free = inode_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_fd_inode_storage_lookup_elem,
	.map_update_elem = bpf_fd_inode_storage_update_elem,
	.map_delete_elem = bpf_fd_inode_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_btf_name = "bpf_local_storage_map",
	.map_btf_id = &inode_storage_map_btf_id,
	.map_selem_alloc = inode_selem_alloc,
	.map_local_storage_update = inode_storage_update,
	.map_local_storage_unlink = unlink_inode_storage,
};

BTF_ID_LIST(bpf_inode_storage_get_btf_ids)
BTF_ID(struct, inode)

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

BTF_ID_LIST(bpf_inode_storage_delete_btf_ids)
BTF_ID(struct, inode)

const struct bpf_func_proto bpf_inode_storage_delete_proto = {
	.func		= bpf_inode_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID,
	.btf_id		= bpf_inode_storage_delete_btf_ids,
};
