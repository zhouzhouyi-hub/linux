// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd
 */
#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/rculist_bl.h>
#include <linux/psi.h>


struct rcu_params rcu_params;

extern struct bpf_struct_ops bpf_bpf_ucas_ops;


static int bpf_ucas_init(struct btf *btf)
{
	return 0;
}

static bool bpf_ucas_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_ucas_ops_btf_struct_access(struct bpf_verifier_log *log,
					   const struct bpf_reg_state *reg,
					   int off, int size)
{
#if 0	
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;

	type_id = btf_find_by_name_kind(reg->btf, "psi_group",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);
	if (t != state) {
		bpf_log(log, "only access to psi_group is supported\n");
		return -EACCES;
	}

	if (off + size > sizeof(struct bpf_ucas_ops_state)) {
		bpf_log(log, "write access at off %d with size %d\n", off, size);
		return -EACCES;
	}
#endif
	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_ucas_verifier_ops = {
	.is_valid_access = bpf_ucas_ops_is_valid_access,
	.btf_struct_access = bpf_ucas_ops_btf_struct_access,
};

static int bpf_ucas_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	return 0;//-EOPNOTSUPP;
}
struct bpf_ucas_ops *opsucas = 0;
static int bpf_ucas_reg(void *kdata)
{
	opsucas = kdata;
	return 0;//-EOPNOTSUPP;
}

static void bpf_ucas_unreg(void *kdata)
{
	struct psi_group *group = &psi_system;
	rcu_params.jiffies_to_sched_qs = 0x11;
	opsucas->test_1(group, &rcu_params);
	printk(KERN_INFO"bpf_ucas_unreg %x\n", rcu_params.jiffies_to_sched_qs);
}

struct bpf_struct_ops bpf_bpf_ucas_ops = {
	.verifier_ops = &bpf_ucas_verifier_ops,
	.init = bpf_ucas_init,
	.init_member = bpf_ucas_init_member,
	.reg = bpf_ucas_reg,
	.unreg = bpf_ucas_unreg,
	.name = "bpf_ucas_ops",
};
