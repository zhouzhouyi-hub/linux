// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define NR_PSI_STATES 9
struct psi_group {
	unsigned long rtpoll_until;
	unsigned long avg[18];
} __attribute__((preserve_access_index));

struct rcu_params {
	unsigned long jiffies_to_sched_qs;
} __attribute__((preserve_access_index));

struct bpf_ucas_ops {
	int (*test_1)(struct psi_group * group, struct rcu_params * rcu_params);
	int (*test_2)(struct psi_group * group, int a1, unsigned short a2,
		      char a3, unsigned long a4);
};

char _license[] SEC("license") = "GPL";

SEC("struct_ops/test_1")
int BPF_PROG(test_1, struct psi_group * group, struct rcu_params * rcu_params)
{
	int ret = 0;
	
	rcu_params->jiffies_to_sched_qs = 0x197583 + group->rtpoll_until + group->avg[0];
	return ret;
}

__u64 test_2_args[5];

SEC("struct_ops/test_2")
int BPF_PROG(test_2, struct psi_group * group, int a1, unsigned short a2,
	     char a3, unsigned long a4)
{

	return 0;
}

SEC(".struct_ops")
struct bpf_ucas_ops ucas_1 = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_2,
};
