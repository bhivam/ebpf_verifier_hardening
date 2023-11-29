#ifndef _PROG_GEN_H
#define _PROG_GEN_H

#include <linux/bpf.h>

typedef struct abstract_register_state 
{
	unsigned int u32_min;
	unsigned int u32_max;

	int s32_min;
	int s32_max;
	
	unsigned long long value;
	unsigned long long mask; 

	unsigned long long u64_min;
	unsigned long long u64_max;

	long long s64_min;
	long long s64_max;
} abstract_register_state;

typedef struct bpf_prog 
{
	int size;
	struct bpf_insn *insns;
} bpf_prog;

#endif
