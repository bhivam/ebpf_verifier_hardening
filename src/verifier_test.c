#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>

#include "libbpf.h"
#include "verifier_test.h"
#include "string.h"

int regs[] = {
	BPF_REG_0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
};

// would these be better as a macro?
int hasFullKnowledge(abstract_register_state state)
{
	return state.mask == 0 && state.u64_max == state.u64_min &&
		state.s64_max == state.s64_min && state.u32_max == state.u32_min &&
		state.s32_max == state.s32_min;
}

// TODO int hasNoKnowledge(abstract_register_state state);

bpf_prog gen_prog(abstract_register_state *state, struct bpf_insn test_insn)
{
	bpf_prog prog;
	int bpf_insn_size = 8;
	int num_insns = 0;

	prog.insns = malloc(1);

	for (int i = 0; i < 10; i++) {
		abstract_register_state curr_reg = state[i];

		if (hasFullKnowledge(curr_reg))
		{
			num_insns += 2;
			prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
			struct bpf_insn ld_imm64_insn[2] = {BPF_LD_IMM64(regs[i], curr_reg.value)};
			prog.insns[num_insns-2] = ld_imm64_insn[0];
			prog.insns[num_insns-1] = ld_imm64_insn[1];
		}
		else
		{
			num_insns += 3;
			prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
			prog.insns[num_insns-3] = BPF_MOV64_IMM(regs[i], 0);
			prog.insns[num_insns-2] = BPF_ALU64_IMM(BPF_NEG, regs[i], 0);
			prog.insns[num_insns-1] = BPF_ALU64_IMM(BPF_NEG, regs[i], 0);
		}
	}

	num_insns += 3;
	prog.insns = realloc(prog.insns, bpf_insn_size * num_insns);
	// only regular instructions assumption (for now)
	prog.insns[num_insns-3] = test_insn;
	prog.insns[num_insns-2] = BPF_MOV64_IMM(BPF_REG_0, 0);
	prog.insns[num_insns-1] = BPF_EXIT_INSN();

	prog.size = num_insns * bpf_insn_size;
	
	return prog;
}



int main(int argc, char **argv)
{
	abstract_register_state state[] = {
		{.mask = 0xffffffffffffffff, .value = 0}, // reg 0
		{.mask = 0xffffffffffffffff, .value = 0}, // reg 1
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 2
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 3
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 4
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 5
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 6
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 7
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 8
		{.mask = 0xffffffffffffffff, .value = 10}, // reg 9
	};
	struct bpf_insn test_insn = BPF_MOV64_IMM(BPF_REG_0, 0);
	
	bpf_prog prog = gen_prog(state, test_insn);
	int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog.insns, prog.size, "GPL", 0);

	printf("VERIFIER LOG:\n%s", bpf_log_buf);

	printf("LOG LEN: %d\n", strlen(bpf_log_buf));
	
	if (prog_fd < 0)
	{
		printf("PROGRAM FAILED VERIFICATION: %s\n", strerror(errno));

		return -1;
	}

	return 0;
}
