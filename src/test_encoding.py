from z3 import *
import json
from lib_reg_bounds_tracking import *
from packaging import version

"""
1. Depending on version we need different json offset
2. The jump instructions require a different set up
3. ALU instrucitons need a different setup

"""
def main():
    s = Optimize()
    smt_file = "../bpf-encodings/5.9/BPF_ADD.smt2"
    
    insn_ver = "5.9"

    abstract_operator = parse_smt2_file(smt_file)
    s.add(abstract_operator)

    in_json_bpf_enc_mapping = []
    out_json_bpf_enc_mapping = []
    with open(smt_file, "r") as file:
        lines = file.readlines()
        in_json_bpf_enc_mapping = lines[-2].strip()
        in_json_bpf_enc_mapping = in_json_bpf_enc_mapping[1:]
        in_json_bpf_enc_mapping = json.loads(in_json_bpf_enc_mapping)

        out_json_bpf_enc_mapping = lines[-1].strip()
        out_json_bpf_enc_mapping = out_json_bpf_enc_mapping[1:]
        out_json_bpf_enc_mapping = json.loads(out_json_bpf_enc_mapping)

    # add in output dst reg and then add quantifer constraint saying that we want the output dst

    input_dst_reg = bpf_register("dst_input0")
    input_src_reg = bpf_register("src_input0")
    output_dst_reg = bpf_register("dst_output0")
    
    json_off = 4 if version.parse(insn_ver) == version.parse("4.14") else 5
    
    # update bv mapping handles no 32-bit valus for version less than 5.73c1
    input_dst_reg.update_bv_mappings(in_json_bpf_enc_mapping["dst_reg"][json_off:], "5.9")
    input_src_reg.update_bv_mappings(in_json_bpf_enc_mapping["src_reg"][json_off:], "5.9")
    output_dst_reg.update_bv_mappings(out_json_bpf_enc_mapping["dst_reg"][json_off:], "5.9")
    
    # s.add(input_dst_reg.singleton(19))
    s.add(input_src_reg.singleton(11))
    
    s.add(input_dst_reg.fully_unknown())
    # s.add(input_src_reg.fully_unknown())
    
    if str(s.check()) == "sat": print("At least one abstract state was found\n")
    else: print("No satisfactory abstract states were found\n")
        
    print("val    :", s.model()[output_dst_reg.var_off_value])
    print("mask   :", s.model()[output_dst_reg.var_off_mask])

    print("s64_min:", s.model()[output_dst_reg.smin_value])
    print("s64_max:", s.model()[output_dst_reg.smax_value])

    print("u64_min:", s.model()[output_dst_reg.umin_value])
    print("u64_max:", s.model()[output_dst_reg.umax_value])

    print("s32_min:", s.model()[output_dst_reg.s32_min_value])
    print("s32_max:", s.model()[output_dst_reg.s32_max_value])

    print("u32_min:", s.model()[output_dst_reg.u32_min_value])
    print("u32_max:", s.model()[output_dst_reg.u32_max_value])
    
    s.add(output_dst_reg.check_uniqueness(s))
    
    if str(s.check()) == "sat": print("Solution was not unique\n")
    else: print("Solution was unique\n")   

if __name__ == "__main__":
    main()
