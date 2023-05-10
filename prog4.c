#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<linux/sched.h>

struct execve_params{

  __u64 __unused;
  __u64 __unused2;
  char* filename;
};

struct event{
  int pid;
  char filename[512];
};

struct {
  __uint(type,BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,256*1024);
} ringbuf SEC(".maps");

SEC("kprobe/prepare_kernel_cred")
int detect_prepare_kernel_cred(struct pt_regs* ctx, struct task_struct* daemon){
  bpf_printk("prepare_kernel_cred called");
  return 0;
}

char _license[] SEC("license") = "GPL";