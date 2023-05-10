First of all, open the file responsible for reading bpf logs i.e
```
sudo cat /sys/kernel/tracing/trace_pipe
```
After that, run the eBPF program loader using `./run`

<br>
After that, switch the directory to modules and insert the kernel module that will call `prepare_kernel_cred` function when loaded. This log will become visible in the tracepipe.
```
➜  prog4 git:(master) ✗ sudo cat /sys/kernel/tracing/trace_pipe
[sudo] password for sh4dy: 
           <...>-7184    [002] ...21   342.909378: bpf_trace_printk: prepare_kernel_cred called
```