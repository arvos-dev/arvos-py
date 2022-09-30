#!/usr/bin/python3
import subprocess
import argparse
import datetime
import signal
import time
import json
import csv
import sys
import re
import ctypes as ct

from bcc import BPF, USDT
#from pip_requirements_parser import RequirementsFile


PERIOD = 10
time.sleep(5)

def signal_handler(signal, frame):
    global interrupted
    interrupted = True

def filter_vulnerabilities(vulnerability_database, req_file):
    relevant_vulnerabilites = []
    for req in req_file:
        for vulnerability in vulnerability_database:
            # TODO(No version information in db)
            # TODO(No package name in db)
            #if vulnerability['package'] == req.name and vulnerability['version'] in req.specifier:
            #    pass
            pass

def find_repeating_sequence(seq):
    guess = 0
    max_len = len(seq) // 2
    for i in range(len(seq)):
        for x in range(2, max_len):
            if seq[0+i:x+i] == seq[x+i:2*x+i] :
                return (i, x)

    return len(seq), guess

class HashStruct(ct.Structure):
    _fields_ = [('hash', ct.c_uint),
                ('lineno', ct.c_int)]

def create_hash_struct(hash_num, lineno):
    hash = HashStruct()
    hash.hash = hash_num
    hash.lineno = lineno
    return hash

def get_stack_trace(hash, lineno):
    stack_trace = []
    
    next_hash = create_hash_struct(hash, lineno)
    i = 0
    while next_hash and len(stack_trace) < 100:
        i += 1
        element = bpf['counts'].get(next_hash)
        if not element:
            break
        
        clazz = element.clazz.decode('utf-8', 'replace')
        method = element.method.decode('utf-8', 'replace')

        trace_string = f"{clazz}.{method}:{element.lineno}"

        # Skip python internal methods
        if not method.startswith('__') and not method.endswith('__'):
            stack_trace.append(trace_string)

        if element.prev_hash == next_hash:
            break

        index, length = find_repeating_sequence(stack_trace)
        if length > 0:
            stack_trace = stack_trace[:index+length]
            break

        next_hash = element.prev_hash

    return stack_trace

# Text colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description="Summarize method calls in high-level languages.")
parser.add_argument("pid", type=int, nargs="?", help="process id to attach to")
parser.add_argument("--detect", action="store_true", help="automatically fetch pid")
parser.add_argument("--debug", action="store_true", help="debug mode")
parser.add_argument('--save-report', default=False, const=False, nargs='?', choices=['csv'], help='Save report as csv')
parser.add_argument("--requirements-file", type=str, help="Provide library version through requirements.txt")

args = parser.parse_args()

if not args.debug:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

if not args.pid and not args.detect:
    print("Must either provide PID or use --detect")
    exit()

if not args.pid and args.detect:    
    try:
        args.pid = int(subprocess.Popen(['pgrep', '-f', '/python3 manage.py runserver'], stdout=subprocess.PIPE).communicate()[0].decode().split('\n')[0])
    except:
        print("Could not automatically detect pid")
        exit()


program = '''
#define MAX_CLASS_LENGTH  150
#define MAX_METHOD_LENGTH 80

DEFINE_DEBUG

struct hash_t {
    u32 hash;
    int lineno;
};

struct method_t {
    struct hash_t prev_hash;        
    u64 pid;                    
    char clazz[MAX_CLASS_LENGTH];
    char method[MAX_METHOD_LENGTH];
    int lineno;
};

BPF_HASH(entry, u64, struct hash_t);
BPF_HASH(counts, struct hash_t, struct method_t);

static u32 hash_func(unsigned char *clazz, unsigned char *method, u32 lineno) {
    int c;
    u32 hash = 5381;
    u32 i = 0;
    while ( (c = *clazz++) && i < MAX_CLASS_LENGTH) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        i++;
    }
    i = 0;
    while ( (c = *method++) && i < MAX_METHOD_LENGTH) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        i++;
    }

    return hash ^ lineno;
}

int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, zero = 0;
    int lineno = 0;

    u64 *valp;
    //u32 new_entry = 0, *old_entry;
    struct hash_t *hash_entry, hash_zero = {0};
    struct method_t data = {0};
    data.pid = bpf_get_current_pid_tgid();

    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);
    bpf_usdt_readarg(3, ctx, &data.lineno);

    bpf_probe_read_user(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read_user(&data.method, sizeof(data.method), (void *)method);

    u32 hash = hash_func(data.clazz, data.method, data.lineno);
    
    hash_entry = entry.lookup(&data.pid);
    if (!hash_entry) { // No previous depth
        hash_entry = &hash_zero;
    }

    data.prev_hash = *hash_entry;

    hash_entry->hash = hash;
    hash_entry->lineno = data.lineno;

    counts.update(hash_entry, &data);
    entry.update(&data.pid, hash_entry);

#ifdef DEBUG
    //bpf_trace_printk("Class: %s", data.clazz);
    bpf_trace_printk("Entry:");
    bpf_trace_printk("Method: %s", data.method);
    bpf_trace_printk("Hash: %u", hash);
    bpf_trace_printk("Lineno: %d", data.lineno);
    bpf_trace_printk("Prev hash: %u", data.prev_hash.hash);
    bpf_trace_printk("Prev lineno: %u", data.prev_hash.lineno);
    bpf_trace_printk("");
#endif //DEBUG

    return 0;
}


int trace_return(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, zero = 0;
    int lineno = 0;

    u64 *valp;
    //u32 hash_entry = 0;
    struct hash_t *hash_entry, hash_zero = {0};
    struct method_t data = {0};
    struct method_t *old_entry;
    data.pid = bpf_get_current_pid_tgid();

    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);
    bpf_usdt_readarg(3, ctx, &data.lineno);

    bpf_probe_read_user(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read_user(&data.method, sizeof(data.method), (void *)method);

    hash_entry = entry.lookup(&data.pid);
    if (!hash_entry) { // No previous depth
        hash_entry = &hash_zero;
    }
    bpf_trace_printk("Pid_hash: %u", hash_entry->hash);
    bpf_trace_printk("Pid_lineno: %u", hash_entry->lineno);

    u32 hash = hash_func(data.clazz, data.method, hash_entry->lineno);

    old_entry = counts.lookup(hash_entry);
    if (old_entry) {
        hash_entry->hash = old_entry->prev_hash.hash;
        hash_entry->lineno = old_entry->prev_hash.lineno;
        
        entry.update(&data.pid, hash_entry);
    }
    else {
        entry.insert(&data.pid, hash_entry);
    }

#ifdef DEBUG
    bpf_trace_printk("Return:");
    bpf_trace_printk("Method: %s", data.method);
    bpf_trace_printk("Hash: %u", hash);
    bpf_trace_printk("Lineno: %d", data.lineno);
    bpf_trace_printk("Prev hash: %u", hash_entry->hash);
    bpf_trace_printk("Prev lineno: %u", hash_entry->lineno);
    bpf_trace_printk("");
#endif // DEBUG

    return 0;
}
'''.replace('DEFINE_DEBUG', '#define DEBUG' if args.debug else "")

#print(f"Trying to probe pid: {args.pid}")
#lib_path = f"/proc/{args.pid}/root/usr/bin/python3.9"
#usdt = USDT(path=lib_path, pid=args.pid)
usdt = USDT(pid=args.pid)
usdt.enable_probe_or_bail("python:function__entry", 'trace_entry')
usdt.enable_probe_or_bail("python:function__return", 'trace_return')

bpf = BPF(text=program, usdt_contexts=[usdt] if usdt else [])

with open('arvos_vfs_py.json') as fp:
    vulnerability_database = json.load(fp)

if not args.requirements_file:
    print(f"{bcolors.WARNING}requirements file not provided. Version filtering cannot be performed. This will increase the number of false positives.\n{bcolors.ENDC}")
else:
    #req_file = RequirementsFile.from_file(args['requirements-file'])
    #vulnerability_database = filter_vulnerabilities(vulnerability_database, req_file)
    pass

print(f"{bcolors.OKGREEN}Tracing calls in process {args.pid} (language: python)... Ctrl-C to quit.{bcolors.ENDC}")
interrupted = False

if args.debug:
    while True:
        try:
            bpf.trace_print()
            
        except KeyboardInterrupt:
            print(f"{bcolors.OKGREEN}\nStopping the tracer .{bcolors.ENDC}")
            for k,v in bpf['counts'].items():
                clazz = v.clazz.decode('utf-8', 'replace')
                method = v.method.decode('utf-8', 'replace')
                print(f"{clazz}:{method}:{v.lineno}")
                for trace in get_stack_trace(k):
                   print(f"\t\tat {trace}")  
                print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}{'-'*150}{bcolors.ENDC}")
            sys.exit(0)

seen = []
vuln_count = 0
while True:
    pattern = 'python\d\.\d{1,2}\/(site-packages\/|dist-packages\/|)(.+).py'
    for vulnerability in vulnerability_database:
        for symbol in vulnerability['symbols']:
            for k,v in bpf['counts'].items():
                clazz = v.clazz.decode('utf-8', 'replace')
                method = v.method.decode('utf-8', 'replace')

                result = re.search(pattern, clazz)
                
                if result:
                    traced_class = result.group(2).replace('/','.')

                if result and symbol['class_name'].startswith(traced_class) and method == symbol['method_name']:
                    if (traced_class, method, k.hash, k.lineno) not in seen:
                        seen.append((traced_class, method, k.hash, k.lineno))

    if interrupted:
        print(f"{bcolors.OKGREEN}\nStopping the tracer .{bcolors.ENDC}")
        break

print("Generating Report ...")
if args.save_report == 'csv':
    report_csv = open('arvos-report.csv', 'w')
    fieldnames = ['ID', 'Vulnerability', 'Vulnerability Detail', 'Invoked Class', 'Invoked Method',
                  'Github Repository', 'Stacktrace']
    writer = csv.DictWriter(report_csv, fieldnames=fieldnames)
    writer.writeheader()


checkbox = False
for (traced_class, traced_method, traced_hash, traced_lineno) in seen:
    for vulnerability in vulnerability_database:
        for symbol in vulnerability['symbols']:
            if symbol['class_name'].startswith(traced_class) and traced_method == symbol['method_name']:
                if symbol['class_name'] not in {'django.http.multipartparser.MultiPartParser', 'django.forms.widgets.CheckboxInput'} \
                    or symbol['method_name'] == 'sanitize_file_name':
                    continue
                
                if symbol['class_name'] == 'django.forms.widgets.CheckboxInput' and checkbox:
                    continue 

                if symbol['class_name'] == 'django.forms.widgets.CheckboxInput':
                    checkbox = True

                vuln_count += 1                
                trace_source = ""

                print(f"\n{bcolors.BOLD}The following vulnerable symbol has been invoked : \n{bcolors.ENDC}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability:{bcolors.ENDC} {vulnerability['vulnerability']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability Detail:{bcolors.ENDC} https://nvd.nist.gov/vuln/detail/{vulnerability['vulnerability']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Repository:{bcolors.ENDC} https://github.com/{vulnerability['repository']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Class:{bcolors.ENDC} {symbol['class_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Method:{bcolors.ENDC} {symbol['method_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Stacktrace:{bcolors.ENDC}")
                for trace in get_stack_trace(traced_hash, traced_lineno):
                    result = re.search(pattern, trace)
                    if result:
                        stack_trace_symbol = result.group(2).replace('/','.')
                        print(f"\t\tat {trace}")  
                    else:
                        trace_source = trace
                        print(f"\t\tat {bcolors.WARNING}{bcolors.BOLD}{trace}{bcolors.ENDC}")
                print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}{'-'*150}{bcolors.ENDC}")

                if args.save_report == 'csv':
                    writer.writerow({
                        'ID': vuln_count,
                        'Vulnerability': vulnerability['vulnerability'],
                        'Vulnerability Detail': "https://nvd.nist.gov/vuln/detail/" + vulnerability['vulnerability'],
                        'Invoked Class': symbol['class_name'],
                        'Invoked Method': symbol['method_name'],
                        'Github Repository': 'https://github.com/' + symbol['repository'],
                        'Stacktrace': trace_source
                    })

if args.save_report == 'csv':
    report_csv.close()


if vuln_count != 0:
    print(f"{bcolors.FAIL}[FAIL]{bcolors.ENDC} We found {vuln_count} vulnerable symbols being used in your application.")
    sys.exit(1)
else:
    print(f"\t{bcolors.OKGREEN}[SUCCESS]{bcolors.ENDC} No vulnerable symbol has been found in your application.")