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


STACK_COUNT = 256
STACK_SIZE  = 256
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

def find_repeating_sequence_end(seq, index, length):
    for i in range(index, len(seq), length):
        if seq[0+i:length+i] != seq[length+i:2*length+i]:
            return i
            
    return 0

class HashStruct(ct.Structure):
    _fields_ = [('hash', ct.c_uint),
                ('lineno', ct.c_int)]

def create_hash_struct(hash_num, lineno):
    hash = HashStruct()
    hash.hash = hash_num
    hash.lineno = lineno
    return hash

def get_formated_stack_trace(stack_trace):
    formated_stack_trace = []
    
    for trace in reversed(stack_trace):
        if (trace.hash == 0):
            continue

        element = bpf['counts'].get(trace)
        if not element:
            break
        
        clazz = element.clazz.decode('utf-8', 'replace')
        method = element.method.decode('utf-8', 'replace')

        trace_string = f"{clazz}.{method}:{element.lineno}"
        formated_stack_trace.append(trace_string)

    index, length = find_repeating_sequence(formated_stack_trace)
    if length > 0:
        end = find_repeating_sequence_end(formated_stack_trace, index, length)
        del formated_stack_trace[index:end]

    return formated_stack_trace

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
parser.add_argument("--trace-period", help="Tracing period in minutes (default: Infinite)", type=int, default=sys.maxsize, required=False)

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

stacks_str = ""
for i in range(STACK_COUNT):
    stacks_str += f"BPF_ARRAY(array{i}, struct hash_t, {STACK_SIZE});\n"

program = '''
#define MAX_CLASS_LENGTH  130
#define MAX_METHOD_LENGTH 50
DEFINE_STACK_SIZE

DEFINE_DEBUG

struct hash_t {
    u32 hash;
    int lineno;
};

struct method_t {    
    u64 pid;                    
    struct hash_t stack_trace[STACK_SIZE];
    char clazz[MAX_CLASS_LENGTH];
    char method[MAX_METHOD_LENGTH];
    int lineno;
};

struct pid_stack_index {
    u64 index;
    int stack_size;
};

BPF_PERCPU_ARRAY(method_t_struct, struct method_t, 1);
BPF_HASH(counts, struct hash_t, struct method_t);

BPF_HASH(current_stack_index);
BPF_HASH(pid_id, u64, struct pid_stack_index);
DEFINE_STACKS

BPF_HASH_OF_MAPS(stack_map, u64, "array0", 256);

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

static int push_stack(void *stack, struct pid_stack_index *index, struct hash_t *entry) {
    if (index->stack_size >= STACK_SIZE - 1) 
        return 1;

    index->stack_size++;

    return bpf_map_update_elem(stack, &index->stack_size, entry, BPF_ANY);
}

static void *pop_stack(void *stack, struct pid_stack_index *index) {
    if (index->stack_size < 0) {
        return NULL;
    }
    
    struct hash_t *entry = bpf_map_lookup_elem(stack, &index->stack_size);
    
    // Don't actually delete elem, just decrease index, next push will overwrite anyways.
    index->stack_size--;

    return entry;
}

static void build_stack(void *stack, struct pid_stack_index *index, struct method_t *entry) {
    for (u64 i = 0; i < STACK_SIZE; i++) {
        u64 map_i = i;
        
        struct hash_t *stack_entry = bpf_map_lookup_elem(stack, &map_i);
        if (!stack_entry || i > index->stack_size) {
            entry->stack_trace[i].hash = 0;
            continue;
        }
        
        bpf_probe_read(&entry->stack_trace[i], sizeof(struct hash_t), stack_entry);
    }
}


int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, zero = 0;
    int lineno = 0, int_zero = 0;
    struct hash_t hash_entry, hash_zero = {0};

    struct method_t *data = method_t_struct.lookup(&int_zero);
    if (!data)
        return 0;

    data->pid = bpf_get_current_pid_tgid();

    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);
    bpf_usdt_readarg(3, ctx, &data->lineno);

    bpf_probe_read_user(&data->clazz, sizeof(data->clazz), (void *)clazz);
    bpf_probe_read_user(&data->method, sizeof(data->method), (void *)method);

    u32 hash = hash_func(data->clazz, data->method, data->lineno);
    
    hash_entry.hash = hash;
    hash_entry.lineno = data->lineno;
    
    // Allocate or fetch global stack index
    u64 *current_stack_idx = current_stack_index.lookup(&zero);
    u64 new_stack_idx = 0;

    if (!current_stack_idx) {
        current_stack_index.insert(&zero, &zero);
    }
    else {
        new_stack_idx = *current_stack_idx;
    }

    /* Allocate or fetch inner pid stack */
    struct pid_stack_index *pid_stack_index = pid_id.lookup(&data->pid);
    struct pid_stack_index pid_stack_idx = { .index = 0, .stack_size = -1};
    
    if (!pid_stack_index) {
        // Grab a new stack
        pid_stack_idx.index = new_stack_idx;
        pid_id.insert(&data->pid, &pid_stack_idx);
        if (new_stack_idx < 256) {
            new_stack_idx++;
            current_stack_index.update(&zero, &new_stack_idx);
        }
    }
    else {
        pid_stack_idx = *pid_stack_index;
    }
    
    void *inner_stack = stack_map.lookup(&pid_stack_idx.index);
    if (!inner_stack)
        return 0;


    /* Inner stack operations */

    if (push_stack(inner_stack, &pid_stack_idx, &hash_entry) != 0) {
        bpf_trace_printk("push error");
    }

    build_stack(inner_stack, &pid_stack_idx, data);

    pid_id.update(&data->pid, &pid_stack_idx);
    counts.update(&hash_entry, data);

#ifdef DEBUG
    bpf_trace_printk("Entry: Method: %s", data->method);
    
    bpf_trace_printk("Stack size: %d", pid_stack_idx.stack_size);
    bpf_trace_printk("");
#endif

    return 0;
}

int trace_return(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, zero = 0, pid;
    int lineno = 0;

    pid = bpf_get_current_pid_tgid();

    u64 *current_stack_idx = current_stack_index.lookup(&zero);
    u64 new_stack_idx = 0;

    if (!current_stack_idx) {
        current_stack_index.insert(&zero, &zero);
    }
    else {
        new_stack_idx = *current_stack_idx;
    }

    /* Allocate or fetch inner pid stack */
    struct pid_stack_index *pid_stack_index = pid_id.lookup(&pid);
    struct pid_stack_index pid_stack_idx = { .index = 0, .stack_size = -1};
    
    if (!pid_stack_index) {
        // Grab a new stack
        pid_stack_idx.index = new_stack_idx;
        pid_id.insert(&pid, &pid_stack_idx);
        if (new_stack_idx < 256) {
            new_stack_idx++;
            current_stack_index.update(&zero, &new_stack_idx);
        }
    }
    else {
        pid_stack_idx = *pid_stack_index;
    }
    
    void *inner_stack = stack_map.lookup(&pid_stack_idx.index);
    if (!inner_stack)
        return 0;

    pop_stack(inner_stack, &pid_stack_idx);
    
    pid_id.update(&pid, &pid_stack_idx);

#ifdef DEBUG
    bpf_trace_printk("Return");
    bpf_trace_printk("Stack size: %d", pid_stack_idx.stack_size);
    bpf_trace_printk("");
#endif 

    return 0;
}
'''.replace('DEFINE_DEBUG', '#define DEBUG' if args.debug else "") \
    .replace('DEFINE_STACKS', stacks_str) \
    .replace('DEFINE_STACK_SIZE', f"#define STACK_SIZE {STACK_SIZE}")

usdt = USDT(pid=args.pid)
usdt.enable_probe_or_bail("python:function__entry", 'trace_entry')
usdt.enable_probe_or_bail("python:function__return", 'trace_return')

bpf = BPF(text=program, usdt_contexts=[usdt] if usdt else [])

stack_map = bpf['stack_map']
for i in range(STACK_COUNT):
    stack_map[ct.c_int(i)] = ct.c_int(bpf[f"array{i}"].map_fd)
    

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
                for trace in get_formated_stack_trace(v.stack_trace):
                   print(f"\t\tat {trace}")  
                print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}{'-'*150}{bcolors.ENDC}")
            sys.exit(0)

seen = []
vuln_count = 0
TRACE_TIME = args.trace_period * (60 / PERIOD)
while TRACE_TIME > 0:
    time.sleep(PERIOD)
    TRACE_TIME -= 1

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
                    stack_trace = get_formated_stack_trace(v.stack_trace)
                    if (traced_class, method, stack_trace) not in seen:
                        seen.append((traced_class, method, stack_trace))

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


for (traced_class, traced_method, stack_trace) in seen:
    for vulnerability in vulnerability_database:
        for symbol in vulnerability['symbols']:
            if symbol['class_name'].startswith(traced_class) and traced_method == symbol['method_name']:
                vuln_count += 1                
                trace_source = ""

                vulnerability_url = ""
                if vulnerability['vulnerability'].startswith('CVE'):
                    vulnerability_url = f"https://nvd.nist.gov/vuln/detail/{vulnerability['vulnerability']}"
                elif vulnerability['vulnerability'].startswith('GHSA'):
                    vulnerability_url = f"https://github.com/advisories/{vulnerability['vulnerability']}"

                print(f"\n{bcolors.BOLD}The following vulnerable symbol has been invoked : \n{bcolors.ENDC}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability:{bcolors.ENDC} {vulnerability['vulnerability']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability Detail:{bcolors.ENDC} {vulnerability_url}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Repository:{bcolors.ENDC} https://github.com/{vulnerability['repository']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Class:{bcolors.ENDC} {symbol['class_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Method:{bcolors.ENDC} {symbol['method_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Stacktrace:{bcolors.ENDC}")
                for trace_string in stack_trace:
                    result = re.search(pattern, trace_string)
                    if result or trace_string.startswith("<frozen"):
                        print(f"\t\tat {trace_string}")  
                    else:
                        trace_source = trace_string
                        print(f"\t\tat {bcolors.WARNING}{bcolors.BOLD}{trace_string}{bcolors.ENDC}")

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