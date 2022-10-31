#!/usr/bin/python3
import subprocess
import argparse
import signal
import time
import requests
import json
import csv
import sys
import ast
import re
import os
import ctypes as ct

from bcc import BPF, USDT
from packaging.specifiers import SpecifierSet
from pip_requirements_parser import RequirementsFile

DOCKER_RUNNING = True if os.environ.get('APP_ENV') == 'docker' else False
MAX_HTTP_RETRIES = 2
STACK_COUNT = 256
STACK_SIZE  = 256
PERIOD = 10

OPERATORS = {
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<="
}

def signal_handler(signal, frame):
    global interrupted
    interrupted = True


vulnerability_scores = {}
def get_vulnerability_score(cve):
    global vulnerability_scores

    if not cve.startswith('CVE'):
        return "None"

    if cve in vulnerability_scores:
        return vulnerability_scores[cve]

    for _ in range(MAX_HTTP_RETRIES):
        if (cve.startswith('CVE')):
            res = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}?apiKey=5cb1bbbd-9b0f-487e-a7db-06f642f91a5a")
            if res.status_code == 200:
                vulnerability_scores[cve] = res.json()['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                return vulnerability_scores[cve]
        elif (cve.startswith('GHSA')):
            github_api_token = os.environ.get("GITHUB_API_TOKEN")
            query = "query { securityAdvisory(ghsaId:" + f'"{cve}"' + ") { severity }}"
            headers = {"Authorization": f"Bearer {github_api_token}"}
            res = requests.post("https://api.github.com/graphql", json={"query": query}, headers=headers)
            if res.ok:
                severity = res.json()['data']['securityAdvisory']['severity']
                severity = 'MEDIUM' if severity == 'MODERATE' else severity
                vulnerability_scores[cve] = severity
                return severity

    return "None"

def get_version_range(vuln):
    if 'package_version_range' not in vuln:
        return ''

    version_range = list(filter(lambda e: e[1] != '~', vuln['package_version_range'].items()))
    if not version_range:
        version_range = list(filter(lambda e: e[1] != '~', vuln['cpe_version_range'].items()))

    return ",".join(map(lambda e: OPERATORS[e[0]] + e[1], version_range))

def filter_vulnerabilities(vulnerability_database, req_file):
    relevant_vulnerabilites = []
    unpinned_requirements = set()

    for vuln in vulnerability_database:
        specifier_set = SpecifierSet(get_version_range(vuln))
        
        for req in req_file.requirements:
            # No package name in current db
            if req.name.lower() == vuln['repository'].split('/')[-1]:
                if req.is_pinned:
                    for version in req.specifier:
                        if version.version in specifier_set:
                            relevant_vulnerabilites.append(vuln)
                            break
                else:
                    unpinned_requirements.add(req.name)
                    relevant_vulnerabilites.append(vuln)
                
                break
        else:
            # Keep vulnerabilites without match in req file?
            relevant_vulnerabilites.append(vuln)

        
    for req_name in unpinned_requirements:
        print(f"{bcolors.WARNING}Version of library {req_name} is not pinned. Can't filter relevant database entries.\n{bcolors.ENDC}")
    
    return relevant_vulnerabilites

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

class NodeVisitor(ast.NodeVisitor):
    def __init__(self, class_name, function_name, lineno):
        self.class_name = class_name
        self.function_name = function_name
        self.lineno = lineno

        self.match_found = False

    def visit_ClassDef(self, node):
        if node.name == self.class_name:
            self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name == self.function_name and node.lineno == self.lineno:
            self.match_found = True

def match_exact_function(filename, symbol_class, function_name, lineno):
    if DOCKER_RUNNING:
        filename = f'/proc/{args.pid}/root' + filename
    
    with open(filename) as fp:
        tree = ast.parse(fp.read())

    visitor = NodeVisitor(symbol_class.split('.')[-1], function_name, lineno)
    visitor.visit(tree)
    
    return visitor.match_found

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
parser.add_argument("--detect", type=str, help="automatically fetch pid")
parser.add_argument("--debug", action="store_true", help="debug mode")
parser.add_argument('--save-report', default=False, const=False, nargs='?', choices=['csv'], help='Save report as csv')
parser.add_argument("--database-file", type=str, default='arvos_vfs_py.json', help="Specify database file")
parser.add_argument("--requirements-file", type=str, help="Provide library version through requirements.txt")
parser.add_argument("--trace-period", help="Tracing period in minutes (default: Infinite)", type=int, default=sys.maxsize, required=False)

args = parser.parse_args()

if not args.debug:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

if not args.pid and not args.detect:
    print("Must either provide PID or use --detect")
    sys.exit(1)

if not args.pid and args.detect:
    for i in range(10):
        "ps ax | grep -v -e 'python_calls.py' -e 'grep' | grep '/python3 manage.py runserver'"
        p1 = subprocess.Popen(['ps', 'ax'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep', '-v', '-e', 'python_calls.py', '-e', 'grep'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.Popen(['grep', args.detect], stdin=p2.stdout, stdout=subprocess.PIPE)
        pid = p3.communicate()[0].decode().split()
        if pid:
            args.pid = int(pid[0])
            break

        time.sleep(5)
    else:
        print(f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} Could not automatically detect pid")
        sys.exit(1)


stacks_str = ""
for i in range(STACK_COUNT):
    stacks_str += f"BPF_ARRAY(array{i}, struct hash_t, {STACK_SIZE});\n"

program = '''
#define MAX_CLASS_LENGTH  150
#define MAX_METHOD_LENGTH 100
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
    

with open(args.database_file) as fp:
    vulnerability_database = json.load(fp)

if not args.requirements_file:
    print(f"{bcolors.WARNING}requirements file not provided. Version filtering cannot be performed. This will increase the number of false positives.\n{bcolors.ENDC}")
else:
    req_file = RequirementsFile.from_file(args.requirements_file)
    vulnerability_database = filter_vulnerabilities(vulnerability_database, req_file)

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
pattern = 'python\d\.\d{1,2}\/(site-packages\/|dist-packages\/|)(.+).py'
vuln_count = 0
TRACE_TIME = args.trace_period * 60
start_time = time.time()
while TRACE_TIME > time.time() - start_time:
    time.sleep(PERIOD)

    for vulnerability in vulnerability_database:
        for symbol in vulnerability['symbols']:
            for k,v in bpf['counts'].items():
                clazz = v.clazz.decode('utf-8', 'replace')
                method = v.method.decode('utf-8', 'replace')

                result = re.search(pattern, clazz)
                
                if result:
                    traced_class = result.group(2).replace('/','.')

                if result and symbol['class_name'].startswith(traced_class) and \
                    method == symbol['method_name'] and \
                    match_exact_function(clazz, symbol['class_name'], method, v.lineno):
                    stack_trace = get_formated_stack_trace(v.stack_trace)
                    if (traced_class, method, stack_trace) not in seen:
                        seen.append((traced_class, method, stack_trace))

    if interrupted:
        print(f"{bcolors.OKGREEN}\nStopping the tracer.{bcolors.ENDC}")
        break

print("Generating Report ...")
if args.save_report == 'csv':
    report_csv = open('arvos-report.csv', 'w')
    fieldnames = ['ID', 'Vulnerability', 'Vulnerability Detail', 'Score', 'Invoked Class', 'Invoked Method',
                  'Github Repository', 'Stacktrace']
    writer = csv.DictWriter(report_csv, fieldnames=fieldnames)
    writer.writeheader()

scores = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0 }
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

                score = get_vulnerability_score(vulnerability['vulnerability'])
                if score in scores:
                    scores[score] += 1

                print(f"\n{bcolors.BOLD}The following vulnerable symbol has been invoked : \n{bcolors.ENDC}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability:{bcolors.ENDC} {vulnerability['vulnerability']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Vulnerability Detail:{bcolors.ENDC} {vulnerability_url}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Score:{bcolors.ENDC} {score}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Repository:{bcolors.ENDC} https://github.com/{vulnerability['repository']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Class:{bcolors.ENDC} {symbol['class_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Invoked Method:{bcolors.ENDC} {symbol['method_name']}")
                print(f"\t{bcolors.FAIL}{bcolors.BOLD}Version Range:{bcolors.ENDC} {get_version_range(vulnerability)}")
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
                        'Score': score,
                        'Invoked Class': symbol['class_name'],
                        'Invoked Method': symbol['method_name'],
                        'Github Repository': 'https://github.com/' + vulnerability['repository'],
                        'Stacktrace': trace_source
                    })


if args.save_report == 'csv':
    report_csv.close()

if vuln_count != 0:
    print(f"{bcolors.FAIL}[FAIL]{bcolors.ENDC} We found {vuln_count} vulnerable symbols being used in your application.")
    print(f"{bcolors.FAIL}[FAIL]{bcolors.ENDC} Severities: CRITICAL: {scores['CRITICAL']}, HIGH: {scores['HIGH']}, MEDIUM: {scores['MEDIUM']}, LOW: {scores['LOW']}")

    sys.exit(1)
else:
    print(f"\t{bcolors.OKGREEN}[SUCCESS]{bcolors.ENDC} No vulnerable symbol has been found in your application.")
    print(f"\t{bcolors.OKGREEN}[SUCCESS]{bcolors.ENDC} Severities: CRITICAL: {scores['CRITICAL']}, HIGH: {scores['HIGH']}, MEDIUM: {scores['MEDIUM']}, LOW: {scores['LOW']}")