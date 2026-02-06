# /etc/bash.bashrc
#
# https://wiki.archlinux.org/index.php/Color_Bash_Prompt
#
# This file is sourced by all *interactive* bash shells on startup,
# including some apparently interactive shells such as scp and rcp
# that can't tolerate any output. So make sure this doesn't display
# anything or bad things will happen !

# Test for an interactive shell. There is no need to set anything
# past this point for scp and rcp, and it's important to refrain from
# outputting anything in those cases.
# If not running interactively, don't do anything!
[[ $- != *i* ]] && return

# Bash won't get SIGWINCH if another process is in the foreground.
# Enable checkwinsize so that bash will check the terminal size when
# it regains control.
# http://cnswww.cns.cwru.edu/~chet/bash/FAQ (E11)
shopt -s checkwinsize

# Enable history appending instead of overwriting.
shopt -s histappend

# Set terminal window title based on terminal type
# Updates title bar to show user@hostname:path for supported terminals
case ${TERM} in
	xterm*|rxvt*|Eterm|aterm|kterm|gnome*)
		PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND; }'printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"'
		;;
	screen)
		PROMPT_COMMAND=${PROMPT_COMMAND:+$PROMPT_COMMAND; }'printf "\033_%s@%s:%s\033\\" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"'
		;;
esac

# fortune is a simple program that displays a pseudorandom message
# from a database of quotations at logon and/or logout.
# If you wish to use it, please install "fortune-mod" from the
# official repositories, then uncomment the following line:
# [[ "$PS1" ]] && /usr/bin/fortune

# Set colorful PS1 only on colorful terminals.
# dircolors --print-database uses its own built-in database
# instead of using /etc/DIR_COLORS. Try to use the external file
# first to take advantage of user additions. Use internal bash
# globbing instead of external grep binary.

# Sanitize TERM variable by replacing non-alphanumeric characters with ?
safe_term=${TERM//[^[:alnum:]]/?}
match_lhs=""

# Load color configuration from user and system dir_colors files
[[ -f ~/.dir_colors ]] && match_lhs="${match_lhs}$(<~/.dir_colors)"
[[ -f /etc/DIR_COLORS ]] && match_lhs="${match_lhs}$(</etc/DIR_COLORS)"
[[ -z ${match_lhs} ]] \
	&& type -P dircolors >/dev/null \
	&& match_lhs=$(dircolors --print-database)

# Check if terminal supports colors and configure accordingly
if [[ $'\n'${match_lhs} == *$'\n'"TERM "${safe_term}* ]] ; then
	
	# we have colors :-)
	# Enable colors for ls, etc. Prefer ~/.dir_colors
	if type -P dircolors >/dev/null ; then
		if [[ -f ~/.dir_colors ]] ; then
			eval $(dircolors -b ~/.dir_colors)
		elif [[ -f /etc/DIR_COLORS ]] ; then
			eval $(dircolors -b /etc/DIR_COLORS)
		fi
	fi
	
	# Set colorful prompt: red for root, green for normal users
	# Shows sad face :( in red when last command failed (exit code != 0)
	PS1="$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]\u@\h'; else echo '\[\033[01;32m\]\u@\h'; fi)\[\033[01;34m\] \w \$([[ \$? != 0 ]] && echo \"\[\033[01;31m\]:(\[\033[01;34m\] \")\\$\[\033[00m\] "
	# Use this other PS1 string if you want \W for root and \w for all other users:
	# PS1="$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]\h\[\033[01;34m\] \W'; else echo '\[\033[01;32m\]\u@\h\[\033[01;34m\] \w'; fi) \$([[ \$? != 0 ]] && echo \"\[\033[01;31m\]:(\[\033[01;34m\] \")\\$\[\033[00m\] "
	
	# Enable color output for common commands
	alias ls="ls --color=auto"
	alias dir="dir --color=auto"
	alias grep="grep --color=auto"
	alias dmesg='dmesg --color'
	# Uncomment the "Color" line in /etc/pacman.conf instead of uncommenting the following line...!
	# alias pacman="pacman --color=auto"
else
	# Terminal doesn't support colors - use plain prompt
	# show root@ when we do not have colors
	PS1="\u@\h \w \$([[ \$? != 0 ]] && echo \":( \")\$ "
	# Use this other PS1 string if you want \W for root and \w for all other users:
	# PS1="\u@\h $(if [[ ${EUID} == 0 ]]; then echo '\W'; else echo '\w'; fi) \$([[ \$? != 0 ]] && echo \":( \")\$ "
fi

# Set secondary prompts for multi-line commands and select menus
PS2="> "
PS3="> "
PS4="+ "

# Try to keep environment pollution down, EPA loves us.
unset safe_term match_lhs

# Try to enable the auto-completion (type: "pacman -S bash-completion" to install it).
[ -r /usr/share/bash-completion/bash_completion ] && . /usr/share/bash-completion/bash_completion

# Try to enable the "Command not found" hook ("pacman -S pkgfile" to install it).
# See also: https://wiki.archlinux.org/index.php/Bash#The_.22command_not_found.22_hook
[ -r /usr/share/doc/pkgfile/command-not-found.bash ] && . /usr/share/doc/pkgfile/command-not-found.bash

# ============================================================================
# GIT ALIASES
# ============================================================================

# Show git log with detailed statistics and patches for each commit
alias githist='git log --stat -p'

# Display git history as a decorated tree graph with one line per commit
alias git-tree='git log --oneline --decorate --all --graph'

# ============================================================================
# AWS PROFILE ALIASES
# ============================================================================

# Authenticate and set AWS profile for development environment
alias dev='gimme-aws-creds --profile=dev; export AWS_PROFILE=11111111111111-/Foo'

# Authenticate and set AWS profile for devops environment
alias devops='gimme-aws-creds --profile=devops; export AWS_PROFILE=222222222222-/Bar'

# Configure environment for sandbox Kubernetes cluster and update kubeconfig
alias setSandbox='export AWS_REGION=us-west-2 export AWS_PROFILE=222222222222-/Bar NAMESPACE=sandbox01 KUBECONFIG=$HOME/.kube/config.sandbox && aws eks --region ${AWS_REGION} update-kubeconfig --name name-of-eks'

# ============================================================================
# KUBERNETES ALIASES
# ============================================================================

# Display the current Kubernetes context name (cluster name only)
# Returns "no-k8s-cluster" if no context is set
alias currentk8s="kubectl config current-context 2>/dev/null | awk -F$'[ /]' '{print \$NF}' | grep . || echo no-k8s-cluster"

# ============================================================================
# TERRAFORM ALIASES
# ============================================================================

# Show the current Terraform workspace name
# Returns "none" if not in a Terraform directory
alias currentTFworkspace="[[ -f .terraform/environment ]] && cat .terraform/environment || echo "none""

# Display the installed Terraform version
# Returns "none" if Terraform is not installed
alias currentTFversion="terraform -version | awk '/^Terraform/ {print \$2}' || echo "none""

# ============================================================================
# AWS SECRETS MANAGER ALIAS
# ============================================================================

# List all AWS Secrets Manager secrets and display their values
# Iterates through all secrets and pretty-prints their JSON content
alias secret='aws secretsmanager list-secrets | jq -r ".SecretList[].Name" | while read i; do echo $i; aws secretsmanager get-secret-value --secret-id $i | jq -r ".SecretString" | jq -r . ; done'

# ============================================================================
# UTILITY ALIASES
# ============================================================================

# Side-by-side diff with cleaner output (removes diff markers and extra tabs)
# Usage: scat file1 file2
alias scat="sdiff \$1 \$2 | sed -r 's/[<>|]//;s/(\t){3}//'"

# ============================================================================
# MACOS SCREEN MANAGEMENT ALIASES (for Macs with display issues)
# ============================================================================

# Disable internal screen on macOS (useful for troubleshooting display issues)
alias disable_screen='sudo nvram boot-args="iog=0x0"'

# Re-enable internal screen on macOS
alias enable_screen='sudo nvram -d boot-args'

# ============================================================================
# MACOS DNS CACHE ALIAS
# ============================================================================

# Flush DNS cache on macOS
alias flushdns='sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder'

# ============================================================================
# GIT HELPER FUNCTION
# ============================================================================

# Extract and format the current git branch name
# Returns: [branch-name] or empty string if not in a git repo
# Used in PS1 prompt to display current branch
function parse_git_branch() {
     git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/[\1]/'
}

# ============================================================================
# AWS ACCOUNT IDENTIFIER
# ============================================================================

# Map AWS_PROFILE to human-readable account names for prompt display
if [[ $AWS_PROFILE == 2222222222222-/devops ]]; then
    account_id=Development
elif [[ $AWS_PROFILE == 1111111111111-/devops ]]; then
    account_id=DevOps
else
    account_id=none
fi

# ============================================================================
# CERTIFICATE EXPIRATION FUNCTIONS
# ============================================================================

# Calculate days until SSL certificate expiration
# Args:
#   $1: Certificate name/label for display
# Requires: EXPIRATION variable set with certificate expiry date
# Uses GNU date (gdate) for UTC date calculations
function calculate_date() {
     d1=$(gdate --utc --date="$(echo $EXPIRATION)" +%s)
     d2=$(gdate --utc +%s)
     EXPIRATION_TIME=$(echo $(( (d1 - d2) / 86400 )) days)
     echo -n "$1 SSL certificate "
     if [[ ${EXPIRATION_TIME} != "0 days" ]]; then
         echo -n "$i "
         echo ": ${EXPIRATION_TIME}"
         echo
     fi
}

# Get Linkerd service mesh identity certificate expiration date
# Extracts certificate from linkerd-identity-issuer secret and parses expiry
# Sets EXPIRATION variable and calls calculate_date()
function get_linkerd_cert_expiration() {
     EXPIRATION=$(kubectl -n linkerd get secret linkerd-identity-issuer -o jsonpath="{.data['crt\.pem']}" | base64 -d | openssl x509 -text | awk -F' :' '/Not After :/{print $2}')
     calculate_date "Linkerd"
}

# Check Linkerd certificate expiration in sandbox environment
# Switches to sandbox context, displays namespace, and shows cert expiration
# Suppresses stderr output for cleaner display
function get_all_linkerd_cert_expiration() {
     (setSandbox && echo -n "$NAMESPACE " && get_linkerd_cert_expiration && echo) 2>/dev/null
}

# ============================================================================
# AWS EBS ENCRYPTION FUNCTIONS
# ============================================================================

# Check EBS encryption status across all AWS regions
# Displays: region name, encryption-by-default status, and default KMS key ID
# Useful for security compliance auditing
function aws_ebs_encryption_check () {
    for region in $(aws ec2 describe-regions --region us-east-1 --query "Regions[*].[RegionName]" --output text); do
        default=$(aws ec2 get-ebs-encryption-by-default --region $region --query "{Encryption_By_Default:EbsEncryptionByDefault}" --output text)
        kms_key=$(aws ec2 get-ebs-default-kms-key-id --region $region | jq '.KmsKeyId')
        echo "$region  --- $default  --- $kms_key"
    done
}

# Enable EBS encryption by default across all AWS regions
# Displays: region name, new encryption status, and default KMS key ID
# WARNING: This makes permanent changes to AWS account settings
function aws_enable_ebs_encryption () {
    for region in $(aws ec2 describe-regions --region us-east-1 --query "Regions[*].[RegionName]" --output text); do
        default=$(aws ec2 enable-ebs-encryption-by-default --region $region --query "{Encryption_By_Default:EbsEncryptionByDefault}" --output text)
        kms_key=$(aws ec2 get-ebs-default-kms-key-id --region $region | jq '.KmsKeyId')
        echo "$region  --- $default  --- $kms_key"
    done
}

# ============================================================================
# PYTHON API DOCUMENTATION FUNCTION
# ============================================================================

# Display interactive Python module API documentation with AI-generated examples
# Args:
#   $1: Python module name (required)
#   $2: Search term to filter functions (optional)
# 
# Features:
#   - Lists all public functions/classes in a module
#   - Shows function signatures and docstrings
#   - Generates executable code examples using Claude AI (requires ANTHROPIC_API_KEY)
#   - Executes examples and displays output
#   - Auto-fixes failing examples
#   - Renders output with glow markdown viewer
#
# Requirements:
#   - glow (markdown renderer): brew install glow
#   - ANTHROPIC_API_KEY environment variable (for examples)
#
# Usage:
#   pyapi flask              # List all Flask functions
#   pyapi flask jsonify      # Show jsonify function with example
pyapi() {
    if [ -z "$1" ]; then
        echo "Usage: pyapi <module_name> [search_term]"
        echo ""
        echo "Environment Variables:"
        echo "  Provider Selection (checks in order):"
        echo "    ANTHROPIC_API_KEY  - Use Anthropic Claude API"
        echo "    OPENAI_API_KEY     - Use OpenAI/LiteLLM API"
        echo ""
        echo "  Anthropic Configuration:"
        echo "    ANTHROPIC_API_KEY  - API key for Anthropic"
        echo "    ANTHROPIC_MODEL    - Model (default: claude-sonnet-4-20250514)"
        echo ""
        echo "  OpenAI/LiteLLM Configuration:"
        echo "    OPENAI_API_KEY     - API key for OpenAI/LiteLLM"
        echo "    OPENAI_BASE_URL    - API base URL (default: https://api.openai.com)"
        echo "    OPENAI_MODEL       - Model (default: gpt-4o)"
        return 1
    fi
    
    if ! command -v glow &> /dev/null; then
        echo "Error: 'glow' is required but not installed."
        return 1
    fi
    
    if ! command -v uv &> /dev/null; then
        echo "Error: 'uv' is required but not installed."
        echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
        return 1
    fi
    
    local tmpfile=$(mktemp)
    
    MODULE_NAME="$1" \
    SEARCH_TERM="${2:-}" \
    ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
    ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-sonnet-4-20250514}" \
    OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com}" \
    OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o}" \
    python3 << 'PYEOF' > "$tmpfile" 2>&1
import sys, importlib, inspect, os, json, subprocess, re, tempfile, shutil
import pkgutil

module_name = os.environ.get("MODULE_NAME", "")
search_term = os.environ.get("SEARCH_TERM", "").lower()

# Provider detection - Anthropic takes priority if set
anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
anthropic_model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
openai_api_key = os.environ.get("OPENAI_API_KEY", "")
openai_base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o")

# Determine active provider
if anthropic_api_key:
    provider = "anthropic"
    api_key = anthropic_api_key
    model = anthropic_model
elif openai_api_key:
    provider = "openai"
    api_key = openai_api_key
    model = openai_model
else:
    provider = None
    api_key = ""
    model = ""

if not module_name:
    print("Error: No module specified")
    sys.exit(1)

# Create temporary venv for code execution
temp_venv = tempfile.mkdtemp(prefix="pyapi_venv_")

def cleanup_venv():
    """Clean up temporary venv"""
    try:
        shutil.rmtree(temp_venv)
    except:
        pass

import atexit
atexit.register(cleanup_venv)

def get_package_name(module_name):
    """Extract the root package name from a module path"""
    # Handle cases like kubernetes.client.models -> kubernetes
    parts = module_name.split('.')
    
    # Common patterns
    if len(parts) > 1:
        # Try the first part first
        return parts[0]
    return module_name

def is_stdlib_module(module_name):
    """Check if a module is part of Python's standard library"""
    # Get the root module name
    root_module = module_name.split('.')[0]
    
    # Comprehensive list of Python stdlib modules
    stdlib_modules = {
        # Built-in modules
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio', 'asyncore',
        'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex', 'bisect',
        'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd',
        'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall',
        'concurrent', 'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg',
        'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses', 'datetime',
        'dbm', 'decimal', 'difflib', 'dis', 'distutils', 'doctest', 'email',
        'encodings', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
        'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass',
        'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac',
        'html', 'http', 'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect',
        'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
        'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math',
        'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis',
        'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'pathlib',
        'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform', 'plistlib',
        'poplib', 'posix', 'posixpath', 'pprint', 'profile', 'pstats', 'pty', 'pwd',
        'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri', 'random', 're',
        'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched', 'secrets',
        'select', 'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
        'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'spwd', 'sqlite3',
        'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct', 'subprocess',
        'sunau', 'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile',
        'telnetlib', 'tempfile', 'termios', 'test', 'textwrap', 'threading', 'time',
        'timeit', 'tkinter', 'token', 'tokenize', 'tomllib', 'trace', 'traceback',
        'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
        'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref',
        'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib', 'zoneinfo',
        # Also include _-prefixed internal modules
        '_thread', '__future__',
    }
    
    return root_module in stdlib_modules

def setup_venv():
    """Create venv with uv and install the target module if needed"""
    try:
        # Create venv with uv
        result = subprocess.run(
            ['uv', 'venv', temp_venv],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            print(f"Failed to create venv: {result.stderr}", file=sys.stderr)
            return False
        
        # Check if this is a stdlib module - no installation needed
        if is_stdlib_module(module_name):
            print(f"📦 `{module_name}` is a standard library module (no installation needed)", file=sys.stderr)
            return True
        
        # Determine package to install
        package_to_install = get_package_name(module_name)
        
        # Install the package
        print(f"📦 Installing `{package_to_install}` from PyPI...", file=sys.stderr)
        pip_path = os.path.join(temp_venv, 'bin', 'pip')
        result = subprocess.run(
            ['uv', 'pip', 'install', '--python', os.path.join(temp_venv, 'bin', 'python'), package_to_install],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            print(f"Failed to install {package_to_install}: {result.stderr}", file=sys.stderr)
            return False
        
        return True
    except Exception as e:
        print(f"Error setting up venv: {e}", file=sys.stderr)
        return False

def extract_code_from_markdown(text):
    """Extract Python code from markdown code blocks"""
    pattern = r'```python\s*\n(.*?)```'
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[0] if matches else text

def execute_code(code):
    """Execute Python code and capture output in the temporary venv"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        # Use the venv's python
        python_path = os.path.join(temp_venv, 'bin', 'python')
        result = subprocess.run(
            [python_path, temp_file],
            capture_output=True,
            text=True,
            timeout=10  # Increased timeout for slower operations
        )
        
        os.unlink(temp_file)
        
        output = ""
        if result.stdout:
            output += result.stdout.strip()
        if result.stderr and result.returncode != 0:
            # Only include stderr if there was an error
            if output:
                output += "\n"
            output += result.stderr.strip()
        
        return output if output else "(no output)", result.returncode
        
    except subprocess.TimeoutExpired:
        try:
            os.unlink(temp_file)
        except:
            pass
        return "(execution timed out after 10 seconds)", 1
    except Exception as e:
        return f"(execution error: {e})", 1

def call_anthropic_api(prompt):
    """Call Anthropic Claude API using curl"""
    payload = {
        "model": anthropic_model,
        "max_tokens": 600,
        "messages": [{"role": "user", "content": prompt}]
    }
    
    try:
        result = subprocess.run(
            [
                'curl', '-s', '-X', 'POST', 'https://api.anthropic.com/v1/messages',
                '-H', f'x-api-key: {anthropic_api_key}',
                '-H', 'anthropic-version: 2023-06-01',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(payload)
            ],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            return None, f"curl failed: {result.stderr}"
        
        try:
            response = json.loads(result.stdout)
            if "error" in response:
                return None, f"API Error: {response['error'].get('message', response['error'])}"
            # Anthropic returns content as an array of content blocks
            content_blocks = response.get("content", [])
            if content_blocks:
                # Extract text from content blocks
                text_parts = [block.get("text", "") for block in content_blocks if block.get("type") == "text"]
                return "".join(text_parts), None
            return None, "No content in response"
        except (json.JSONDecodeError, KeyError) as e:
            return None, f"Invalid response: {e}\n{result.stdout[:200]}"
    except subprocess.TimeoutExpired:
        return None, "API call timed out"
    except Exception as e:
        return None, f"Error calling API: {e}"

def call_openai_api(prompt):
    """Call OpenAI/LiteLLM API using curl"""
    # Construct API URL
    api_url = openai_base_url.rstrip('/')
    if not api_url.endswith('/chat/completions'):
        api_url += '/chat/completions'
    
    payload = {
        "model": openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 600,
        "temperature": 0.7
    }
    
    try:
        result = subprocess.run(
            [
                'curl', '-s', '-X', 'POST', api_url,
                '-H', f'Authorization: Bearer {openai_api_key}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(payload)
            ],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            return None, f"curl failed: {result.stderr}"
        
        try:
            response = json.loads(result.stdout)
            if "error" in response:
                return None, f"API Error: {response['error']}"
            return response["choices"][0]["message"]["content"], None
        except (json.JSONDecodeError, KeyError) as e:
            return None, f"Invalid response: {e}\n{result.stdout[:200]}"
    except subprocess.TimeoutExpired:
        return None, "API call timed out"
    except Exception as e:
        return None, f"Error calling API: {e}"

def call_api(prompt):
    """Call the appropriate API based on configured provider"""
    if not api_key:
        return None, "No API key set (set ANTHROPIC_API_KEY or OPENAI_API_KEY)"
    
    if provider == "anthropic":
        return call_anthropic_api(prompt)
    else:
        return call_openai_api(prompt)

def validate_code_has_print(code):
    """Check if code contains a print statement"""
    # Simple check for print() call
    return 'print(' in code or 'print (' in code

def is_valid_output(output, returncode):
    """Check if the execution produced valid output"""
    if returncode != 0:
        return False
    if not output or output.strip() == "":
        return False
    if output == "(no output)":
        return False
    # Check for common error indicators in output
    error_indicators = ["Traceback", "Error:", "Exception:", "error:", "failed"]
    for indicator in error_indicators:
        if indicator in output:
            return False
    return True

def get_code_example(module_name, func_name, sig, doc):
    """Get AI-generated code example for a function with validation and retries"""
    if not api_key:
        return "*Set ANTHROPIC_API_KEY or OPENAI_API_KEY to see code examples*", ""
    
    max_attempts = 3
    last_code = ""
    last_output = ""
    last_error = ""
    
    prompt = f"""Generate a SHORT executable Python code example for this function:
Function: {func_name}{sig}
Module: {module_name}
Doc: {doc[:200]}

CRITICAL REQUIREMENTS:
1. Code MUST be complete and standalone (include ALL imports)
2. Code MUST call print() to display output - THIS IS MANDATORY
3. Code must be 5-10 lines max
4. Use simple, realistic example data (no external files/URLs/network)
5. No servers, no async/await, no user input, no infinite loops
6. For web frameworks (Flask/Django): use app context or test client
7. For classes: instantiate and call a method, print the result
8. Wrap any potentially failing operations in try/except

GOOD EXAMPLE:
```python
from collections import Counter
data = ['apple', 'banana', 'apple', 'cherry', 'banana', 'apple']
counter = Counter(data)
print(f"Counts: {{dict(counter)}}")
print(f"Most common: {{counter.most_common(2)}}")
```

Provide ONLY the code in a ```python block. The code MUST print something."""
    
    for attempt in range(max_attempts):
        if attempt == 0:
            # First attempt - use initial prompt
            example_text, error = call_api(prompt)
            if error:
                return f"*Could not generate example: {error}*", ""
        else:
            # Retry with error feedback
            fix_prompt = f"""The previous code example FAILED. Here's what went wrong:

Previous code:
```python
{last_code}
```

Problem: {last_error}
Output: {last_output}

Generate a WORKING version that:
1. MUST include print() statements - this is why it failed before
2. MUST be complete with all imports
3. MUST NOT use external resources (files, URLs, network)
4. Should handle edge cases gracefully
5. Use simple hardcoded test data

For module `{module_name}`, function `{func_name}`:
- Show a realistic but simple usage
- Print the result clearly

Provide ONLY the fixed code in a ```python block."""
            
            example_text, error = call_api(fix_prompt)
            if error:
                continue
        
        # Extract code
        code = extract_code_from_markdown(example_text)
        last_code = code
        
        # Validate code has print statement
        if not validate_code_has_print(code):
            last_error = "Code does not contain any print() statements"
            last_output = "(no print statement found)"
            continue
        
        # Execute code
        output, returncode = execute_code(code)
        last_output = output
        
        # Check if execution was successful with valid output
        if is_valid_output(output, returncode):
            return example_text, output
        
        # Set error for next retry
        if returncode != 0:
            last_error = f"Execution failed with return code {returncode}"
        elif not output or output == "(no output)":
            last_error = "Code executed but produced no output (missing print?)"
        else:
            last_error = f"Output contains errors"
    
    # All attempts failed - return last attempt with error note
    status_msg = f"*(Example may have issues after {max_attempts} attempts)*"
    if last_output and last_output != "(no output)":
        return example_text, f"{last_output}\n{status_msg}"
    return example_text, status_msg

# Setup venv first
print("🔧 Setting up temporary environment...", file=sys.stderr)
if not setup_venv():
    sys.exit(1)

try:
    # Use the venv's python to import the module
    python_path = os.path.join(temp_venv, 'bin', 'python')
    
    # Get module info using the venv's python
    inspect_code = """
import sys, importlib, inspect, json, pkgutil
try:
    mod = importlib.import_module('""" + module_name + """')
    items = []
    
    # Get submodules
    if hasattr(mod, '__path__'):
        for importer, modname, ispkg in pkgutil.iter_modules(mod.__path__, mod.__name__ + "."):
            submod_name = modname.split('.')[-1]
            items.append({
                "name": submod_name,
                "sig": "",
                "doc": "Submodule: " + modname,
                "type": "submodule",
                "full_name": modname
            })
    
    # Get callable items
    for name in sorted(dir(mod)):
        if not name.startswith("_"):
            obj = getattr(mod, name)
            if callable(obj):
                doc = (inspect.getdoc(obj) or "").split("\\n")[0]
                sig = ""
                try:
                    sig = str(inspect.signature(obj))
                except:
                    sig = "(...)"
                
                obj_type = "function"
                if inspect.isclass(obj):
                    obj_type = "class"
                elif inspect.ismethod(obj):
                    obj_type = "method"
                    
                items.append({"name": name, "sig": sig, "doc": doc, "type": obj_type})
    
    print(json.dumps(items))
except Exception as e:
    import traceback
    print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}), file=sys.stderr)
    sys.exit(1)
"""
    
    result = subprocess.run(
        [python_path, '-c', inspect_code],
        capture_output=True,
        text=True,
        timeout=10
    )
    
    if result.returncode != 0:
        print(f"❌ Failed to inspect module: {result.stderr}")
        sys.exit(1)
    
    items = json.loads(result.stdout)
    
    # Filter by search term
    if search_term:
        items = [item for item in items if search_term in item['name'].lower()]
    
    if not items:
        print(f"No {'matching ' if search_term else ''}functions found in '{module_name}'")
        sys.exit(0)
    
    # Build markdown output
    print(f"# 📚 `{module_name}` API Reference")
    print()
    
    # Show provider info if API key is set
    if api_key:
        provider_name = "Anthropic Claude" if provider == "anthropic" else "OpenAI/LiteLLM"
        print(f"🤖 **AI Provider:** {provider_name} (`{model}`)")
        print()
    
    if search_term:
        print(f"🔍 **Filter:** `{search_term}`")
        print()
    
    print(f"**Total:** {len(items)} callable(s)")
    print()
    print("---")
    print()
    
    for item in items:
        name = item['name']
        sig = item.get('sig', '')
        doc = item.get('doc', '')
        obj_type = item['type']
        
        if obj_type == "submodule":
            emoji = "📦"
            full_name = item.get('full_name', name)
            
            print(f"## {emoji} `{name}` (submodule)")
            print()
            print(f"**Full path:** `{full_name}`")
            print()
            print(f"*💡 Use `pyapi {full_name}` to explore this submodule*")
            print()
        else:
            emoji = "🔧" if obj_type == "function" else "📦" if obj_type == "class" else "⚙️"
            
            print(f"## {emoji} `{name}`")
            print()
            print("**Signature:**")
            print()
            print("```python")
            print(f"{name}{sig}")
            print("```")
            print()
            
            if doc:
                print(f"**Description:** {doc}")
                print()
            
            # Generate and execute code example (only when filtering)
            if search_term and api_key and obj_type != "submodule":
                print("**Example:**")
                print()
                example, output = get_code_example(module_name, name, sig, doc)
                print(example)
                print()
                
                if output:
                    print("**Output:**")
                    print()
                    print("```")
                    print(output)
                    print("```")
                    print()
            elif not search_term and obj_type != "submodule":
                print(f"*💡 Use `pyapi {module_name} {name.lower()}` to see code examples*")
                print()
        
        print("---")
        print()
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYEOF
    
    if [ $? -ne 0 ]; then
        cat "$tmpfile"
        rm "$tmpfile"
        return 1
    fi
    
    cat "$tmpfile" | glow -w 120 -
    rm "$tmpfile"
}

# ============================================================================
# CUSTOM PROMPT CONFIGURATION
# ============================================================================

# Elaborate custom prompt showing context information:
# Format: user:path:[aws::account]-[k8s::cluster]-[tfver::version]-[tfwrk::workspace]-(git::branch):
#         └─ $ ▶
# 
# Components:
#   - User and current working directory
#   - AWS account name (Development/DevOps/none)
#   - Current Kubernetes context
#   - Terraform version
#   - Terraform workspace
#   - Git branch
#   - Green $ for normal user, # for root
export PS1="\u:\w\[\e[40m\]:[\[\e[m\]\[\e[44m\]aws::${account_id}\[\e[m\]]-[\[\e[m\]\[\e[44m\]k8s::$(currentk8s)\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfver::$(currentTFversion)\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfwrk::$(currentTFworkspace)\[\e[m\]]-((\e[44m\]git::$(parse_git_branch)\[\e[m\])):\n └─\[\033[0m\033[0;32m\] `[ $(id -u) == "0" ] && echo "#" || echo '$'` \[\033[0m\033[0;32m\] ▶\[\033[0m\] "

# Reload bashrc before each prompt to pick up changes
# WARNING: This can cause performance issues and infinite loops if bashrc has errors
PROMPT_COMMAND="source ~/.bashrc"

# ============================================================================
# ARTIFACTORY CONFIGURATION
# ============================================================================

# Artifactory credentials and URL configuration
# Used for accessing private artifact repositories
export ARTIFACTORY_USERNAME=${USER}
export ARTIFACTORY_URL=https://
export ARTIFACTORY_API=xxxxxxxxxxxxxxxxxxxxxxx
export ARTIFACTORY_API_KEY=$ARTIFACTORY_API

# ============================================================================
# VI MODE
# ============================================================================

# Enable vi-style command line editing
# Use ESC to enter command mode, then vi keybindings (hjkl, w, b, etc.)
set -o vi
