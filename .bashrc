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
        return 1
    fi
    
    if ! command -v glow &> /dev/null; then
        echo "❌ Error: 'glow' is required but not installed."
        return 1
    fi
    
    local tmpfile=$(mktemp)
    
    MODULE_NAME="$1" SEARCH_TERM="${2:-}" ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" python3 << 'PYEOF' > "$tmpfile" 2>&1
import sys, importlib, inspect, os, json, subprocess, re
from urllib.request import Request, urlopen

# Read environment variables
module_name = os.environ.get("MODULE_NAME", "")
search_term = os.environ.get("SEARCH_TERM", "").lower()
api_key = os.environ.get("ANTHROPIC_API_KEY", "")

if not module_name:
    print("Error: No module specified")
    sys.exit(1)

def extract_code_from_markdown(text):
    """Extract Python code from markdown code blocks
    
    Args:
        text: Markdown text containing ```python code blocks
        
    Returns:
        Extracted Python code or original text if no code block found
    """
    pattern = r'```python\s*\n(.*?)```'
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[0] if matches else text

def execute_code(code):
    """Execute Python code in a temporary file and capture output
    
    Args:
        code: Python code string to execute
        
    Returns:
        tuple: (output_string, return_code)
        - output_string: Combined stdout/stderr or error message
        - return_code: 0 for success, 1 for failure
    """
    try:
        import tempfile
        # Write code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        # Execute with 5 second timeout
        result = subprocess.run(
            ['python3', temp_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        os.unlink(temp_file)
        
        # Combine stdout and stderr
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += "\nErrors:\n" + result.stderr
        
        return output.strip() if output.strip() else "(no output)", result.returncode
        
    except subprocess.TimeoutExpired:
        return "(execution timed out after 5 seconds)", 1
    except Exception as e:
        return f"(execution error: {e})", 1

def get_code_example(module_name, func_name, sig, doc):
    """Generate AI-powered executable code example for a function
    
    Uses Claude API to generate, execute, and optionally fix code examples.
    
    Args:
        module_name: Name of the Python module
        func_name: Name of the function
        sig: Function signature string
        doc: Function docstring
        
    Returns:
        tuple: (example_markdown, execution_output)
        - example_markdown: AI-generated code in markdown format
        - execution_output: Result of executing the code
    """
    if not api_key:
        return "*Set ANTHROPIC_API_KEY to see code examples*", ""
    
    prompt = f"""Generate a SHORT executable Python code example for this function:
Function: {func_name}{sig}
Module: {module_name}
Doc: {doc[:200]}
CRITICAL REQUIREMENTS:
- MUST be complete, standalone, executable code (5-8 lines max)
- MUST print something to show the output
- Include necessary imports
- For Flask/web frameworks: use app.app_context() or create minimal working context
- For functions that return objects: print the result or relevant attributes
- Use realistic but simple example data
- Add brief inline comments
- No servers, no async, no user input - just code that runs and prints
Example format:
```python
from flask import Flask, jsonify
app = Flask(__name__)
with app.app_context():
    response = jsonify(name="John", age=30)
    print(response.get_json())  # Output the JSON data
```
Provide ONLY the code in a ```python block."""
    
    try:
        # Initial code generation request
        data = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 600,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
        )
        response = urlopen(req)
        result = json.loads(response.read())
        example_text = result["content"][0]["text"]
        
        # Extract and execute code
        code = extract_code_from_markdown(example_text)
        output, returncode = execute_code(code)
        
        # If execution failed, ask AI to fix it
        if returncode != 0:
            fix_prompt = f"""The following code example FAILED with this error:
```python
{code}
```
Error output:
{output}
Generate a FIXED version that will execute successfully. Follow the same requirements:
- MUST be complete, standalone, executable code (5-8 lines max)
- MUST print something to show the output
- Include necessary imports
- For Flask/web frameworks: use app.app_context() or create minimal working context
- Use realistic but simple example data
- No servers, no async, no user input
Provide ONLY the fixed code in a ```python block."""
            
            fix_data = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 600,
                "messages": [{"role": "user", "content": fix_prompt}]
            }).encode()
            
            fix_req = Request(
                "https://api.anthropic.com/v1/messages",
                data=fix_data,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
            )
            fix_response = urlopen(fix_req)
            fix_result = json.loads(fix_response.read())
            example_text = fix_result["content"][0]["text"]
            
            # Try executing the fixed code
            fixed_code = extract_code_from_markdown(example_text)
            output, returncode = execute_code(fixed_code)
        
        return example_text, output
    except Exception as e:
        return f"*Could not generate example: {e}*", ""

# Main module introspection logic
try:
    mod = importlib.import_module(module_name)
    
    # Collect all public callable items (functions, classes, methods)
    items = []
    for name in sorted(dir(mod)):
        if not name.startswith("_"):
            # Filter by search term if provided
            if search_term and search_term not in name.lower():
                continue
            obj = getattr(mod, name)
            if callable(obj):
                # Extract first line of docstring
                doc = (inspect.getdoc(obj) or "").split("\n")[0]
                sig = ""
                try:
                    sig = str(inspect.signature(obj))
                except:
                    sig = "(...)"
                
                # Determine object type
                obj_type = "function"
                if inspect.isclass(obj):
                    obj_type = "class"
                elif inspect.ismethod(obj):
                    obj_type = "method"
                    
                items.append((name, sig, doc, obj_type))
    
    if not items:
        print(f"No {'matching ' if search_term else ''}functions found in '{module_name}'")
        sys.exit(0)
    
    # Build markdown output
    print(f"# 📚 `{module_name}` API Reference")
    print()
    
    if search_term:
        print(f"🔍 **Filter:** `{search_term}`")
        print()
    
    print(f"**Total:** {len(items)} callable(s)")
    print()
    print("---")
    print()
    
    # Generate documentation for each item
    for name, sig, doc, obj_type in items:
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
        
        # Generate and execute code example (only when filtering to specific function)
        if search_term and api_key:
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
        elif not search_term:
            print(f"*💡 Use `pyapi {module_name} {name.lower()}` to see code examples*")
            print()
        
        print("---")
        print()
        
except ModuleNotFoundError:
    print(f"❌ Module '{module_name}' not found. Try: pip install {module_name}")
    sys.exit(1)
PYEOF
    
    # Check if Python script succeeded
    if [ $? -ne 0 ]; then
        cat "$tmpfile"
        rm "$tmpfile"
        return 1
    fi
    
    # Render markdown with glow
    cat "$tmpfile" | glow -w 80 -
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
