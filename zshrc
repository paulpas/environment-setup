# Check if the homebrew path is not already in the $PATH
if [[ ":$PATH:" != *":/opt/homebrew/bin:"* ]]; then
    PATH="/opt/homebrew/bin:$PATH"
fi 
if [[ ":$PATH:" != *":/opt/homebrew/opt/gnu-tar/libexec/gnubin:"* ]]; then
    PATH="/opt/homebrew/opt/gnu-tar/libexec/gnubin:$PATH"
fi 
export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
#eval "$(pyenv init -)"
#eval "$(pyenv virtualenv-init -)"
######################## Set Paths ################################
start_time=$(gdate +%s%3N)
new_paths=()
# Array of paths to check and add if not already present
paths_to_add=(
  "/opt/homebrew/opt/curl/bin"
  "/Applications/Docker.app/Contents/Resources/bin"
  "/opt/homebrew/bin"
  "/Users/${USER}/.cargo/bin"
  "/Users/${USER}/git/ata/target/release"
  "$HOME/.jenv/bin"
)

# Loop through each path and add to the new_paths array if not in $PATH
for path in "${paths_to_add[@]}"; do
  if [[ ":$PATH:" != *":$path:"* ]]; then
    new_paths+=("$path")
  fi
done

# Prepend/appends any new paths found to the current PATH
if [ ${#new_paths[@]} -ne 0 ]; then
  PATH="${new_paths[*]}:$PATH"
fi

export PATH=$PATH:/Applications/chromedriver/mac_arm-119.0.6045.105/chromedriver-mac-arm64/
export PATH
end_time=$(gdate +%s%3N)
echo "Path Execution time: $((end_time - start_time)) ms"
###################################################################
# Save the last modification time of .bash_profile
LAST_BASH_PROFILE_MD5=""


update_zsh_profile() {
    local current_md5
    # Calculate checksum
    if [[ -f "${HOME}/.zshrc" ]]; then
        current_md5=$(md5sum ${HOME}/.zshrc ${HOME}/.bashrc | md5sum | cut -d ' ' -f 1)
    else
        current_md5=""
    fi

    # Only source if the checksum changes
    if [[ "$current_md5" != "$LAST_ZSH_PROFILE_MD5" ]]; then
        source "${HOME}/.zshrc"
        source "${HOME}/.bashrc"
        LAST_ZSH_PROFILE_MD5="$current_md5"
    fi
}

update_bash_profile() {
    start_time=$(gdate +%s%3N)
    local current_md5
    # Calculate checksum
    if [[ -f "${HOME}/.bashrc" ]]; then
        current_md5=$(md5sum "${HOME}/.bashrc" | cut -d ' ' -f 1)
    else
        current_md5=""
    fi
    # Only source if the checksum changes
    if [[ "$current_md5" != "$LAST_BASH_PROFILE_MD5" ]]; then
        source "${HOME}/.bashrc"
        LAST_BASH_PROFILE_MD5="$current_md5"
    fi
    end_time=$(gdate +%s%3N)
    echo "Updating .bashrc Execution time: $((end_time - start_time)) ms"
}

export KUBECONFIG=${KUBECONFIG:-null}
export DOCKER_DEFAULT_PLATFORM=linux/amd64
# Caching results to avoid multiple executions within the same session
account_id=${AWS_PROFILE:-none}
current_k8s="no-k8s-cluster"
tf_version=""
tf_workspace=""
git_branch=""

function get_account_id() {
    if [[ $AWS_PROFILE == 123456789-/Infrastructure ]]; then
        account_id=Development
    elif [[ $AWS_PROFILE == 9876543231-/Infrastructure ]]; then
        account_id=DevOps
    else
        account_id=${AWS_PROFILE:-none}
    fi
}

function currentk8s() {
  if [[ ${KUBECONFIG} != "null" ]]; then
    current_k8s=$(kubectl config current-context 2>/dev/null | awk -F$'[ /]' '/arn:aws/ {print $NF}' | grep .)
  else
    current_k8s="no-k8s-cluster"
  fi
}

function update_tf_version() {
  if [[ -f .terraform/environment ]]; then
    tf_version=$(terraform -version | awk '/^Terraform/ {print $2}')
  else
    tf_version="none"
  fi
}

function update_tf_workspace() {
  if [[ -f .terraform/environment ]]; then
    tf_workspace=$(<.terraform/environment)
  else
    tf_workspace="none"
  fi
}

function parse_git_branch() {
  git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "none")
}

# Add to your ~/.bashrc file

# Begin persistent history across all terminals
log_bash_persistent_history()
{
  [[
    $(history 1) =~ ^\ *[0-9]+\ +([^\ ]+\ [^\ ]+)\ +(.*)$
  ]]
  local date_part="${BASH_REMATCH[1]}"
  local dir_part=$(pwd)
  local command_part="${BASH_REMATCH[2]}"
  if [ "$command_part" != "$PERSISTENT_HISTORY_LAST" ]
  then
    echo $date_part "|" "$dir_part" ">" "$command_part" >> ~/.persistent_history
    export PERSISTENT_HISTORY_LAST="$command_part"
  fi
}

# Stuff to do on PROMPT_COMMAND
run_on_prompt_command()
{
    log_bash_persistent_history
}


export HISTTIMEFORMAT="%F %T  "

alias phall='less ~/.persistent_history' # scroll through everything
alias phf='cat ~/.persistent_history|grep --color' # find a search term in entire history
#alias phtrim='tail -20000 ~/.persistent_history | tee ~/.persistent_history' # trim history, commented out because I never use it
alias phlast='tail -15 ~/.persistent_history' # print last N history
alias phfr='tail -50 ~/.persistent_history | grep --color' # find a search term from last N entries

# Update all cached values once per command execution
PROMPT_COMMAND="get_account_id; currentk8s >/dev/null ; update_tf_version >/dev/null; update_tf_workspace >/dev/null; parse_git_branch >/dev/null; update_zsh_profile ; source ~/.bashrc; run_on_prompt_command"
export PS1='[\[\e[37;45m\]$?\[\e[m\]] \u:\w[\[\e[40m\]]:[\[\e[m\]\[\e[44m\]aws::${account_id}\[\e[m\]]-[\[\e[m\]\[\e[44m\]k8s::${current_k8s}\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfver::${tf_version}\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfwrk::${tf_workspace}\[\e[m\]]-([\[\e[44m\]git::[${git_branch}]\[\e[m\])]:\n └─\[\033[0m\]\[\033[0;32m\]`[ ${EUID} == 0 ] && echo "#" || echo "$"` \[\033[0m\]▶ '

start_time=$(gdate +%s%3N)
#export PS1='[\e[37;45m\]$?\[\e[m\]] \u:\w[\e[40m]:[\[\e[m\]\[\e[44m\]aws::${account_id}\[\e[m\]]-[\[\e[m\]\[\e[44m\]k8s::${current_k8s}\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfver::${tf_version}\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfwrk::${tf_workspace}\[\e[m\]]-([\e[44m\]git::[${git_branch}]\[\e[m\])]:\n └─\033[0m\033[0;32m`[ ${EUID} == 0 ] && echo "#" || echo "$"` \033[0m▶ '
end_time=$(gdate +%s%3N)
echo "PS1 Execution time: $((end_time - start_time)) ms"

###################################################################
start_time=$(gdate +%s%3N)
export ARTIFACTORY_USERNAME=${USER}@foo.com
export ARTIFACTORY_URL=https://foo.jfrog.io/artifactory/
export ARTIFACTORY_API=xxxxxx
export ARTIFACTORY_API_KEY=$ARTIFACTORY_API

set -o vi

export HOMEBREW_BUNDLE_FILE=$HOME/.Brewfile
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1
[[ -z $GITHOME ]] && export GITHOME=~/git
[[ -z $OPENAI_API_KEY ]] && export OPENAI_API_KEY=sk-xxxxxx
[[ -z $BAR_USERNAME ]] && export BAR_USERNAME=foo@bar.com
[[ -z $ATLASSIAN_USERNAME ]] && export ATLASSIAN_USERNAME=foo@abar.com
[[ -z $ATLASSIAN_API_TOKEN ]] && export ATLASSIAN_API_TOKEN='xxxxxxxxx'
[[ -z $CONF_CREDS ]] && export CONF_CREDS=${ATLASSIAN_USERNAME}:${ATLASSIAN_API_TOKEN}
[[ -z $HOMEBREW_ROOT ]] && HOMEBREW_ROOT=/opt/homebrew
#source ${HOMEBREW_ROOT}/Cellar/git/$(ls -tr ${HOMEBREW_ROOT}/Cellar/git/ | tail -1)/share/zsh/site-functions/git-completion.bash
#source /opt/homebrew/etc/bash_completion.d/git-prompt.sh
#source "/Users/${USER}/.sdkman/bin/sdkman-init.sh"
end_time=$(gdate +%s%3N)
echo "Setting Shell and Sources  Execution time: $((end_time - start_time)) ms"

alias githist='git log --stat -p'
alias git-tree='git log --oneline --decorate --all --graph'
alias dev='gimme-aws-creds --profile=dev; export AWS_PROFILE=123456789-/Infrastructure'
alias devops='gimme-aws-creds --profile=devops; export AWS_PROFILE=987654321-/Infrastructure'

#alias currentk8s="if [[ ${KUBECONFIG} != "null" ]]; then kubectl config current-context 2>/dev/null | awk -F$'[ /]' '{print \$NF}' | grep . ; else echo no-k8s-cluster; fi"
alias currentTFworkspace="( [[ -f .terraform/environment ]] && cat .terraform/environment ) || echo "none""
alias currentTFversion="( [[ -f .terraform/environment ]] && terraform -version | awk '/^Terraform/ {print \$2}') || echo "none""
alias secret='aws secretsmanager list-secrets | jq -r ".SecretList[].Name" | grep $(currentk8s) | while read i; do echo $i; aws secretsmanager get-secret-value --secret-id $i | jq -r ".SecretString" | jq -r . ; done'
alias secret_jenkins='aws secretsmanager list-secrets | jq -r ".SecretList[].Name" | grep jenkins | while read i; do echo $i; aws secretsmanager get-secret-value --secret-id $i | jq -r ".SecretString" | jq -r . ; done'
alias scat="sdiff \$1 \$2 | sed -r 's/[<>|]//;s/(\t){3}//'"
alias disable_screen='sudo nvram boot-args="iog=0x0"'
alias enable_screen='sudo nvram -d boot-args'
alias flushdns='sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder'
alias pr-list='pr_output'
alias git-pr-list='pr_output'
alias debugk8s='kubectl run debug-shell --rm -i --tty --image ubuntu -- bash'


function kube_fetch_all_secrets() {
    currentk8s | grep -vq 'no-k8s-clusters' || kubeseal --format yaml -f local_secret.yaml > kubernetes-secrets.yaml
}
function pr_output() {
    repo=$(basename `git rev-parse --show-toplevel`)
    IFS=$'\n'
    for output in $(gh pr list --state closed --json number,title,closedAt | jq -r '.[] | "PR #\(.number),\(.closedAt),\(.title)"'); do
        echo ${repo},${output}
    done
    unset IFS
}
pr-get-all-from-last-tag() {
    tag=$1
    if [[ -z $tag ]]; then
        echo "Enter a tag number. ex. 1.0.0"
    fi
    repo=$(basename `git rev-parse --show-toplevel`)
    IFS=$'\n'
    git log --merges --oneline ${tag}..HEAD | grep -o '#[0-9]*' | sed 's/#//g' | while read pr; do
        (echo "${repo},$(gh pr view ${pr} --json number,title,closedAt | jq -r '"PR #\(.number),\(.closedAt),\(.title)"')") &
    done | sort -n 
    unset IFS
    wait 2>/dev/null
    echo
}
#function parse_git_branch() {
#     git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/'
#}
cloudstrike() {
    sudo renice 20 $(ps -ef | grep [c]om.crowdstrike.falcon.Agent | awk '{print $2}')
}

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

function get_linkerd_cert_expiration() {
    EXPIRATION=$(kubectl -n linkerd get secret linkerd-identity-issuer -o jsonpath="{.data['crt\.pem']}" | base64 -d | openssl x509 -text | awk -F' :' '/Not After :/{print $2}')
    calculate_date "Linkerd"
}

function get_all_linkerd_cert_expiration() {
    (setSbx && echo -n "$NAMESPACE " && get_linkerd_cert_expiration && echo) 2>/dev/null
    (setSit && echo -n "$NAMESPACE "&& get_linkerd_cert_expiration && echo) 2>/dev/null
    (setVerify && echo -n "$NAMESPACE "&& get_linkerd_cert_expiration && echo) 2>/dev/null
    (setUser && echo -n "$NAMESPACE "&& get_linkerd_cert_expiration && echo) 2>/dev/null
    (setProd && echo -n "$NAMESPACE "&& get_linkerd_cert_expiration && echo) 2>/dev/null
}

function aws_ebs_encryption_check () {
    for region in $(aws ec2 describe-regions --region us-east-1 --query "Regions[*].[RegionName]" --output text); do
        default=$(aws ec2 get-ebs-encryption-by-default --region $region --query "{Encryption_By_Default:EbsEncryptionByDefault}" --output text)
        kms_key=$(aws ec2 get-ebs-default-kms-key-id --region $region | jq '.KmsKeyId')
        echo "$region  --- $default  --- $kms_key"
    done
}

function aws_enable_ebs_encryption () {
    for region in $(aws ec2 describe-regions --region us-east-1 --query "Regions[*].[RegionName]" --output text); do
        default=$(aws ec2 enable-ebs-encryption-by-default --region $region --query "{Encryption_By_Default:EbsEncryptionByDefault}" --output text)
        kms_key=$(aws ec2 get-ebs-default-kms-key-id --region $region | jq '.KmsKeyId')
        echo "$region  --- $default  --- $kms_key"
    done
}

function kz_deployment() {
    if [[ $# != 3 ]]; then
        echo "Usage: kz_deployment <environment> <type> <deployment name>"
        return 1
    fi
    environment=$1
    type=$2
    name=$3
    kustomize build environments/${environment} | kustomize cfg grep "kind=${type}" | kustomize cfg grep "metadata.name=${name}"
}

function git_most_recent_pr() {
    num=${1:-1}
    git for-each-ref refs/tags --merged origin/main --sort=-taggerdate --format="%(taggerdate) ----->>>>>> %(refname:short)" --count=$num
}

#pr () {
#    diff=`gh pr diff $1`
#    ollama run starling "Provide a brief summary and highlight any violations of security and coding best practices in the following git changes diff: $diff"
#}
commit () {
    diff=`gh pr diff $1`
    ollama run codellama "Provide a brief summary and highlight any violations of security and coding best practices in the following git changes diff: $diff"
}

function ktcpdump() {
  # Kill any existing 'kubectl port-forward' processes before starting a new one
  kill $(pgrep -f 'kubectl.*port-forward.*hubble-relay') 2>/dev/null

  # default verdict to 'all'
  local verdict=${1:-all}
  local verdict_option
  case "${verdict,,}" in
    dropped | DROPPED | forwarded | FORWARDED | undecided | UNDECIDEED | error | ERROR)
      echo "Capturing ${verdict^^} packets"
      verdict_option="--verdict ${verdict^^}"
      ;;
    all)
      echo "Capturing all packets"
      verdict_option=""
      ;;
    *)
      echo "Invalid argument, available options are: 'forwarded', 'dropped', 'undecided', 'error', 'all'"
      return
      ;;
  esac
  kubectl port-forward -n cilium svc/hubble-relay 4245:80 &>/dev/null &
  local pid=$!
  # Wait for port-forward to be ready. Try 5 times to connect to port 4245 using nc.
  for i in {1..5}; do
      if nc -zv localhost 4245 &>/dev/null; then
          echo "Access to hubble-relay established. Proceeding..."
          break
      else
          echo "Waiting for access to hubble-relay to be ready..."
          sleep 1
      fi
  done 
  # Trap SIGINT and kill the port-forward process upon receiving the signal
  trap "echo 'Stopping port-forward'; kill -9 $pid" SIGINT 

  hubble observe -f --server localhost:4245 $verdict_option

  # Cleanup after hubble observe command is done
  kill -9 $pid
  trap - SIGINT
}


#THIS MUST BE AT THE END OF THE FILE FOR SDKMAN TO WORK!!!
#export SDKMAN_DIR="$HOME/.sdkman"
#[[ -s "$HOME/.sdkman/bin/sdkman-init.sh" ]] && source "$HOME/.sdkman/bin/sdkman-init.sh"
#
#if [[ -n "$IN_NIX_SHELL" ]]; then
#    export PS1="(devenv) $PS1"
#fi

export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
#eval "$(goenv init -)"
export PATH="$PATH:$GOPATH/bin"


#start_time=$(gdate +%s%3N)
#export PS1="[\e[37;45m\]\$?\[\e[m\]] \u:\w\[\e[40m\]:[\[\e[m\]\[\e[44m\]aws::${account_id}\[\e[m\]]-[\[\e[m\]\[\e[44m\]k8s::$(currentk8s)\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfver::$(currentTFversion)\[\e[m\]]-[\[\e[m\]\[\e[44m\]tfwrk::$(currentTFworkspace)\[\e[m\]]-((\e[44m\]git::[$(parse_git_branch)]\[\e[m\])):\n └─\[\033[0m\033[0;32m\] `[ ${EUID} == "0" ] && echo "#" || echo '$'` \[\033[0m\033[0;32m\] ▶\[\033[0m\] "
#PROMPT_COMMAND="source $HOME/.zshrc"
#end_time=$(gdate +%s%3N)
echo "zshrc Execution time: $((end_time - start_time)) ms"
