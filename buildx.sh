#!/usr/bin/env bash
#
#
# pkcs11shim : a PKCS#11 shim library
#
# This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
#
# Copyright (C) 2020  Mastercard
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
##############################################################################
# This script builds the libpkcs11-shim tarball for the given distro and arch.
# The script uses Docker Buildx to build the tarball in a container.
# The tarball is output to the current directory.
#
set -e

PACKAGE="libpkcs11shim"
GITHUB_REPO="https://github.com/Mastercard/libpkcs11shim"
SUPPORTED_ARCHS="amd64 arm64"
SUPPORTED_DISTROS="ol7 ol8 ol9 deb12 ubuntu2204 ubuntu2404 amzn2023 alpine321"

# Declare an associative array, needed by docker buildx --platform option
declare -A rev_arch_map
rev_arch_map["x86_64"]="amd64"
rev_arch_map["aarch64"]="arm64"

#
# Usage: buildx.sh [--repo URL | -r URL] [--verbose | -v] [--max-procs N | -j N] [distro[/arch]|all[/all]] [...]
#
function usage() {
    echo "Usage: $0 [--repo URL | -r URL] [--verbose | -v] [--max-procs N | -j N] [distro[/arch]|all[/all]] [...]"
    echo "Supported distros: $SUPPORTED_DISTROS"
    echo "Supported archs: $SUPPORTED_ARCHS"
    echo ""
    echo "Options:"
    echo "  --repo URL, -r URL       Specify the repository URL"
    echo "  --verbose, -v            Increase verbosity (can be specified multiple times)"
    echo "  --max-procs N, -j N      Specify the maximum number of processes"
    exit 1
}

#
# Get the current directory
#
function get_current_dir() {
    current_dir="$(pwd)"
    echo "${current_dir}"
}

#
# Get the directory of the script
#
function get_script_dir() {
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    echo "${script_dir}"
}

#
# Generate a random container name
#
function gen_random_container_name() {
    random_docker_name=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 12)
    echo -n "container-$PACKAGE-$random_docker_name"
}

#
# Get the current git tag or commit hash if current commit is not tagged
#
function get_git_tag_or_hash() {
    # Get the current tag if it exists, otherwise get the short commit hash
    git describe --tags --abbrev=0 2>/dev/null || git rev-parse --short HEAD
}

#
# Build the tarball for the given distro and arch
#
# $1 - distro
# $2 - arch
# $3 - verbose: 0 or 1
# $4 - repo_url (default: $GITHUB_REPO)
function create_build() {
    local distro="$1"
    local arch="$2"
    local verbose="$3"
    local repo_url="$4"

    local verbosearg="--quiet"

    if [ "$verbose" -eq 1 ]; then
        verbosearg="--progress=auto"
    elif [ "$verbose" -eq 2 ]; then
        verbosearg="--progress=plain"
    fi

    # TODO: keep this outside of this function, should be a global variable
    declare -A arch_map
    arch_map["amd64"]="x86_64"
    arch_map["arm64"]="aarch64"

    local platformarch="${arch_map[$arch]:-$arch}"

  


    echo "Building artifacts for $distro on arch $arch (platform: $platformarch)..."
    
    local containername=$(gen_random_container_name)
    
    docker buildx build $verbosearg --platform linux/$platformarch --build-arg REPO_URL=$repo_url -t libpkcs11shim-build-$distro-$arch -f $(get_script_dir)/buildx/Dockerfile.$distro $(get_script_dir)/buildx
    
    local artifacts=$(docker run --platform linux/$platformarch --name $containername libpkcs11shim-build-$distro-$arch)

    for artifact in $artifacts; do
        docker cp --quiet $containername:$artifact $(get_current_dir)/
    done
    docker rm -f $containername > /dev/null 2>&1
    echo "Done with for $distro on $arch, produced artifacts:"
    for artifact in $artifacts; do
        echo "  $(get_current_dir)/$(basename $artifact)"
    done
}

# main function.

#
# Parse the arguments and execute the builds
#
function parse_and_build() {
    local repo_url="$GITHUB_REPO"
    local verbose=0
    local args=()
    local numprocs=$(nproc)

    # Parse optional -repo and -verbose arguments
    while [[ "$1" == --* || "$1" == -* ]]; do
        case "$1" in
            --repo|-r)
                shift
                repo_url="$1"
                ;;
            --verbose|-v)
                if [ "$verbose" -lt 2 ]; then
                    verbose=$(($verbose + 1))
                fi
                ;;
            -vv)
                verbose=2
                ;;
            --max-procs|-j)
                shift
                numprocs="$1"
                # Validate the number of processes:
                # - Must be a positive integer
                # - Must be less than or equal to the number of CPUs
                if ! [[ "$numprocs" =~ ^[0-9]+$ ]] || [ "$numprocs" -le 0 ] || [ "$numprocs" -gt "$(nproc)" ]; then
                    echo "Invalid number of processes: $numprocs"
                    usage
                fi
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
        shift
    done
    
    # Collect remaining arguments
    local args=("$@")

    local build_args=()

    for arg in "${args[@]}"; do
        if [[ "$arg" == "all/all" ]]; then
            for distro in $SUPPORTED_DISTROS; do
                for arch in $SUPPORTED_ARCHS; do
                    build_args+=("$distro $arch $verbose $repo_url")
                done
            done
        elif [[ "$arg" == "all" ]]; then
            local host_arch=$(uname -m)
            for distro in $SUPPORTED_DISTROS; do
                build_args+=("$distro $host_arch $verbose $repo_url")
            done
        elif [[ "$arg" == */* ]]; then
            IFS='/' read -r distro arch_list <<< "$arg"
            if [[ "$arch_list" == "all" ]]; then
                for arch in $SUPPORTED_ARCHS; do
                    build_args+=("$distro $arch $verbose $repo_url")
                done
            else
                IFS=',' read -ra archs <<< "$arch_list"
                for arch in "${archs[@]}"; do
                    build_args+=("$distro $arch $verbose $repo_url")
                done
            fi
        else
            IFS=',' read -ra distros <<< "$arg"
            local host_arch=${rev_arch_map[$(uname -m)]:-$(uname -m)}
            for distro in "${distros[@]}"; do
                build_args+=("$distro $host_arch $verbose $repo_url")
            done
        fi
    done

    export -f create_build
    export -f get_current_dir
    export -f get_script_dir
    export -f gen_random_container_name

    # Run builds in parallel, limiting to the number of jobs specified by the user
    #printf "%s\n" "${build_args[@]}" | xargs -P $numprocs -I {} bash -c 'echo "BUILD {}" && sleep 2'
    printf "%s\n" "${build_args[@]}" | xargs -P $numprocs -I {} bash -c 'create_build {}'
}

#
# Main logic
#
if [[ "$#" -lt 1 ]]; then
    usage
fi

parse_and_build "$@"

# EOF
