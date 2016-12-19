#!/bin/bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

. "$(dirname "$0")/config.sh"

(cd ./tls && ./tls $HOSTS)

echo "Copying weave images, scripts, and certificates to hosts, and"
echo "  prefetch test images"

exists_on() {
    docker_on $1 inspect --format=" " $2 >/dev/null 2>&1
}

pull_if_missing() {
    if ! exists_on "$1" "$2" ; then
        echo "Pulling $2 on $1..."
        docker_on $1 pull $2 >/dev/null 2>&1
    fi
}

setup_host() {
    HOST=$1
    docker_on $HOST load -i ../weave.tar.gz &
    local pids="$!"
    
    DANGLING_IMAGES="$(docker_on $HOST images -q -f dangling=true)"
    [ -n "$DANGLING_IMAGES" ] && docker_on $HOST rmi $DANGLING_IMAGES 1>/dev/null 2>&1 || true
    run_on $HOST mkdir -p bin
    
    upload_executable $HOST ../bin/docker-ns &
    local pids="$pids $!"
    
    upload_executable $HOST ../weave &
    local pids="$pids $!"

    rsync -az -e "$SSH" --exclude=tls ./tls/ $HOST:~/tls &
    local pids="$pids $!"

    for IMG in $TEST_IMAGES ; do
        pull_if_missing "$HOST" "$IMG"
        local pids="$pids $!"
    done
    for pid in $pids; do wait $pid; done
}

for HOST in $HOSTS; do
    setup_host $HOST &
    ppids="$ppids $!"
done

# Wait individually for tasks so we fail-exit on any non-zero return code
# ('wait' on its own always returns 0)
for pid in $ppids; do
    wait $pid;
done

echo "Setup completed successfully."
