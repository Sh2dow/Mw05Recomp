REM From the root of your repo
git submodule sync --recursive
git submodule foreach --recursive "git remote -v"

REM Make sure you have the full history (not a shallow clone) for all submodules
git submodule foreach --recursive "git fetch --all --tags --prune --force"

git submodule update --init --recursive
