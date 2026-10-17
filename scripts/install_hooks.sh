#!/bin/bash
# one-time per clone: point git at the versioned hooks
cd "$(git rev-parse --show-toplevel)" && git config core.hooksPath scripts/hooks && echo "hooks installed (core.hooksPath=scripts/hooks)"
