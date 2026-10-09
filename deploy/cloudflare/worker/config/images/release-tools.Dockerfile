# The harness passes BASE as an exact locally built image (tag bound to its image id);
# this file adds nothing, so the container runs that image unchanged.
ARG BASE
FROM ${BASE}
