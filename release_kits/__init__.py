"""Operator kits for the staging account, each beside its runbook under deploy/aws-staging/.

A kit renders every value it uses from an account plan that
``dev.assemble_account_plan assemble`` wrote, or from an earlier step's receipt.
It never resolves ambient credentials: every step that touches an account takes
an explicit session file, and every step takes the plan directory. Each step
prints its exact commands and the plan hash, waits for the operator to type the
step's identifier, runs, and writes a hashed receipt chained to the one before.
"""
