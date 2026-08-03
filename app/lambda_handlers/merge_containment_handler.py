def lambda_handler(event, context=None):
    """
    AWS Lambda entry point for the "MergeContainmentResults" state.

    A Step Functions Parallel state always returns a JSON array, one entry
    per branch. This state merges the HostIsolation and IdentityResponse
    branch outputs back into a single event dict so the rest of the state
    machine (Forensics -> ChainOfCustody -> EvidenceUpload -> Ticketing ->
    Notification -> ResponseTimeReport) can keep working with one object.

    Input:  [ host_isolation_branch_output, identity_response_branch_output ]
    Output: single merged event dict
    """

    merged = {}
    merged_timings = {}

    for branch_output in event:
        merged_timings.update(branch_output.get("timings", {}))
        merged.update({
            key: value
            for key, value in branch_output.items()
            if key != "timings"
        })

    merged["timings"] = merged_timings

    return merged