package nt219.authz

default allow := false

allow if {
    input.action == "approve"
    input.user.role == "OFFICER"
}

allow if {
    input.action == "reject"
    input.user.role == "OFFICER"
}

allow if {
    input.action == "officer_local_sign"
    input.user.role == "OFFICER"
    input.file.status == "APPROVED"
}

allow if {
    input.action == "officer_remote_sign"
    input.user.role == "OFFICER"
    input.file.status == "APPROVED"
}

allow if {
    input.action == "citizen_remote_sign"
    input.user.role == "Citizen"
    input.file.ownerId == input.user.id
    input.file.status == "APPROVED"
}